// Command edge-sync is the pull sidecar that runs next to each edge Angie node.
// Every WAF_EDGE_SYNC_INTERVAL seconds it reads the generation manifest from the
// shared store (S3/MinIO), materialises changed objects to the local Angie tree,
// validates with `angie -t`, reloads its own Angie, and records the applied
// generation. The manifest is the single commit point, so a node never serves a
// half-written change set (FR-004); on any failure it stays on last-known-good
// (FR-012). See specs/001-horizontal-scaling/contracts/sync-protocol.md.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zwarder/waf/gobackend/internal/storage"
)

const tmpSuffix = ".edge-tmp"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	store, err := storage.NewS3(s3OptsFromEnv())
	if err != nil {
		log.Error("s3 client init failed", "err", err)
		os.Exit(1)
	}

	metrics := newEdgeMetrics()
	s := &syncer{
		store:     store,
		layout:    edgeLayout(),
		statePath: getenv("WAF_EDGE_STATE_FILE", filepath.Join(getenv("WAF_STATE_DIR", "/var/lib/angie/data"), ".edge_applied.json")),
		testCmd:   getenv("WAF_ANGIE_TEST_CMD", "angie -t"),
		reloadCmd: getenv("WAF_ANGIE_RELOAD_CMD", "angie -s reload"),
		metrics:   metrics,
		log:       log,
	}
	s.applied = s.loadApplied() // cold start → empty manifest (generation 0)

	// Metrics endpoint for operator convergence view (SC-007).
	metricsAddr := getenv("WAF_EDGE_METRICS_ADDR", ":9101")
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.handler())
		srv := &http.Server{Addr: metricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		log.Info("edge-sync metrics serving", "addr", metricsAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server failed", "err", err)
		}
	}()

	interval := time.Duration(getenvInt("WAF_EDGE_SYNC_INTERVAL", 10)) * time.Second
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("edge-sync starting",
		"interval", interval, "bucket", getenv("WAF_S3_BUCKET", "waf-state"),
		"applied_generation", s.applied.Generation)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.tick(ctx) // sync immediately so a fresh node converges without waiting a full interval
	for {
		select {
		case <-ctx.Done():
			log.Info("edge-sync stopped")
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

// syncer holds the loop state. applied is the last manifest fully materialised
// AND reloaded — the diff baseline and the last-known-good marker.
type syncer struct {
	store     storage.Store
	layout    storage.LocalLayout
	statePath string
	testCmd   string
	reloadCmd string
	metrics   *edgeMetrics
	log       *slog.Logger

	applied storage.Manifest
}

// tick runs one sync cycle. Any failure leaves applied (and the live tree)
// untouched: the node keeps serving the last-known-good generation (FR-012).
func (s *syncer) tick(ctx context.Context) {
	now := time.Now()
	s.metrics.refreshLag(now)

	m, _, err := s.store.ReadManifest(ctx)
	if err != nil {
		s.metrics.errorsTotal.Inc()
		s.log.Warn("read manifest failed; staying on last-known-good", "err", err, "applied", s.applied.Generation)
		return
	}
	if m.Generation <= s.applied.Generation {
		return // idempotent: nothing new (also the steady state)
	}

	if err := s.apply(ctx, m); err != nil {
		s.metrics.errorsTotal.Inc()
		s.log.Warn("apply generation failed; staying on last-known-good", "gen", m.Generation, "err", err)
		return
	}

	s.applied = m
	if err := s.saveApplied(m); err != nil {
		s.log.Warn("persist applied manifest failed (will re-diff on restart)", "err", err)
	}
	s.metrics.applied(m.Generation, time.Now())
	s.log.Info("applied generation", "gen", m.Generation, "entries", len(m.Entries))
}

// apply materialises manifest m over the live tree atomically: download every
// changed object to a temp file first (live tree untouched if a download fails),
// then commit with per-file rename, then validate + reload. Advancing the
// applied generation happens only in tick after this returns nil.
func (s *syncer) apply(ctx context.Context, m storage.Manifest) error {
	suspended := make(map[int64]struct{}, len(m.SuspendedTenants))
	for _, tid := range m.SuspendedTenants {
		suspended[tid] = struct{}{}
	}

	// desired = manifest entries minus suspended tenants' subtrees (FR-011).
	desired := make(map[string]storage.Entry, len(m.Entries))
	for k, e := range m.Entries {
		if tid, ok := tenantOfKey(k); ok {
			if _, isSusp := suspended[tid]; isSusp {
				continue
			}
		}
		desired[k] = e
	}

	// Phase 1 — download every changed/missing object to a temp file. A key is
	// (re)downloaded when its etag differs from applied OR the local file is gone
	// (covers cold start, unsuspend, and local drift).
	type staged struct{ tmp, final string }
	var pending []staged
	cleanup := func() {
		for _, st := range pending {
			_ = os.Remove(st.tmp)
		}
	}
	for k, e := range desired {
		final := s.layout.Path(k)
		if prev, ok := s.applied.Entries[k]; ok && prev.ETag == e.ETag && fileExists(final) {
			continue
		}
		tmp := final + tmpSuffix
		if err := s.download(ctx, k, tmp, fileMode(e)); err != nil {
			cleanup()
			return err
		}
		pending = append(pending, staged{tmp: tmp, final: final})
	}

	// Phase 2 — commit. Per-file rename is atomic on POSIX; the manifest already
	// gated visibility, so this never exposes a partial set.
	for _, st := range pending {
		if err := os.Rename(st.tmp, st.final); err != nil {
			cleanup()
			return err
		}
	}
	// Remove objects that left the manifest (delete) or were suspended.
	for k := range s.applied.Entries {
		if _, keep := desired[k]; keep {
			continue
		}
		path := s.layout.Path(k)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			s.log.Warn("remove stale object failed", "key", k, "err", err)
			continue
		}
		pruneEmptyDir(filepath.Dir(path))
	}

	// Phase 3 — validate then reload this node's Angie. A failed `angie -t` keeps
	// the running config (reload not issued) → last-known-good in memory.
	if out, err := s.run(s.testCmd); err != nil {
		return errors.New("angie -t failed: " + strings.TrimSpace(out))
	}
	if out, err := s.run(s.reloadCmd); err != nil {
		return errors.New("angie reload failed: " + strings.TrimSpace(out))
	}
	return nil
}

// download streams key into tmp with the given mode (sensitive → 0600).
func (s *syncer) download(ctx context.Context, key, tmp string, mode os.FileMode) error {
	rc, _, err := s.store.Get(ctx, key)
	if err != nil {
		return err
	}
	defer rc.Close()
	if err := os.MkdirAll(filepath.Dir(tmp), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, rc); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil { // umask can mask O_CREATE perms
		_ = f.Close()
		return err
	}
	return f.Close()
}

// run executes a configurable shell command (angie -t / reload). Empty → skip.
func (s *syncer) run(cmd string) (string, error) {
	if strings.TrimSpace(cmd) == "" {
		return "", nil
	}
	c := exec.Command("sh", "-c", cmd)
	out, err := c.CombinedOutput()
	return string(out), err
}

// loadApplied reads the persisted applied manifest; absent/corrupt → generation 0
// (full cold sync, FR-008).
func (s *syncer) loadApplied() storage.Manifest {
	data, err := os.ReadFile(s.statePath)
	if err != nil {
		return storage.NewManifest("default")
	}
	m, err := storage.UnmarshalManifest(data)
	if err != nil {
		s.log.Warn("applied state file corrupt; cold full sync", "err", err)
		return storage.NewManifest("default")
	}
	return m
}

// saveApplied persists the applied manifest atomically (temp + rename).
func (s *syncer) saveApplied(m storage.Manifest) error {
	data, err := storage.MarshalManifest(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.statePath), 0o755); err != nil {
		return err
	}
	tmp := s.statePath + tmpSuffix
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath)
}

func s3OptsFromEnv() storage.S3Options {
	return storage.S3Options{
		Endpoint:  os.Getenv("WAF_S3_ENDPOINT"),
		AccessKey: os.Getenv("WAF_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("WAF_S3_SECRET_KEY"),
		Bucket:    getenv("WAF_S3_BUCKET", "waf-state"),
		Region:    os.Getenv("WAF_S3_REGION"),
		UseTLS:    getenv("WAF_S3_USE_TLS", "false") == "true",
		Scope:     "default",
	}
}

// tenantOfKey extracts <tid> from a tenants/<tid>/… key.
func tenantOfKey(key string) (int64, bool) {
	rest, ok := strings.CutPrefix(key, "tenants/")
	if !ok {
		return 0, false
	}
	tid, _, _ := strings.Cut(rest, "/")
	n, err := strconv.ParseInt(tid, 10, 64)
	return n, err == nil
}

func fileMode(e storage.Entry) os.FileMode {
	if e.Mode != 0 {
		return os.FileMode(e.Mode)
	}
	if e.Sensitive {
		return 0o600
	}
	return 0o644
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// pruneEmptyDir best-effort removes dir if empty (tidies emptied conn_<id> dirs).
func pruneEmptyDir(dir string) {
	_ = os.Remove(dir) // fails (ignored) when non-empty
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
