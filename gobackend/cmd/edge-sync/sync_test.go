package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zwarder/waf/gobackend/internal/storage"
)

// TestSyncerApply drives the real Store + Publisher through the sidecar diff:
// cold-start full sync, suspend removal, unsuspend re-download, idempotency.
// Reload/test commands are empty so the test needs no shell.
func TestSyncerApply(t *testing.T) {
	ctx := context.Background()
	remote := storage.NewLocalFS(t.TempDir(), "default") // stands in for S3
	pub := storage.NewPublisher(remote)
	edge := t.TempDir()

	put := func(key, body string, sensitive bool) storage.ObjectInfo {
		oi, err := remote.Put(ctx, key, strings.NewReader(body), storage.PutOptions{Sensitive: sensitive})
		require.NoError(t, err)
		return oi
	}
	conf1 := put("tenants/1/conn_10/10.conf", "server{}", false)
	key1 := put("tenants/1/conn_10/10.key", "PRIVKEY", true)
	conf2 := put("tenants/2/conn_20/20.conf", "server{}", false)
	rules := put("modsec/rules.conf", "Include x", false)
	require.NoError(t, pub.Publish(ctx, storage.ChangeSet{Changed: []storage.ObjectInfo{conf1, key1, conf2, rules}}))

	s := &syncer{
		store: remote,
		layout: storage.LocalLayout{
			Tenants: filepath.Join(edge, "tenants"),
			HTTPD:   filepath.Join(edge, "httpd"),
			State:   filepath.Join(edge, "state"),
			Modsec:  filepath.Join(edge, "modsec"),
		},
		statePath: filepath.Join(edge, "state", ".edge_applied.json"),
		metrics:   newEdgeMetrics(),
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		// testCmd/reloadCmd empty → reload steps skipped (no shell dependency).
	}
	s.applied = s.loadApplied()
	require.Equal(t, int64(0), s.applied.Generation, "cold start")

	t10conf := filepath.Join(edge, "tenants", "1", "compose", "conn_10", "10.conf")
	t10key := filepath.Join(edge, "tenants", "1", "compose", "conn_10", "10.key")
	t20conf := filepath.Join(edge, "tenants", "2", "compose", "conn_20", "20.conf")
	msRules := filepath.Join(edge, "modsec", "rules.conf")

	// Gen 1: full cold sync materialises every object via the edge layout.
	s.tick(ctx)
	require.Equal(t, int64(1), s.applied.Generation)
	requireContent(t, t10conf, "server{}")
	requireContent(t, t10key, "PRIVKEY")
	requireContent(t, t20conf, "server{}")
	requireContent(t, msRules, "Include x")

	// Gen 2: suspend tenant 1 → its subtree removed, tenant 2 untouched (FR-011).
	require.NoError(t, pub.Publish(ctx, storage.ChangeSet{SuspendAdd: []int64{1}}))
	s.tick(ctx)
	require.Equal(t, int64(2), s.applied.Generation)
	require.NoFileExists(t, t10conf)
	require.NoFileExists(t, t10key)
	requireContent(t, t20conf, "server{}")

	// Gen 3: unsuspend → tenant 1 re-downloaded (local files were gone).
	require.NoError(t, pub.Publish(ctx, storage.ChangeSet{SuspendRemove: []int64{1}}))
	s.tick(ctx)
	require.Equal(t, int64(3), s.applied.Generation)
	requireContent(t, t10conf, "server{}")
	requireContent(t, t10key, "PRIVKEY")

	// Idempotent: no new generation → no change.
	s.tick(ctx)
	require.Equal(t, int64(3), s.applied.Generation)

	// Persisted applied survives a restart (no redundant re-sync).
	s2 := &syncer{statePath: s.statePath, log: s.log}
	require.Equal(t, int64(3), s2.loadApplied().Generation)
}

func TestSyncerApplyRejectsUnsafeManifestKey(t *testing.T) {
	edge := t.TempDir()
	s := &syncer{
		layout: storage.LocalLayout{
			Tenants: filepath.Join(edge, "tenants"),
			HTTPD:   filepath.Join(edge, "httpd"),
			State:   filepath.Join(edge, "state"),
			Modsec:  filepath.Join(edge, "modsec"),
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	m := storage.NewManifest("default")
	m.Generation = 1
	m.Entries = map[string]storage.Entry{
		"state/../../outside": {ETag: "x"},
	}

	err := s.apply(context.Background(), m)
	require.Error(t, err)
	require.NoFileExists(t, filepath.Join(edge, "outside"))
}

func requireContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, want, string(got))
}
