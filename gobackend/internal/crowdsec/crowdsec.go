// Package crowdsec implements the CrowdSec banned-IP sync logic.
//
// This is a faithful port of backend/src/crowdsec/service.py — specifically
// the registry/state/mapping/sync functions that enforce the per-connection
// ban isolation invariant:
//
//	"Each connection's Angie server block includes
//	 /etc/angie/tenants/<tid>/compose/conn_<id>/blocked_ips.conf, so a ban
//	 routed to one connection by _resolve_ip_connections lands only in that
//	 connection's file and never leaks onto other domains."
//
// State and per-connection ban files are written through the shared store
// (storage.Store) so every edge node converges to the same bans (horizontal
// scaling); blocked_ips.conf writes publish a manifest generation.
package crowdsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zwarder/waf/gobackend/internal/storage"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// ── Interfaces (keep Syncer testable without Docker) ──────────────────────────

// CSCLIRunner is the interface the Syncer depends on for cscli execution.
type CSCLIRunner interface {
	RunJSON(ctx context.Context, args ...string) (json.RawMessage, error)
}

// AngieReloader is called after blocked_ips.conf files are updated.
type AngieReloader interface {
	Reload(ctx context.Context)
}

// ConnectionSource provides the live connection list.
type ConnectionSource interface {
	ListConnections(ctx context.Context) ([]Connection, error)
}

// Connection is the crowdsec-package view of a connection row.
type Connection struct {
	ID       int64
	TenantID int64
	Name     string
	Domain   string // canonical single domain (lowercase, IDNA-normalised)
	Enabled  bool
	Status   string
}

// ── Canonical object keys ─────────────────────────────────────────────────────

const (
	connectionsKey = "state/connections.json"
	mappingKey     = "state/blocked_ips_mapping.json"
)

func connBlockedKey(tenantID, connID int64) string {
	return fmt.Sprintf("tenants/%d/conn_%d/blocked_ips.conf", tenantID, connID)
}

// ── Syncer ────────────────────────────────────────────────────────────────────

// Syncer holds the configuration for the blocked-IPs sync logic.
type Syncer struct {
	runner   CSCLIRunner
	reloader AngieReloader
	src      ConnectionSource
	store    storage.Store
	pub      *storage.Publisher

	// stateDir is used only by the path helpers (tests); writes go via the store.
	stateDir string

	// guardBase is the local tenants base for the dir-existence guard in
	// SyncBlockedIPsConf. Non-empty in local mode; "" in s3 mode (no skip).
	guardBase string
}

// NewSyncer constructs a Syncer with production defaults. localTenantsBase is
// the live tenants dir for the dir-existence guard ("" in s3 mode).
func NewSyncer(runner CSCLIRunner, reloader AngieReloader, src ConnectionSource, st storage.Store, pub *storage.Publisher, localTenantsBase string) *Syncer {
	stateDir := os.Getenv("WAF_STATE_DIR")
	if stateDir == "" {
		stateDir = "/var/lib/angie/data"
	}
	return &Syncer{
		runner:    runner,
		reloader:  reloader,
		src:       src,
		store:     st,
		pub:       pub,
		stateDir:  stateDir,
		guardBase: localTenantsBase,
	}
}

// NewSyncerWithDirs constructs a Syncer backed by a local-mapped store so writes
// land at the given dirs (used in tests).
func NewSyncerWithDirs(runner CSCLIRunner, reloader AngieReloader, src ConnectionSource, stateDir, tenantsBase string) *Syncer {
	st := storage.NewLocalFSMapped(storage.LocalLayout{
		State:   stateDir,
		Tenants: tenantsBase,
		HTTPD:   filepath.Join(stateDir, "httpd"),
		Modsec:  filepath.Join(stateDir, "modsec"),
	}, "test")
	return &Syncer{
		runner:    runner,
		reloader:  reloader,
		src:       src,
		store:     st,
		pub:       storage.NewPublisher(st),
		stateDir:  stateDir,
		guardBase: tenantsBase,
	}
}

// ── State file paths (path helpers used by tests) ─────────────────────────────

func (s *Syncer) connectionsJSON() string {
	return filepath.Join(s.stateDir, "connections.json")
}

func (s *Syncer) blockedIPsMappingPath() string {
	return filepath.Join(s.stateDir, "blocked_ips_mapping.json")
}

// connComposeDir returns the per-connection directory Angie reads config from
// (local mode only; used by the dir-existence guard).
func (s *Syncer) connComposeDir(tenantID, connID int64) string {
	return filepath.Join(s.guardBase, fmt.Sprintf("%d", tenantID), "compose", fmt.Sprintf("conn_%d", connID))
}

// readObject reads an object's bytes; maps a missing object to ErrNotFound.
func (s *Syncer) readObject(key string) ([]byte, error) {
	rc, _, err := s.store.Get(context.Background(), key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (s *Syncer) putObject(ctx context.Context, key string, data []byte) (storage.ObjectInfo, error) {
	return s.store.Put(ctx, key, strings.NewReader(string(data)), storage.PutOptions{})
}

// ── Connection registry ───────────────────────────────────────────────────────

type registryEntry struct {
	ID       int64  `json:"id"`
	TenantID int64  `json:"tenant_id"`
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Enabled  bool   `json:"enabled"`
	Status   string `json:"status"`
}

// WriteConnectionsRegistry materialises the live connection set into the
// connections.json object. Backend-internal state (not edge-consumed) — no
// manifest publish.
func (s *Syncer) WriteConnectionsRegistry(conns []Connection) error {
	entries := make([]registryEntry, 0, len(conns))
	for _, c := range conns {
		entries = append(entries, registryEntry{
			ID:       c.ID,
			TenantID: c.TenantID,
			Name:     c.Name,
			Domain:   c.Domain,
			Enabled:  c.Enabled,
			Status:   c.Status,
		})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	_, err = s.putObject(context.Background(), connectionsKey, data)
	return err
}

// loadConnections reads connections.json and returns all entries.
func (s *Syncer) loadConnections() []registryEntry {
	data, err := s.readObject(connectionsKey)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			slog.Warn("crowdsec: failed to read connections.json", "err", err)
		}
		return nil
	}
	var entries []registryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		slog.Warn("crowdsec: failed to parse connections.json", "err", err)
		return nil
	}
	return entries
}

// loadConnectionIDs returns IDs of enabled connections.
func (s *Syncer) loadConnectionIDs() []int64 {
	entries := s.loadConnections()
	out := make([]int64, 0, len(entries))
	for _, e := range entries {
		if e.Enabled {
			out = append(out, e.ID)
		}
	}
	return out
}

// ── Domain helpers ────────────────────────────────────────────────────────────

func connDomains(e registryEntry) []string {
	if e.Domain == "" {
		return nil
	}
	return []string{e.Domain}
}

// buildDomainToConnMap builds domain→connectionID (first match wins, enabled only).
func (s *Syncer) buildDomainToConnMap() map[string]int64 {
	m := make(map[string]int64)
	for _, e := range s.loadConnections() {
		if !e.Enabled {
			continue
		}
		for _, d := range connDomains(e) {
			dl := strings.ToLower(strings.TrimSpace(d))
			if dl == "" {
				continue
			}
			if _, exists := m[dl]; !exists {
				m[dl] = e.ID
			}
		}
	}
	return m
}

// buildConnTenantMap builds connectionID→tenantID.
func (s *Syncer) buildConnTenantMap() map[int64]int64 {
	m := make(map[int64]int64)
	for _, e := range s.loadConnections() {
		m[e.ID] = e.TenantID
	}
	return m
}

// ── Blocked IPs mapping (manual block state) ──────────────────────────────────

// LoadBlockedIPsMapping loads the IP→connectionIDs manual mapping.
func (s *Syncer) LoadBlockedIPsMapping() map[string][]int64 {
	data, err := s.readObject(mappingKey)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			slog.Warn("crowdsec: failed to read blocked_ips_mapping.json", "err", err)
		}
		return make(map[string][]int64)
	}
	var m map[string][]int64
	if err := json.Unmarshal(data, &m); err != nil {
		slog.Warn("crowdsec: failed to parse blocked_ips_mapping.json", "err", err)
		return make(map[string][]int64)
	}
	return m
}

// SaveBlockedIPsMapping persists the IP→connectionIDs mapping (indent=2, mirrors
// Python). Backend-internal state — no manifest publish.
func (s *Syncer) SaveBlockedIPsMapping(mapping map[string][]int64) error {
	data, err := json.MarshalIndent(mapping, "", "  ")
	if err != nil {
		return err
	}
	_, err = s.putObject(context.Background(), mappingKey, data)
	return err
}

// ── CrowdSec alert/decision parsing ──────────────────────────────────────────

type Alert struct {
	ID        json.RawMessage `json:"id"`
	Scenario  string          `json:"scenario"`
	Message   string          `json:"message"`
	Source    map[string]any  `json:"source"`
	Decisions []Decision      `json:"decisions"`
	Meta      []MetaItem      `json:"meta"`
	StopAt    string          `json:"stop_at"`
	StartAt   string          `json:"start_at"`
	Capacity  json.RawMessage `json:"capacity"`
}

type Decision struct {
	ID       json.RawMessage `json:"id"`
	Value    string          `json:"value"`
	Type     string          `json:"type"`
	Duration string          `json:"duration"`
	Origin   string          `json:"origin"`
	Scope    string          `json:"scope"`
}

type MetaItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ExtractTargetHosts parses CrowdSec alert meta for target_host / http_host
// entries, returning ip_value → set of hostnames.
func ExtractTargetHosts(alerts []Alert) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{})
	for _, alert := range alerts {
		ipValue := ""
		if src, ok := alert.Source["value"]; ok {
			if v, ok := src.(string); ok {
				ipValue = v
			}
		}
		if ipValue == "" {
			continue
		}
		for _, m := range alert.Meta {
			key := strings.ToLower(m.Key)
			val := strings.ToLower(strings.TrimSpace(m.Value))
			if val == "" {
				continue
			}
			switch key {
			case "target_host", "http_host", "target_fqdn", "host":
				if result[ipValue] == nil {
					result[ipValue] = make(map[string]struct{})
				}
				result[ipValue][val] = struct{}{}
			}
		}
	}
	return result
}

// ResolveIPConnections determines which connections an IP should be blocked on.
//
// Priority (mirrors Python _resolve_ip_connections exactly):
//  1. Manual mapping (IP → explicit connection_ids)
//  2. Automatic: target_host from CrowdSec meta → domain → connection_id
//  3. Fallback: all connections
func ResolveIPConnections(
	ipValue string,
	manualMapping map[string][]int64,
	targetHosts map[string]map[string]struct{},
	domainToConn map[string]int64,
	allConnIDs []int64,
) []int64 {
	if ids, ok := manualMapping[ipValue]; ok {
		return ids
	}

	ipHosts := targetHosts[ipValue]
	connIDSet := make(map[int64]struct{})
	for host := range ipHosts {
		if connID, ok := domainToConn[host]; ok {
			connIDSet[connID] = struct{}{}
		}
	}
	if len(connIDSet) > 0 {
		ids := make([]int64, 0, len(connIDSet))
		for id := range connIDSet {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		return ids
	}

	return allConnIDs
}

// ── SyncBlockedIPsConf — the main sync ───────────────────────────────────────

const blockedIPsHeader = "# Auto-generated by WAF backend — do not edit manually\n" +
	"# Per-connection CrowdSec ban list; synced on block/unblock and periodically.\n"

// SyncBlockedIPsConf is the faithful Go port of Python _sync_blocked_ips_conf.
//
// Security invariant: an IP is only written to the blocked_ips.conf of the
// connection(s) it is routed to — never to all connections unless it has no
// target_host meta AND is not in the manual mapping (fallback-to-all, the
// correct Python behaviour).
func (s *Syncer) SyncBlockedIPsConf(ctx context.Context) error {
	raw, err := s.runner.RunJSON(ctx, "decisions", "list")
	if err != nil {
		return fmt.Errorf("crowdsec: cscli decisions list: %w", err)
	}

	var alerts []Alert
	if raw != nil {
		if err := json.Unmarshal(raw, &alerts); err != nil {
			slog.Warn("crowdsec: decisions list returned non-array JSON", "err", err)
			alerts = nil
		}
	}

	bannedIPs := make(map[string]struct{})
	for _, alert := range alerts {
		for _, dec := range alert.Decisions {
			if dec.Type == "ban" && dec.Value != "" {
				bannedIPs[dec.Value] = struct{}{}
			}
		}
	}

	allConnIDs := s.loadConnectionIDs()
	manualMapping := s.LoadBlockedIPsMapping()
	targetHosts := ExtractTargetHosts(alerts)
	domainToConn := s.buildDomainToConnMap()
	connTenant := s.buildConnTenantMap()

	connIPs := make(map[int64]map[string]struct{}, len(allConnIDs))
	for _, cid := range allConnIDs {
		connIPs[cid] = make(map[string]struct{})
	}
	for ipVal := range bannedIPs {
		for _, cid := range ResolveIPConnections(ipVal, manualMapping, targetHosts, domainToConn, allConnIDs) {
			if _, exists := connIPs[cid]; !exists {
				connIPs[cid] = make(map[string]struct{})
			}
			connIPs[cid][ipVal] = struct{}{}
		}
	}

	written := 0
	var changed []storage.ObjectInfo
	for _, connID := range allConnIDs {
		tenantID, ok := connTenant[connID]
		if !ok {
			continue
		}
		// Local-mode dir guard: skip connections whose compose tree isn't
		// materialised yet (writing there would create an orphan dir). In s3
		// mode (guardBase=="") we write for all enabled conns; angiecfg's
		// skip-if-exists preserves the banlist.
		if s.guardBase != "" {
			info, statErr := os.Stat(s.connComposeDir(tenantID, connID))
			if statErr != nil || !info.IsDir() {
				continue
			}
		}

		ips := connIPs[connID]
		sortedIPs := make([]string, 0, len(ips))
		for ip := range ips {
			sortedIPs = append(sortedIPs, ip)
		}
		sort.Strings(sortedIPs)

		var sb strings.Builder
		sb.WriteString(blockedIPsHeader)
		for _, ip := range sortedIPs {
			sb.WriteString("deny ")
			sb.WriteString(ip)
			sb.WriteString(";\n")
		}

		oi, err := s.store.Put(ctx, connBlockedKey(tenantID, connID), strings.NewReader(sb.String()), storage.PutOptions{})
		if err != nil {
			slog.Warn("crowdsec: failed to write blocked_ips.conf", "conn", connID, "err", err)
			continue
		}
		changed = append(changed, oi)
		written++
	}

	if len(changed) > 0 {
		if err := s.pub.Publish(ctx, storage.ChangeSet{Changed: changed}); err != nil {
			slog.Warn("crowdsec: failed to publish manifest", "err", err)
		}
	}

	s.reloader.Reload(ctx)

	slog.Info("crowdsec: synced banned IPs",
		"banned_ips", len(bannedIPs),
		"connections_written", written)

	return nil
}

// StoreConnSource adapts *store.Store to crowdsec.ConnectionSource.
type StoreConnSource struct {
	Store *store.Store
}

func (a StoreConnSource) ListConnections(ctx context.Context) ([]Connection, error) {
	rows, err := a.Store.ListConnections(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(rows))
	for _, r := range rows {
		out = append(out, Connection{
			ID:       r.ID,
			TenantID: r.TenantID,
			Name:     r.Name,
			Domain:   r.Domain,
			Enabled:  r.Enabled,
			Status:   r.Status,
		})
	}
	return out, nil
}
