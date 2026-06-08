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
// The public surface used by later tasks:
//   - Syncer.SyncBlockedIPsConf(ctx) — the full sync (decisions list →
//     route IPs → write per-connection files → reload Angie).
//   - Syncer.WriteConnectionsRegistry(conns) — materialise the DB snapshot
//     that the sync uses.
//   - Syncer.LoadBlockedIPsMapping / SaveBlockedIPsMapping — manual-block state.
package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zwarder/waf/gobackend/internal/store"
)

// ── Interfaces (keep Syncer testable without Docker) ──────────────────────────

// CSCLIRunner is the interface the Syncer depends on for cscli execution.
// *cscli.Runner satisfies it; tests use fakeRunner.
type CSCLIRunner interface {
	RunJSON(ctx context.Context, args ...string) (json.RawMessage, error)
}

// AngieReloader is called after blocked_ips.conf files are updated.
// Pass angie.Reload (a function value adaptor) or a no-op for tests.
type AngieReloader interface {
	Reload(ctx context.Context)
}

// ConnectionSource provides the live connection list.
// *store.Store satisfies it; tests use fakeConnSource.
type ConnectionSource interface {
	ListConnections(ctx context.Context) ([]Connection, error)
}

// Connection is the crowdsec-package view of a connection row.
// Exactly the fields that the Python registry / sync functions use.
type Connection struct {
	ID       int64
	TenantID int64
	Name     string
	Domain   string // canonical single domain (lowercase, IDNA-normalised)
	Enabled  bool
	Status   string
}

// ── Syncer ────────────────────────────────────────────────────────────────────

// Syncer holds the configuration for the blocked-IPs sync logic.
type Syncer struct {
	runner  CSCLIRunner
	reloader AngieReloader
	src     ConnectionSource

	// stateDir is the backend-writable dir for JSON state files.
	// Matches Python _STATE_DIR = "/var/lib/angie/data".
	stateDir string

	// tenantsBase is the host-side path to the waf-tenants volume.
	// Matches Python TENANTS_BASE = "/var/lib/waf/tenants".
	tenantsBase string
}

// NewSyncer constructs a Syncer with production defaults.
func NewSyncer(runner CSCLIRunner, reloader AngieReloader, src ConnectionSource) *Syncer {
	stateDir := os.Getenv("WAF_STATE_DIR")
	if stateDir == "" {
		stateDir = "/var/lib/angie/data"
	}
	tenantsBase := os.Getenv("WAF_TENANTS_DIR")
	if tenantsBase == "" {
		tenantsBase = "/var/lib/waf/tenants"
	}
	return &Syncer{
		runner:      runner,
		reloader:    reloader,
		src:         src,
		stateDir:    stateDir,
		tenantsBase: tenantsBase,
	}
}

// NewSyncerWithDirs constructs a Syncer with explicit directories (useful in tests).
func NewSyncerWithDirs(runner CSCLIRunner, reloader AngieReloader, src ConnectionSource, stateDir, tenantsBase string) *Syncer {
	return &Syncer{
		runner:      runner,
		reloader:    reloader,
		src:         src,
		stateDir:    stateDir,
		tenantsBase: tenantsBase,
	}
}

// ── State file paths ──────────────────────────────────────────────────────────

func (s *Syncer) connectionsJSON() string {
	return filepath.Join(s.stateDir, "connections.json")
}

func (s *Syncer) blockedIPsMappingPath() string {
	return filepath.Join(s.stateDir, "blocked_ips_mapping.json")
}

// connComposeDir returns the per-connection directory Angie reads config from.
// Mirrors Python _conn_compose_dir(tenant_id, conn_id).
func (s *Syncer) connComposeDir(tenantID, connID int64) string {
	return filepath.Join(s.tenantsBase, fmt.Sprintf("%d", tenantID), "compose", fmt.Sprintf("conn_%d", connID))
}

// ── Connection registry ───────────────────────────────────────────────────────

// registryEntry is the JSON shape written to connections.json.
// Mirrors the payload list in Python _write_connections_registry.
type registryEntry struct {
	ID       int64  `json:"id"`
	TenantID int64  `json:"tenant_id"`
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Enabled  bool   `json:"enabled"`
	Status   string `json:"status"`
}

// WriteConnectionsRegistry materialises the live connection set into the
// connections.json cache file (atomic rename, mirrors Python _write_connections_registry).
// Called by the periodic sync loop before SyncBlockedIPsConf.
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
	if err := os.MkdirAll(s.stateDir, 0o755); err != nil {
		return fmt.Errorf("crowdsec: create state dir: %w", err)
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	dst := s.connectionsJSON()
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// loadConnections reads connections.json and returns all entries.
// Mirrors Python _load_connections.
func (s *Syncer) loadConnections() []registryEntry {
	data, err := os.ReadFile(s.connectionsJSON())
	if err != nil {
		if !os.IsNotExist(err) {
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
// Mirrors Python _load_connection_ids.
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

// connDomains returns all domains for a registry entry.
// In the Python registry format the single domain is stored in "domain"; the
// Python _conn_domains also checks a "domains" list key but WriteConnectionsRegistry
// only writes the single "domain" field. For faithful port we just return the
// single Domain field (which is already the canonical domain).
// Mirrors Python _conn_domains.
func connDomains(e registryEntry) []string {
	if e.Domain == "" {
		return nil
	}
	return []string{e.Domain}
}

// buildDomainToConnMap builds domain→connectionID (first match wins, enabled only).
// Mirrors Python _build_domain_to_conn_map.
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
// Mirrors Python _build_conn_tenant_map.
func (s *Syncer) buildConnTenantMap() map[int64]int64 {
	m := make(map[int64]int64)
	for _, e := range s.loadConnections() {
		m[e.ID] = e.TenantID
	}
	return m
}

// ── Blocked IPs mapping (manual block state) ──────────────────────────────────

// LoadBlockedIPsMapping loads the IP→connectionIDs manual mapping from disk.
// Mirrors Python _load_blocked_ips_mapping.
func (s *Syncer) LoadBlockedIPsMapping() map[string][]int64 {
	data, err := os.ReadFile(s.blockedIPsMappingPath())
	if err != nil {
		if !os.IsNotExist(err) {
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

// SaveBlockedIPsMapping persists the IP→connectionIDs mapping to disk.
// Mirrors Python _save_blocked_ips_mapping (note: Python uses indent=2).
func (s *Syncer) SaveBlockedIPsMapping(mapping map[string][]int64) error {
	if err := os.MkdirAll(s.stateDir, 0o755); err != nil {
		return fmt.Errorf("crowdsec: create state dir: %w", err)
	}
	data, err := json.MarshalIndent(mapping, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.blockedIPsMappingPath(), data, 0o644)
}

// ── CrowdSec alert/decision parsing ──────────────────────────────────────────

// Alert is the JSON shape of one element from `cscli decisions list -o json`.
// cscli returns a list of alert objects, each with a source and nested decisions.
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
// Mirrors Python _extract_target_hosts_from_alerts.
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
	// 1. Manual mapping
	if ids, ok := manualMapping[ipValue]; ok {
		return ids
	}

	// 2. Automatic: resolve via target_host
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

	// 3. Fallback: all connections
	return allConnIDs
}

// ── SyncBlockedIPsConf — the main sync ───────────────────────────────────────

const blockedIPsHeader = "# Auto-generated by WAF backend — do not edit manually\n" +
	"# Per-connection CrowdSec ban list; synced on block/unblock and periodically.\n"

// SyncBlockedIPsConf is the faithful Go port of Python _sync_blocked_ips_conf.
//
// Algorithm:
//  1. `cscli decisions list` → collect all banned IPs from "ban" decisions.
//  2. Load the connection registry + manual IP mapping + domain map.
//  3. Route each banned IP to its target connection(s) via resolveIPConnections.
//  4. For each enabled connection whose compose dir exists, write (or overwrite)
//     blocked_ips.conf with the appropriate deny lines.
//  5. Reload Angie.
//
// Security invariant: an IP is only written to the blocked_ips.conf of the
// connection(s) it is routed to — never to all connections unless it has no
// target_host meta AND is not in the manual mapping, in which case fallback to
// all connections is the correct Python behaviour.
func (s *Syncer) SyncBlockedIPsConf(ctx context.Context) error {
	// 1. Fetch decisions from CrowdSec.
	raw, err := s.runner.RunJSON(ctx, "decisions", "list")
	if err != nil {
		return fmt.Errorf("crowdsec: cscli decisions list: %w", err)
	}

	var alerts []Alert
	if raw != nil {
		if err := json.Unmarshal(raw, &alerts); err != nil {
			// Non-list response (e.g. null or {}): treat as empty.
			slog.Warn("crowdsec: decisions list returned non-array JSON", "err", err)
			alerts = nil
		}
	}

	// Collect all unique banned IPs.
	bannedIPs := make(map[string]struct{})
	for _, alert := range alerts {
		for _, dec := range alert.Decisions {
			if dec.Type == "ban" && dec.Value != "" {
				bannedIPs[dec.Value] = struct{}{}
			}
		}
	}

	// 2. Load supporting maps.
	allConnIDs := s.loadConnectionIDs()
	manualMapping := s.LoadBlockedIPsMapping()
	targetHosts := ExtractTargetHosts(alerts)
	domainToConn := s.buildDomainToConnMap()
	connTenant := s.buildConnTenantMap()

	// 3. Route each IP to connection(s).
	// connIPs[connID] = set of IPs to deny in that connection's file.
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

	// 4. Write per-connection blocked_ips.conf files.
	written := 0
	for _, connID := range allConnIDs {
		tenantID, ok := connTenant[connID]
		if !ok {
			continue
		}
		connDir := s.connComposeDir(tenantID, connID)
		// Skip connections whose config tree isn't materialised yet —
		// writing there would create an orphan dir Angie never includes
		// (same guard as Python).
		info, statErr := os.Stat(connDir)
		if statErr != nil || !info.IsDir() {
			continue
		}

		// Sort IPs for deterministic output.
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

		confPath := filepath.Join(connDir, "blocked_ips.conf")
		if err := os.WriteFile(confPath, []byte(sb.String()), 0o644); err != nil {
			slog.Warn("crowdsec: failed to write blocked_ips.conf",
				"conn", connID, "path", confPath, "err", err)
			continue
		}
		written++
	}

	// 5. Reload Angie.
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

