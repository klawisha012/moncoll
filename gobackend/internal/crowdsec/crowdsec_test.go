package crowdsec

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// ── Fakes ─────────────────────────────────────────────────────────────────────

// fakeRunner returns a fixed JSON payload (simulating cscli decisions list).
type fakeRunner struct {
	payload json.RawMessage
	err     error
}

func (f *fakeRunner) RunJSON(_ context.Context, _ ...string) (json.RawMessage, error) {
	return f.payload, f.err
}

// fakeReloader records how many times Reload was called.
type fakeReloader struct{ calls int }

func (f *fakeReloader) Reload(_ context.Context) { f.calls++ }

// fakeConnSource returns a fixed connection list.
type fakeConnSource struct{ conns []Connection }

func (f *fakeConnSource) ListConnections(_ context.Context) ([]Connection, error) {
	return f.conns, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func newTestSyncer(t *testing.T, runner CSCLIRunner, reloader AngieReloader, stateDir, tenantsBase string) *Syncer {
	t.Helper()
	return NewSyncerWithDirs(runner, reloader, &fakeConnSource{}, stateDir, tenantsBase)
}

// seedConnections writes connections.json for the syncer to read back.
func seedConnections(t *testing.T, s *Syncer, conns []Connection) {
	t.Helper()
	require.NoError(t, s.WriteConnectionsRegistry(conns))
}

// ── Domain map tests ──────────────────────────────────────────────────────────

func TestBuildDomainToConnMap(t *testing.T) {
	stateDir := t.TempDir()
	r := &fakeReloader{}
	s := NewSyncerWithDirs(&fakeRunner{}, r, &fakeConnSource{}, stateDir, t.TempDir())

	conns := []Connection{
		{ID: 1, TenantID: 10, Name: "conn1", Domain: "example.com", Enabled: true},
		{ID: 2, TenantID: 10, Name: "conn2", Domain: "other.com", Enabled: true},
		{ID: 3, TenantID: 10, Name: "conn3", Domain: "disabled.com", Enabled: false},
	}
	seedConnections(t, s, conns)

	m := s.buildDomainToConnMap()

	require.Equal(t, int64(1), m["example.com"])
	require.Equal(t, int64(2), m["other.com"])
	_, hasDisabled := m["disabled.com"]
	require.False(t, hasDisabled, "disabled connections must not appear in domain map")
}

func TestBuildDomainToConnMap_FirstMatchWins(t *testing.T) {
	stateDir := t.TempDir()
	s := NewSyncerWithDirs(&fakeRunner{}, &fakeReloader{}, &fakeConnSource{}, stateDir, t.TempDir())

	// Two enabled connections with the same domain — first id wins (sorted by
	// registry order, which is insertion order = id order from ListConnections).
	conns := []Connection{
		{ID: 1, TenantID: 10, Domain: "dup.com", Enabled: true},
		{ID: 2, TenantID: 10, Domain: "dup.com", Enabled: true},
	}
	seedConnections(t, s, conns)

	m := s.buildDomainToConnMap()
	require.Equal(t, int64(1), m["dup.com"])
}

// ── Conn tenant map test ──────────────────────────────────────────────────────

func TestBuildConnTenantMap(t *testing.T) {
	stateDir := t.TempDir()
	s := NewSyncerWithDirs(&fakeRunner{}, &fakeReloader{}, &fakeConnSource{}, stateDir, t.TempDir())

	conns := []Connection{
		{ID: 5, TenantID: 99, Domain: "a.com", Enabled: true},
		{ID: 6, TenantID: 100, Domain: "b.com", Enabled: false},
	}
	seedConnections(t, s, conns)

	m := s.buildConnTenantMap()
	require.Equal(t, int64(99), m[5])
	require.Equal(t, int64(100), m[6])
}

// ── connDomains test ──────────────────────────────────────────────────────────

func TestConnDomains(t *testing.T) {
	e := registryEntry{Domain: "foo.com"}
	require.Equal(t, []string{"foo.com"}, connDomains(e))

	e2 := registryEntry{Domain: ""}
	require.Nil(t, connDomains(e2))
}

// ── Blocked IPs mapping round-trip ───────────────────────────────────────────

func TestBlockedIPsMappingRoundTrip(t *testing.T) {
	stateDir := t.TempDir()
	s := NewSyncerWithDirs(&fakeRunner{}, &fakeReloader{}, &fakeConnSource{}, stateDir, t.TempDir())

	// Initially empty.
	m := s.LoadBlockedIPsMapping()
	require.Empty(t, m)

	// Save and reload.
	mapping := map[string][]int64{
		"1.2.3.4":    {10, 20},
		"10.0.0.1":   {30},
	}
	require.NoError(t, s.SaveBlockedIPsMapping(mapping))

	loaded := s.LoadBlockedIPsMapping()
	require.Equal(t, mapping, loaded)
}

func TestBlockedIPsMappingFileContainsIndent(t *testing.T) {
	stateDir := t.TempDir()
	s := NewSyncerWithDirs(&fakeRunner{}, &fakeReloader{}, &fakeConnSource{}, stateDir, t.TempDir())

	require.NoError(t, s.SaveBlockedIPsMapping(map[string][]int64{"1.1.1.1": {1}}))

	raw, err := os.ReadFile(s.blockedIPsMappingPath())
	require.NoError(t, err)
	// Python uses indent=2; Go must match.
	require.Contains(t, string(raw), "  \"1.1.1.1\"")
}

// ── extractTargetHostsFromAlerts tests ───────────────────────────────────────

func TestExtractTargetHostsFromAlerts_Basic(t *testing.T) {
	alerts := []alertShape{
		{
			Source: map[string]any{"value": "1.2.3.4"},
			Meta: []metaItem{
				{Key: "target_host", Value: "example.com"},
				{Key: "http_host", Value: "Example.com"}, // normalised to lower
			},
		},
		{
			Source: map[string]any{"value": "5.6.7.8"},
			Meta: []metaItem{
				{Key: "target_fqdn", Value: "other.com"},
			},
		},
	}

	result := extractTargetHostsFromAlerts(alerts)
	require.Contains(t, result, "1.2.3.4")
	require.Contains(t, result["1.2.3.4"], "example.com")
	// Duplicate after lower-case normalisation — still just one entry.
	require.Len(t, result["1.2.3.4"], 1)

	require.Contains(t, result, "5.6.7.8")
	require.Contains(t, result["5.6.7.8"], "other.com")
}

func TestExtractTargetHostsFromAlerts_NoSource(t *testing.T) {
	alerts := []alertShape{
		{Source: map[string]any{}, Meta: []metaItem{{Key: "target_host", Value: "x.com"}}},
	}
	result := extractTargetHostsFromAlerts(alerts)
	require.Empty(t, result) // no ip_value → skip
}

func TestExtractTargetHostsFromAlerts_UnknownKey(t *testing.T) {
	alerts := []alertShape{
		{
			Source: map[string]any{"value": "9.9.9.9"},
			Meta:   []metaItem{{Key: "user_agent", Value: "curl"}},
		},
	}
	result := extractTargetHostsFromAlerts(alerts)
	// 9.9.9.9 has no target_host / http_host / etc — result is absent.
	require.Empty(t, result)
}

// ── resolveIPConnections tests ────────────────────────────────────────────────

func TestResolveIPConnections_ManualMapping(t *testing.T) {
	manual := map[string][]int64{"1.2.3.4": {5, 7}}
	result := resolveIPConnections("1.2.3.4", manual, nil, nil, []int64{1, 2, 3})
	require.Equal(t, []int64{5, 7}, result)
}

func TestResolveIPConnections_AutomaticViaTargetHost(t *testing.T) {
	manual := map[string][]int64{}
	targetHosts := map[string]map[string]struct{}{
		"1.2.3.4": {"example.com": {}, "staging.com": {}},
	}
	domainToConn := map[string]int64{
		"example.com": 10,
		"staging.com": 20,
	}
	allConns := []int64{10, 20, 30}

	result := resolveIPConnections("1.2.3.4", manual, targetHosts, domainToConn, allConns)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	require.Equal(t, []int64{10, 20}, result)
}

func TestResolveIPConnections_Fallback_AllConnections(t *testing.T) {
	// No manual mapping, no target_host meta → fallback to all.
	manual := map[string][]int64{}
	allConns := []int64{1, 2, 3}
	result := resolveIPConnections("9.9.9.9", manual, map[string]map[string]struct{}{}, map[string]int64{}, allConns)
	require.Equal(t, allConns, result)
}

func TestResolveIPConnections_TargetHostNotInDomainMap(t *testing.T) {
	// IP has target_host but the domain is not configured → fallback to all.
	manual := map[string][]int64{}
	targetHosts := map[string]map[string]struct{}{
		"1.2.3.4": {"unknown.com": {}},
	}
	domainToConn := map[string]int64{"example.com": 10}
	allConns := []int64{10, 20}

	result := resolveIPConnections("1.2.3.4", manual, targetHosts, domainToConn, allConns)
	require.Equal(t, allConns, result)
}

// ── SyncBlockedIPsConf integration (pure / in-memory) ────────────────────────

// decisionsJSON builds a realistic cscli decisions list JSON payload.
// The structure matches cscli's actual output: a list of alert objects,
// each with a source, optional meta, and nested decisions.
func decisionsJSON(alerts ...alertShape) json.RawMessage {
	b, _ := json.Marshal(alerts)
	return json.RawMessage(b)
}

func makeAlert(ipValue string, banValue string, hosts ...string) alertShape {
	meta := make([]metaItem, 0, len(hosts))
	for _, h := range hosts {
		meta = append(meta, metaItem{Key: "target_host", Value: h})
	}
	dec := decisionShape{Type: "ban", Value: banValue}
	return alertShape{
		Source:    map[string]any{"value": ipValue},
		Decisions: []decisionShape{dec},
		Meta:      meta,
	}
}

// TestSyncBlockedIPsConf_IsolationInvariant is the security-critical test.
//
// Setup:
//   - conn 1 (tenant 10) handles example.com
//   - conn 2 (tenant 10) handles other.com
//   - conn 3 (tenant 11) no domain match / distinct tenant
//
// Decisions:
//   - IP 1.1.1.1 → target_host=example.com → should land ONLY in conn 1
//   - IP 2.2.2.2 → target_host=other.com   → should land ONLY in conn 2
//   - IP 3.3.3.3 → no target_host          → fallback → ALL conns
//
// Assert: conn_1 has 1.1.1.1+3.3.3.3, conn_2 has 2.2.2.2+3.3.3.3,
//         conn_3 has 3.3.3.3.
// Cross-domain leak check: 1.1.1.1 must NOT appear in conn_2 or conn_3.
func TestSyncBlockedIPsConf_IsolationInvariant(t *testing.T) {
	stateDir := t.TempDir()
	tenantsBase := t.TempDir()

	// Create compose dirs for all three connections.
	dirs := map[int64]string{
		1: filepath.Join(tenantsBase, "10", "compose", "conn_1"),
		2: filepath.Join(tenantsBase, "10", "compose", "conn_2"),
		3: filepath.Join(tenantsBase, "11", "compose", "conn_3"),
	}
	for _, d := range dirs {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}

	conns := []Connection{
		{ID: 1, TenantID: 10, Name: "c1", Domain: "example.com", Enabled: true},
		{ID: 2, TenantID: 10, Name: "c2", Domain: "other.com", Enabled: true},
		{ID: 3, TenantID: 11, Name: "c3", Domain: "third.com", Enabled: true},
	}

	payload := decisionsJSON(
		makeAlert("1.1.1.1", "1.1.1.1", "example.com"),
		makeAlert("2.2.2.2", "2.2.2.2", "other.com"),
		makeAlert("3.3.3.3", "3.3.3.3"), // no meta → fallback
	)

	runner := &fakeRunner{payload: payload}
	reloader := &fakeReloader{}
	s := NewSyncerWithDirs(runner, reloader, &fakeConnSource{}, stateDir, tenantsBase)

	// Seed the connection registry.
	require.NoError(t, s.WriteConnectionsRegistry(conns))

	// Run the sync.
	require.NoError(t, s.SyncBlockedIPsConf(context.Background()))

	// Angie must be reloaded exactly once.
	require.Equal(t, 1, reloader.calls)

	// Read all three files.
	readConf := func(connID int64) string {
		p := filepath.Join(dirs[connID], "blocked_ips.conf")
		b, err := os.ReadFile(p)
		require.NoError(t, err, "blocked_ips.conf must exist for conn %d", connID)
		return string(b)
	}

	conf1 := readConf(1)
	conf2 := readConf(2)
	conf3 := readConf(3)

	// ── conn 1 ────────────────────────────────────────────────────────────────
	require.Contains(t, conf1, "deny 1.1.1.1;", "conn1 must block 1.1.1.1 (example.com target)")
	require.Contains(t, conf1, "deny 3.3.3.3;", "conn1 must block 3.3.3.3 (fallback)")

	// ── conn 2 ────────────────────────────────────────────────────────────────
	require.Contains(t, conf2, "deny 2.2.2.2;", "conn2 must block 2.2.2.2 (other.com target)")
	require.Contains(t, conf2, "deny 3.3.3.3;", "conn2 must block 3.3.3.3 (fallback)")

	// ── conn 3 ────────────────────────────────────────────────────────────────
	require.Contains(t, conf3, "deny 3.3.3.3;", "conn3 must block 3.3.3.3 (fallback)")

	// ── Cross-domain isolation (SECURITY CRITICAL) ────────────────────────────
	require.NotContains(t, conf2, "deny 1.1.1.1;",
		"ISOLATION VIOLATION: 1.1.1.1 (example.com) must NOT leak into conn2 (other.com)")
	require.NotContains(t, conf3, "deny 1.1.1.1;",
		"ISOLATION VIOLATION: 1.1.1.1 (example.com) must NOT leak into conn3")
	require.NotContains(t, conf1, "deny 2.2.2.2;",
		"ISOLATION VIOLATION: 2.2.2.2 (other.com) must NOT leak into conn1 (example.com)")
	require.NotContains(t, conf3, "deny 2.2.2.2;",
		"ISOLATION VIOLATION: 2.2.2.2 (other.com) must NOT leak into conn3")
}

// TestSyncBlockedIPsConf_ManualMappingOverridesAutomatic ensures that a manual
// mapping (IP → specific conn IDs) takes priority over target_host meta and
// global fallback — mirroring Python _resolve_ip_connections priority 1.
func TestSyncBlockedIPsConf_ManualMappingOverridesAutomatic(t *testing.T) {
	stateDir := t.TempDir()
	tenantsBase := t.TempDir()

	dirs := map[int64]string{
		1: filepath.Join(tenantsBase, "10", "compose", "conn_1"),
		2: filepath.Join(tenantsBase, "10", "compose", "conn_2"),
	}
	for _, d := range dirs {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}

	conns := []Connection{
		{ID: 1, TenantID: 10, Domain: "example.com", Enabled: true},
		{ID: 2, TenantID: 10, Domain: "other.com", Enabled: true},
	}

	// cscli reports 1.1.1.1 targeting "other.com" (would normally map to conn 2)…
	payload := decisionsJSON(makeAlert("1.1.1.1", "1.1.1.1", "other.com"))

	runner := &fakeRunner{payload: payload}
	reloader := &fakeReloader{}
	s := NewSyncerWithDirs(runner, reloader, &fakeConnSource{}, stateDir, tenantsBase)
	require.NoError(t, s.WriteConnectionsRegistry(conns))

	// …but the manual mapping says: only block on conn 1.
	require.NoError(t, s.SaveBlockedIPsMapping(map[string][]int64{"1.1.1.1": {1}}))

	require.NoError(t, s.SyncBlockedIPsConf(context.Background()))

	conf1, _ := os.ReadFile(filepath.Join(dirs[1], "blocked_ips.conf"))
	conf2, _ := os.ReadFile(filepath.Join(dirs[2], "blocked_ips.conf"))

	require.Contains(t, string(conf1), "deny 1.1.1.1;", "manual mapping → conn1 must block it")
	require.NotContains(t, string(conf2), "deny 1.1.1.1;",
		"ISOLATION VIOLATION: manual mapping overrides auto; 1.1.1.1 must NOT appear in conn2")
}

// TestSyncBlockedIPsConf_SkipsNonExistentConnDir ensures that a connection
// whose compose dir doesn't exist yet is silently skipped (not created).
func TestSyncBlockedIPsConf_SkipsNonExistentConnDir(t *testing.T) {
	stateDir := t.TempDir()
	tenantsBase := t.TempDir()

	// Only create dir for conn 1, not conn 2.
	dir1 := filepath.Join(tenantsBase, "10", "compose", "conn_1")
	require.NoError(t, os.MkdirAll(dir1, 0o755))

	conns := []Connection{
		{ID: 1, TenantID: 10, Domain: "example.com", Enabled: true},
		{ID: 2, TenantID: 10, Domain: "other.com", Enabled: true},
	}

	payload := decisionsJSON(makeAlert("1.1.1.1", "1.1.1.1")) // fallback → all conns

	s := NewSyncerWithDirs(&fakeRunner{payload: payload}, &fakeReloader{}, &fakeConnSource{}, stateDir, tenantsBase)
	require.NoError(t, s.WriteConnectionsRegistry(conns))
	require.NoError(t, s.SyncBlockedIPsConf(context.Background()))

	// conn 1 dir exists → file written.
	_, err := os.Stat(filepath.Join(dir1, "blocked_ips.conf"))
	require.NoError(t, err)

	// conn 2 dir does NOT exist → must not be created.
	dir2 := filepath.Join(tenantsBase, "10", "compose", "conn_2")
	_, err = os.Stat(dir2)
	require.True(t, os.IsNotExist(err), "conn2 dir must not be created by sync")
}

// TestSyncBlockedIPsConf_EmptyDecisions writes empty blocked_ips.conf when
// there are no active bans (header-only files).
func TestSyncBlockedIPsConf_EmptyDecisions(t *testing.T) {
	stateDir := t.TempDir()
	tenantsBase := t.TempDir()

	dir1 := filepath.Join(tenantsBase, "10", "compose", "conn_1")
	require.NoError(t, os.MkdirAll(dir1, 0o755))

	conns := []Connection{
		{ID: 1, TenantID: 10, Domain: "example.com", Enabled: true},
	}

	// cscli returns empty array.
	payload := json.RawMessage(`[]`)
	s := NewSyncerWithDirs(&fakeRunner{payload: payload}, &fakeReloader{}, &fakeConnSource{}, stateDir, tenantsBase)
	require.NoError(t, s.WriteConnectionsRegistry(conns))
	require.NoError(t, s.SyncBlockedIPsConf(context.Background()))

	b, err := os.ReadFile(filepath.Join(dir1, "blocked_ips.conf"))
	require.NoError(t, err)
	// Must start with the header, no deny lines.
	require.Contains(t, string(b), "# Auto-generated")
	require.NotContains(t, string(b), "deny ")
}

// TestSyncBlockedIPsConf_NilRunnerOutput mirrors Python behaviour when cscli
// returns nothing (e.g., container offline): sync must not panic.
func TestSyncBlockedIPsConf_NilRunnerOutput(t *testing.T) {
	stateDir := t.TempDir()
	tenantsBase := t.TempDir()

	dir1 := filepath.Join(tenantsBase, "10", "compose", "conn_1")
	require.NoError(t, os.MkdirAll(dir1, 0o755))

	conns := []Connection{
		{ID: 1, TenantID: 10, Domain: "example.com", Enabled: true},
	}

	s := NewSyncerWithDirs(&fakeRunner{payload: nil}, &fakeReloader{}, &fakeConnSource{}, stateDir, tenantsBase)
	require.NoError(t, s.WriteConnectionsRegistry(conns))
	// Should not panic or error.
	require.NoError(t, s.SyncBlockedIPsConf(context.Background()))
}

// TestWriteConnectionsRegistry_AtomicRename verifies that the file is written
// atomically (tmp file replaced).
func TestWriteConnectionsRegistry_AtomicRename(t *testing.T) {
	stateDir := t.TempDir()
	s := NewSyncerWithDirs(&fakeRunner{}, &fakeReloader{}, &fakeConnSource{}, stateDir, t.TempDir())

	conns := []Connection{
		{ID: 42, TenantID: 7, Name: "test", Domain: "test.com", Enabled: true, Status: "active"},
	}
	require.NoError(t, s.WriteConnectionsRegistry(conns))

	// tmp file must be gone.
	_, err := os.Stat(s.connectionsJSON() + ".tmp")
	require.True(t, os.IsNotExist(err))

	// Read back.
	var entries []registryEntry
	raw, _ := os.ReadFile(s.connectionsJSON())
	require.NoError(t, json.Unmarshal(raw, &entries))
	require.Len(t, entries, 1)
	require.Equal(t, int64(42), entries[0].ID)
	require.Equal(t, "test.com", entries[0].Domain)
}

// TestLoadConnectionIDs filters to enabled only.
func TestLoadConnectionIDs(t *testing.T) {
	stateDir := t.TempDir()
	s := NewSyncerWithDirs(&fakeRunner{}, &fakeReloader{}, &fakeConnSource{}, stateDir, t.TempDir())

	conns := []Connection{
		{ID: 1, TenantID: 1, Domain: "a.com", Enabled: true},
		{ID: 2, TenantID: 1, Domain: "b.com", Enabled: false},
		{ID: 3, TenantID: 1, Domain: "c.com", Enabled: true},
	}
	require.NoError(t, s.WriteConnectionsRegistry(conns))

	ids := s.loadConnectionIDs()
	require.Equal(t, []int64{1, 3}, ids)
}
