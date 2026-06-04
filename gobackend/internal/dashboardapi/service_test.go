package dashboardapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dashboardv1 "github.com/zwarder/waf/gobackend/gen/dashboard/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ─── Fakes ───────────────────────────────────────────────────────────────────

// fakeExecutor records the last SQL passed to QueryCached / Query and returns
// canned rows.
type fakeExecutor struct {
	cachedRows [][]interface{}
	queryRows  [][]interface{}
	lastCached string
	lastQuery  string
}

func (f *fakeExecutor) QueryCached(_ context.Context, sql string) ([][]interface{}, error) {
	f.lastCached = sql
	return f.cachedRows, nil
}

func (f *fakeExecutor) Query(_ context.Context, sql string) ([][]interface{}, error) {
	f.lastQuery = sql
	return f.queryRows, nil
}

// fakeDomainResolver records the (connID, tenantID) pair it was called with and
// returns canned domains.
type fakeDomainResolver struct {
	domains []string
	err     error
	// recorded call args
	gotConnID   *int64
	gotTenantID *int64
}

func (f *fakeDomainResolver) DomainsForConnection(_ context.Context, connID *int64, tenantID *int64) ([]string, error) {
	f.gotConnID = connID
	f.gotTenantID = tenantID
	return f.domains, f.err
}

func ptr[T any](v T) *T { return &v }

// ctxWithIdentity returns a context populated with an auth.Identity.
func ctxWithIdentity(tenantID *int64) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		UserID:       42,
		PlatformRole: "client",
		TenantID:     tenantID,
	})
}

func adminCtx() context.Context {
	// Admin: TenantID == nil.
	return auth.WithIdentity(context.Background(), &auth.Identity{
		UserID:       1,
		PlatformRole: "admin",
		TenantID:     nil,
	})
}

// ─── Tenant-isolation wiring tests ───────────────────────────────────────────

// TestTenantIsolation_ClientTenantIDFlowsToDomainsForConnection verifies that
// when a client identity (non-nil TenantID) is in the context, GetMetrics
// extracts it and passes it verbatim to DomainsForConnection.
func TestTenantIsolation_ClientTenantIDFlowsToDomainsForConnection(t *testing.T) {
	dr := &fakeDomainResolver{domains: []string{"client.example.com"}}
	ex := &fakeExecutor{cachedRows: [][]interface{}{{int64(0)}}}
	svc := newWithDeps(ex, dr)

	ctx := ctxWithIdentity(ptr(int64(7)))
	_, err := svc.GetMetrics(ctx, &dashboardv1.DashboardRequest{Hours: 1})
	require.NoError(t, err)

	require.NotNil(t, dr.gotTenantID, "tenantID must be passed to DomainsForConnection")
	assert.Equal(t, int64(7), *dr.gotTenantID, "tenantID must match the identity in context")
}

// TestTenantIsolation_AdminPassesNilTenantID verifies that an admin identity
// (TenantID == nil) results in nil being passed to DomainsForConnection,
// which triggers the "no filter" path (admin sees all traffic).
func TestTenantIsolation_AdminPassesNilTenantID(t *testing.T) {
	dr := &fakeDomainResolver{domains: nil}
	ex := &fakeExecutor{cachedRows: [][]interface{}{{int64(0)}}}
	svc := newWithDeps(ex, dr)

	ctx := adminCtx()
	_, err := svc.GetMetrics(ctx, &dashboardv1.DashboardRequest{Hours: 1})
	require.NoError(t, err)

	assert.Nil(t, dr.gotTenantID, "admin identity must pass nil tenantID → no SQL host filter")
}

// TestTenantIsolation_ConnectionIDFromRequest verifies that a non-nil
// connection_id in the request is forwarded to DomainsForConnection.
func TestTenantIsolation_ConnectionIDFromRequest(t *testing.T) {
	dr := &fakeDomainResolver{domains: []string{"specific.example.com"}}
	ex := &fakeExecutor{cachedRows: [][]interface{}{{int64(0)}}}
	svc := newWithDeps(ex, dr)

	ctx := ctxWithIdentity(ptr(int64(3)))
	_, err := svc.GetMetrics(ctx, &dashboardv1.DashboardRequest{
		Hours:        1,
		ConnectionId: wrapperspb.Int64(99),
	})
	require.NoError(t, err)

	require.NotNil(t, dr.gotConnID, "connection_id must be forwarded to DomainsForConnection")
	assert.Equal(t, int64(99), *dr.gotConnID)
	assert.Equal(t, int64(3), *dr.gotTenantID)
}

// TestTenantIsolation_NoConnectionID verifies that nil connection_id in the
// request results in nil being passed to DomainsForConnection (tenant-aggregate mode).
func TestTenantIsolation_NoConnectionID(t *testing.T) {
	dr := &fakeDomainResolver{domains: []string{"a.com", "b.com"}}
	ex := &fakeExecutor{cachedRows: [][]interface{}{{int64(5)}}}
	svc := newWithDeps(ex, dr)

	ctx := ctxWithIdentity(ptr(int64(2)))
	_, err := svc.GetTopRules(ctx, &dashboardv1.DashboardRequest{Hours: 24})
	require.NoError(t, err)

	assert.Nil(t, dr.gotConnID, "absent connection_id must forward nil to DomainsForConnection")
}

// ─── Row-mapping tests ────────────────────────────────────────────────────────

// TestGetMetrics_RowMapping verifies that scalar rows are mapped correctly to
// the MetricsResponse proto fields.
func TestGetMetrics_RowMapping(t *testing.T) {
	// Queries in order: total, prev_total, blocked, high_sev, active_rules, error_responses.
	callCount := 0
	responses := [][][]interface{}{
		{{int64(1000)}}, // total_requests
		{{int64(500)}},  // prev_total → change = (1000-500)/500*100 = 100%
		{{int64(42)}},   // blocked_threats
		{{int64(10)}},   // high_severity
		{{int64(7)}},    // active_rules
		{{int64(5)}},    // error_responses → health = (1000-5)/1000*100 = 99.5%
	}

	ex := &fakeExecutor{}
	dr := &fakeDomainResolver{domains: nil}

	// We need a custom executor that cycles through responses.
	mex := &multiCallExecutor{responses: responses, callPtr: &callCount}
	svc := newWithDeps(mex, dr)

	resp, err := svc.GetMetrics(adminCtx(), &dashboardv1.DashboardRequest{Hours: 24})
	require.NoError(t, err)
	_ = ex // suppress lint

	assert.Equal(t, int64(1000), resp.GetTotalRequests())
	assert.Equal(t, 100.0, resp.GetTotalRequestsChange())
	assert.Equal(t, int64(42), resp.GetBlockedThreats())
	assert.Equal(t, int64(10), resp.GetHighSeverityCount())
	assert.Equal(t, int64(7), resp.GetActiveRules())
	assert.InDelta(t, 99.5, resp.GetSystemHealth(), 0.01)
	assert.Equal(t, 0.0, resp.GetAvgLatencyMs())
}

// TestGetTopRules_RowMapping verifies rule rows are mapped to RuleHit protos.
func TestGetTopRules_RowMapping(t *testing.T) {
	cannedRows := [][]interface{}{
		{"942100", int64(500)},
		{"", int64(200)}, // empty ruleId → "unknown"
	}
	ex := &fakeExecutor{cachedRows: cannedRows}
	dr := &fakeDomainResolver{domains: nil}
	svc := newWithDeps(ex, dr)

	resp, err := svc.GetTopRules(adminCtx(), &dashboardv1.DashboardRequest{Hours: 24})
	require.NoError(t, err)

	require.Len(t, resp.GetRules(), 2)
	assert.Equal(t, "942100", resp.GetRules()[0].GetRule())
	assert.Equal(t, int64(500), resp.GetRules()[0].GetHits())
	assert.Equal(t, "unknown", resp.GetRules()[1].GetRule())
	assert.Equal(t, int64(200), resp.GetRules()[1].GetHits())
}

// TestGetEvents_RowMapping verifies security event rows are mapped correctly,
// including severity label translation and fallback values.
func TestGetEvents_RowMapping(t *testing.T) {
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	cannedRows := [][]interface{}{
		{ts, "942100", "1.2.3.4", int64(2), "/login", "SQL injection"},
		{ts, "", "", int64(0), "", ""},  // empty fields → defaults
	}
	ex := &fakeExecutor{cachedRows: cannedRows}
	dr := &fakeDomainResolver{domains: []string{"example.com"}}
	svc := newWithDeps(ex, dr)

	ctx := ctxWithIdentity(ptr(int64(5)))
	resp, err := svc.GetEvents(ctx, &dashboardv1.EventsRequest{Hours: 24})
	require.NoError(t, err)

	require.Len(t, resp.GetEvents(), 2)

	ev0 := resp.GetEvents()[0]
	assert.Equal(t, "942100", ev0.GetType())
	assert.Equal(t, "1.2.3.4", ev0.GetIp())
	assert.Equal(t, "medium", ev0.GetSeverity()) // severity 2 → "medium"
	assert.Equal(t, "/login", ev0.GetPath())

	ev1 := resp.GetEvents()[1]
	assert.Equal(t, "unknown", ev1.GetType())    // empty ruleId → "unknown"
	assert.Equal(t, "0.0.0.0", ev1.GetIp())      // empty ip → "0.0.0.0"
	assert.Equal(t, "info", ev1.GetSeverity())   // severity 0 → "info"
}

// TestGetTraffic_MergeTimestamps verifies that timestamps from both nginx and
// WAF logs are merged and malicious/clean counts are computed correctly.
func TestGetTraffic_MergeTimestamps(t *testing.T) {
	t1 := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 1, 15, 11, 0, 0, 0, time.UTC)

	nginxRows := [][]interface{}{
		{t1, int64(100)},
		{t2, int64(50)},
	}
	wafRows := [][]interface{}{
		{t1, int64(20)},
		// t2 not in WAF → malicious=0 for t2
	}

	// The executor needs to return different data for first vs second call.
	mex := &trafficExecutor{nginxRows: nginxRows, wafRows: wafRows}
	dr := &fakeDomainResolver{domains: nil}
	svc := newWithDeps(mex, dr)

	resp, err := svc.GetTraffic(adminCtx(), &dashboardv1.DashboardRequest{Hours: 24})
	require.NoError(t, err)

	points := resp.GetPoints()
	require.Len(t, points, 2)

	// t1: total=100, malicious=20, clean=80
	assert.Equal(t, int64(80), points[0].GetClean())
	assert.Equal(t, int64(20), points[0].GetMalicious())

	// t2: total=50, malicious=0, clean=50
	assert.Equal(t, int64(50), points[1].GetClean())
	assert.Equal(t, int64(0), points[1].GetMalicious())
}

// TestGetTestTraffic_UsesQueryNotQueryCached verifies that GetTestTraffic calls
// Query (bypass cache) rather than QueryCached.
func TestGetTestTraffic_UsesQueryNotQueryCached(t *testing.T) {
	ex := &fakeExecutor{queryRows: nil}
	dr := &fakeDomainResolver{domains: nil}
	svc := newWithDeps(ex, dr)

	_, err := svc.GetTestTraffic(adminCtx(), &dashboardv1.TestTrafficRequest{Marker: "test-uuid"})
	require.NoError(t, err)

	assert.NotEmpty(t, ex.lastQuery, "GetTestTraffic must call Query (not QueryCached)")
	assert.Empty(t, ex.lastCached, "GetTestTraffic must NOT call QueryCached")
	assert.Contains(t, ex.lastQuery, "test-uuid", "marker must appear in the SQL")
	assert.Contains(t, ex.lastQuery, testMarkerHeader, "test marker header must appear in SQL")
}

// TestGetTestTraffic_MarkerSanitized verifies that dangerous characters in the
// marker are stripped before being embedded in the SQL.
func TestGetTestTraffic_MarkerSanitized(t *testing.T) {
	ex := &fakeExecutor{queryRows: nil}
	dr := &fakeDomainResolver{domains: nil}
	svc := newWithDeps(ex, dr)

	_, err := svc.GetTestTraffic(adminCtx(), &dashboardv1.TestTrafficRequest{
		Marker: "abc'def\\ghi\x00jkl",
	})
	require.NoError(t, err)
	// The SQL should not contain single quotes, backslashes, or NUL bytes from the marker.
	assert.NotContains(t, ex.lastQuery, "'def")
	assert.NotContains(t, ex.lastQuery, "\\ghi")
}

// TestGetSeverityDistribution_RowMapping verifies severity name translation.
func TestGetSeverityDistribution_RowMapping(t *testing.T) {
	cannedRows := [][]interface{}{
		{int64(0), int64(5)},  // EMERGENCY
		{int64(2), int64(10)}, // CRITICAL
		{int64(6), int64(3)},  // INFO
	}
	ex := &fakeExecutor{cachedRows: cannedRows}
	dr := &fakeDomainResolver{domains: nil}
	svc := newWithDeps(ex, dr)

	resp, err := svc.GetSeverityDistribution(adminCtx(), &dashboardv1.DashboardRequest{Hours: 1})
	require.NoError(t, err)

	slices := resp.GetSlices()
	require.Len(t, slices, 3)
	assert.Equal(t, "EMERGENCY", slices[0].GetSeverity())
	assert.Equal(t, int64(5), slices[0].GetHits())
	assert.Equal(t, "CRITICAL", slices[1].GetSeverity())
	assert.Equal(t, "INFO", slices[2].GetSeverity())
}

// TestGetGeoipUnresolved_RowMapping checks IP strings and hit counts.
func TestGetGeoipUnresolved_RowMapping(t *testing.T) {
	cannedRows := [][]interface{}{
		{"8.8.8.8", int64(42)},
		{"1.1.1.1", int64(7)},
	}
	ex := &fakeExecutor{cachedRows: cannedRows}
	dr := &fakeDomainResolver{domains: []string{"example.com"}}
	svc := newWithDeps(ex, dr)

	resp, err := svc.GetGeoipUnresolved(ctxWithIdentity(ptr(int64(1))), &dashboardv1.DashboardRequest{Hours: 24})
	require.NoError(t, err)

	ips := resp.GetIps()
	require.Len(t, ips, 2)
	assert.Equal(t, "8.8.8.8", ips[0].GetIp())
	assert.Equal(t, int64(42), ips[0].GetHits())
}

// ─── SQL content tests ────────────────────────────────────────────────────────

// TestGetMetrics_SQLContainsHostFilter verifies that when DomainsForConnection
// returns domains, the host filter appears in the SQL.
func TestGetMetrics_SQLContainsHostFilter(t *testing.T) {
	dr := &fakeDomainResolver{domains: []string{"secure.example.com"}}
	// 6 queries, each returns a scalar 0 row.
	mex := &nCallExecutor{resp: [][]interface{}{{int64(0)}}, n: 6}
	svc := newWithDeps(mex, dr)

	ctx := ctxWithIdentity(ptr(int64(1)))
	_, err := svc.GetMetrics(ctx, &dashboardv1.DashboardRequest{Hours: 24})
	require.NoError(t, err)

	// Every SQL observed must contain either host IN or request_headers filter.
	for _, sql := range mex.seen {
		hasNginxFilter := strings.Contains(sql, "host IN ('secure.example.com')")
		hasWAFFilter := strings.Contains(sql, "request_headers['Host'] IN ('secure.example.com')")
		assert.True(t, hasNginxFilter || hasWAFFilter,
			"SQL must contain a tenant host filter: %s", sql)
	}
}

// TestGetMetrics_EmptyDomainsProduceSentinel verifies that when
// DomainsForConnection returns an empty slice, the SQL uses the sentinel value
// ('__none__') that matches nothing — preventing data leakage.
func TestGetMetrics_EmptyDomainsProduceSentinel(t *testing.T) {
	// Client with zero connections → empty domains.
	dr := &fakeDomainResolver{domains: []string{}}
	mex := &nCallExecutor{resp: [][]interface{}{{int64(0)}}, n: 6}
	svc := newWithDeps(mex, dr)

	ctx := ctxWithIdentity(ptr(int64(99)))
	_, err := svc.GetMetrics(ctx, &dashboardv1.DashboardRequest{Hours: 24})
	require.NoError(t, err)

	for _, sql := range mex.seen {
		assert.Contains(t, sql, "__none__",
			"empty domain list must produce sentinel IN ('__none__') to match nothing: %s", sql)
	}
}

// ─── Helper executors ─────────────────────────────────────────────────────────

// multiCallExecutor returns a different canned response per call (in order).
type multiCallExecutor struct {
	responses [][][]interface{}
	callPtr   *int
}

func (m *multiCallExecutor) QueryCached(_ context.Context, _ string) ([][]interface{}, error) {
	if *m.callPtr >= len(m.responses) {
		return [][]interface{}{{int64(0)}}, nil
	}
	r := m.responses[*m.callPtr]
	*m.callPtr++
	return r, nil
}

func (m *multiCallExecutor) Query(_ context.Context, _ string) ([][]interface{}, error) {
	return nil, nil
}

// trafficExecutor returns nginx rows on first QueryCached call, WAF rows on second.
type trafficExecutor struct {
	nginxRows [][]interface{}
	wafRows   [][]interface{}
	call      int
}

func (t *trafficExecutor) QueryCached(_ context.Context, _ string) ([][]interface{}, error) {
	t.call++
	if t.call == 1 {
		return t.nginxRows, nil
	}
	return t.wafRows, nil
}

func (t *trafficExecutor) Query(_ context.Context, _ string) ([][]interface{}, error) {
	return nil, nil
}

// nCallExecutor returns the same resp for up to n QueryCached calls, recording
// each SQL seen.
type nCallExecutor struct {
	resp [][]interface{}
	n    int
	seen []string
}

func (e *nCallExecutor) QueryCached(_ context.Context, sql string) ([][]interface{}, error) {
	e.seen = append(e.seen, sql)
	return e.resp, nil
}

func (e *nCallExecutor) Query(_ context.Context, _ string) ([][]interface{}, error) {
	return nil, nil
}
