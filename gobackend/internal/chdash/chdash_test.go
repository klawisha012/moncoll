package chdash_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zwarder/waf/gobackend/internal/chdash"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// ─── Fake ConnectionSource ───────────────────────────────────────────────────

type fakeSource struct {
	conns []store.Connection
	err   error
}

func (f *fakeSource) ListConnections(_ context.Context) ([]store.Connection, error) {
	return f.conns, f.err
}

func ptr[T any](v T) *T { return &v }

// fixture connections
var (
	conn10 = store.Connection{ID: 10, TenantID: 1, Domain: "example.com", Enabled: true}
	conn11 = store.Connection{ID: 11, TenantID: 1, Domain: "blog.example.com", Enabled: true}
	conn20 = store.Connection{ID: 20, TenantID: 2, Domain: "tenant2.com", Enabled: true}
	connDis = store.Connection{ID: 30, TenantID: 1, Domain: "disabled.example.com", Enabled: false}
)

var allConns = []store.Connection{conn10, conn11, conn20, connDis}

// ─── DomainsForConnection truth-table ────────────────────────────────────────

func TestDomainsForConnection_AdminNoConn(t *testing.T) {
	// Admin (tenantID=nil) + connectionID=nil → nil (no filter, see all traffic).
	src := &fakeSource{conns: allConns}
	domains, err := chdash.DomainsForConnection(context.Background(), src, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, domains, "admin with no connection filter must return nil (no filter)")
}

func TestDomainsForConnection_AdminSpecificConn(t *testing.T) {
	// Admin (tenantID=nil) + connectionID=10 → that connection's domain regardless of tenant.
	src := &fakeSource{conns: allConns}
	domains, err := chdash.DomainsForConnection(context.Background(), src, ptr(int64(10)), nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com"}, domains)
}

func TestDomainsForConnection_AdminSpecificConn_NotFound(t *testing.T) {
	// Admin + connectionID not in DB → empty slice (not nil).
	src := &fakeSource{conns: allConns}
	domains, err := chdash.DomainsForConnection(context.Background(), src, ptr(int64(999)), nil)
	require.NoError(t, err)
	assert.NotNil(t, domains, "must return empty slice, never nil")
	assert.Empty(t, domains)
}

func TestDomainsForConnection_ClientNoConn_HasDomains(t *testing.T) {
	// Client (tenantID=1) + connectionID=nil → all enabled domains for tenant 1.
	src := &fakeSource{conns: allConns}
	domains, err := chdash.DomainsForConnection(context.Background(), src, nil, ptr(int64(1)))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"example.com", "blog.example.com"}, domains,
		"disabled connections must not appear; only enabled ones for the tenant")
}

func TestDomainsForConnection_ClientNoConn_NoDomains(t *testing.T) {
	// Client (tenantID=99, no connections) + connectionID=nil → empty slice (NOT nil).
	// SECURITY: must return []string{} not nil. nil would mean "no filter" = entire platform visible.
	src := &fakeSource{conns: allConns}
	domains, err := chdash.DomainsForConnection(context.Background(), src, nil, ptr(int64(99)))
	require.NoError(t, err)
	assert.NotNil(t, domains, "SECURITY: client with no connections must get empty slice, NOT nil")
	assert.Empty(t, domains)
}

func TestDomainsForConnection_ClientOwnConn(t *testing.T) {
	// Client (tenantID=1) + their own connectionID=10 → that connection's domain.
	src := &fakeSource{conns: allConns}
	domains, err := chdash.DomainsForConnection(context.Background(), src, ptr(int64(10)), ptr(int64(1)))
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com"}, domains)
}

func TestDomainsForConnection_ClientOtherTenantConn(t *testing.T) {
	// Client (tenantID=1) requesting another tenant's connection (connID=20 belongs to tenant 2).
	// SECURITY: must return empty slice, NOT that connection's domain.
	src := &fakeSource{conns: allConns}
	domains, err := chdash.DomainsForConnection(context.Background(), src, ptr(int64(20)), ptr(int64(1)))
	require.NoError(t, err)
	assert.NotNil(t, domains, "SECURITY: must return empty slice, NOT nil, NOT tenant2.com")
	assert.Empty(t, domains, "SECURITY: client must not see another tenant's domain")
}

func TestDomainsForConnection_ClientDisabledConn(t *testing.T) {
	// Client requesting their own but disabled connection → empty slice.
	src := &fakeSource{conns: allConns}
	domains, err := chdash.DomainsForConnection(context.Background(), src, ptr(int64(30)), ptr(int64(1)))
	require.NoError(t, err)
	assert.NotNil(t, domains)
	assert.Empty(t, domains, "disabled connection must not be returned")
}

func TestDomainsForConnection_DBError_Client(t *testing.T) {
	// DB error for a client → empty slice (fail closed), error propagated.
	src := &fakeSource{err: errors.New("db down")}
	domains, err := chdash.DomainsForConnection(context.Background(), src, nil, ptr(int64(1)))
	assert.Error(t, err)
	assert.NotNil(t, domains, "SECURITY: on DB error for client must get non-nil empty slice")
	assert.Empty(t, domains)
}

func TestDomainsForConnection_DBError_Admin(t *testing.T) {
	// DB error for an admin (tenantID=nil) with a specific conn → error, nil (fail open).
	// Matching Python: "Fail closed for clients, fail open for admins."
	src := &fakeSource{err: errors.New("db down")}
	domains, err := chdash.DomainsForConnection(context.Background(), src, ptr(int64(10)), nil)
	assert.Error(t, err)
	assert.Nil(t, domains, "admin fail-open: nil returned on DB error")
}

// ─── Security invariant: scoped caller NEVER gets nil ────────────────────────

func TestDomainsForConnection_NeverNilForClient(t *testing.T) {
	// Exhaustive check: for any non-nil tenantID, result is never nil.
	cases := []struct {
		name   string
		connID *int64
		conns  []store.Connection
	}{
		{"no_conns_in_db", nil, []store.Connection{}},
		{"wrong_tenant_conn", ptr(int64(20)), allConns},
		{"nonexistent_conn", ptr(int64(999)), allConns},
		{"disabled_own_conn", ptr(int64(30)), allConns},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeSource{conns: tc.conns}
			domains, err := chdash.DomainsForConnection(
				context.Background(), src, tc.connID, ptr(int64(1)))
			require.NoError(t, err)
			assert.NotNil(t, domains,
				"SECURITY: non-nil tenantID must NEVER yield nil domain list")
		})
	}
}

// ─── QuoteDomains ────────────────────────────────────────────────────────────

func TestQuoteDomains_Empty(t *testing.T) {
	// Empty slice → sentinel IN-list.
	assert.Equal(t, "('__none__')", chdash.QuoteDomains([]string{}))
}

func TestQuoteDomains_EmptyStrings(t *testing.T) {
	// Slice of empty strings → sentinel.
	assert.Equal(t, "('__none__')", chdash.QuoteDomains([]string{"", ""}))
}

func TestQuoteDomains_Single(t *testing.T) {
	assert.Equal(t, "('example.com')", chdash.QuoteDomains([]string{"example.com"}))
}

func TestQuoteDomains_Multi(t *testing.T) {
	assert.Equal(t, "('a.com', 'b.com')", chdash.QuoteDomains([]string{"a.com", "b.com"}))
}

func TestQuoteDomains_Sanitizes(t *testing.T) {
	// Single-quotes, backslashes, and NUL bytes must be stripped.
	assert.Equal(t, "('malicious.com')", chdash.QuoteDomains([]string{"mali'cious.com"}))
	assert.Equal(t, "('malicious.com')", chdash.QuoteDomains([]string{`mali\cious.com`}))
	assert.Equal(t, "('malicious.com')", chdash.QuoteDomains([]string{"mali\x00cious.com"}))
}

// ─── HostFilterNginx ─────────────────────────────────────────────────────────

func TestHostFilterNginx_Nil(t *testing.T) {
	// nil → "" (admin: no filter added to SQL).
	assert.Equal(t, "", chdash.HostFilterNginx(nil))
}

func TestHostFilterNginx_Empty(t *testing.T) {
	// [] → sentinel that matches nothing (column: host).
	assert.Equal(t, " AND host IN ('__none__')", chdash.HostFilterNginx([]string{}))
}

func TestHostFilterNginx_Single(t *testing.T) {
	assert.Equal(t, " AND host IN ('example.com')", chdash.HostFilterNginx([]string{"example.com"}))
}

func TestHostFilterNginx_Multi(t *testing.T) {
	assert.Equal(t, " AND host IN ('a.com', 'b.com')", chdash.HostFilterNginx([]string{"a.com", "b.com"}))
}

// ─── HostFilterWAF ───────────────────────────────────────────────────────────

func TestHostFilterWAF_Nil(t *testing.T) {
	// nil → "" (admin: no filter).
	assert.Equal(t, "", chdash.HostFilterWAF(nil))
}

func TestHostFilterWAF_Empty(t *testing.T) {
	// [] → sentinel. Column: request_headers['Host'].
	assert.Equal(t, " AND request_headers['Host'] IN ('__none__')", chdash.HostFilterWAF([]string{}))
}

func TestHostFilterWAF_Single(t *testing.T) {
	assert.Equal(t, " AND request_headers['Host'] IN ('example.com')", chdash.HostFilterWAF([]string{"example.com"}))
}

func TestHostFilterWAF_Multi(t *testing.T) {
	assert.Equal(t, " AND request_headers['Host'] IN ('a.com', 'b.com')", chdash.HostFilterWAF([]string{"a.com", "b.com"}))
}

// ─── ClampMinutes ────────────────────────────────────────────────────────────

func TestClampMinutes_Normal(t *testing.T) {
	assert.Equal(t, 1440, chdash.ClampMinutes(24.0))  // 24h = 1440m
	assert.Equal(t, 60, chdash.ClampMinutes(1.0))
	assert.Equal(t, 120, chdash.ClampMinutes(2.0))
}

func TestClampMinutes_BelowMin(t *testing.T) {
	// Below minimum hours (0.0167 ≈ 1 minute): clamps to at least 1 minute.
	assert.Equal(t, 1, chdash.ClampMinutes(0.0))
	assert.Equal(t, 1, chdash.ClampMinutes(-100.0))
	assert.Equal(t, 1, chdash.ClampMinutes(0.001))
}

func TestClampMinutes_AboveMax(t *testing.T) {
	// Above maximum (8760h = 1 year): clamps to 8760*60 = 525600 minutes.
	assert.Equal(t, 525600, chdash.ClampMinutes(9000.0))
	assert.Equal(t, 525600, chdash.ClampMinutes(1_000_000.0))
}

func TestClampMinutes_Minimum(t *testing.T) {
	// At exactly the minimum (0.0167h ≈ 1.002 minutes) → 1.
	assert.Equal(t, 1, chdash.ClampMinutes(0.0167))
}

func TestClampMinutes_Maximum(t *testing.T) {
	assert.Equal(t, 525600, chdash.ClampMinutes(8760.0))
}
