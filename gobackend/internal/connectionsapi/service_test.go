package connectionsapi

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	connectionsv1 "github.com/zwarder/waf/gobackend/gen/connections/v1"
	"github.com/zwarder/waf/gobackend/internal/angiecfg"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/certs"
	"github.com/zwarder/waf/gobackend/internal/conndns"
	"github.com/zwarder/waf/gobackend/internal/edge"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// ── Fakes ─────────────────────────────────────────────────────────────────────

// fakeStore is a minimal in-memory store fake.
type fakeStore struct {
	conns        map[int64]*store.Connection
	nextID       int64
	createErr    error // if set, CreateConnection returns this
	verifiedZone bool  // if set, TenantHasVerifiedZone returns true
}

func newFakeStore() *fakeStore {
	return &fakeStore{conns: make(map[int64]*store.Connection), nextID: 1}
}

func (f *fakeStore) addConn(c *store.Connection) {
	c.ID = f.nextID
	f.nextID++
	cp := *c
	f.conns[cp.ID] = &cp
}

func (f *fakeStore) ListConnectionsFull(_ context.Context, tenantID int64) ([]store.Connection, error) {
	var out []store.Connection
	for _, c := range f.conns {
		if c.TenantID == tenantID {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (f *fakeStore) GetConnectionFull(_ context.Context, tenantID, connID int64) (*store.Connection, error) {
	c, ok := f.conns[connID]
	if !ok || c.TenantID != tenantID {
		return nil, &store.NotFoundError{Entity: "connection"}
	}
	cp := *c
	return &cp, nil
}

func (f *fakeStore) GetConnectionInternal(_ context.Context, connID int64) (*store.Connection, error) {
	c, ok := f.conns[connID]
	if !ok {
		return nil, &store.NotFoundError{Entity: "connection"}
	}
	cp := *c
	return &cp, nil
}

func (f *fakeStore) CreateConnection(_ context.Context, c *store.Connection) (*store.Connection, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	cp := *c
	cp.ID = f.nextID
	f.nextID++
	cp.CreatedAt = time.Now().UTC()
	cp.UpdatedAt = time.Now().UTC()
	f.conns[cp.ID] = &cp
	return &cp, nil
}

func (f *fakeStore) UpdateConnection(_ context.Context, tenantID, connID int64, upd store.ConnectionUpdate) (*store.Connection, error) {
	c, ok := f.conns[connID]
	if !ok || c.TenantID != tenantID {
		return nil, &store.NotFoundError{Entity: "connection"}
	}
	if upd.Name != nil {
		c.Name = *upd.Name
	}
	if upd.OriginHosts != nil {
		c.OriginHosts = upd.OriginHosts
	}
	if upd.Enabled != nil {
		c.Enabled = *upd.Enabled
	}
	if upd.OriginPort != nil {
		c.OriginPort = *upd.OriginPort
	}
	if upd.OriginTLSMode != nil {
		c.OriginTLSMode = *upd.OriginTLSMode
	}
	if upd.HTTPVersions != nil {
		c.HTTPVersions = *upd.HTTPVersions
	}
	if upd.CompressionAlgo != nil {
		c.CompressionAlgo = *upd.CompressionAlgo
	}
	cp := *c
	return &cp, nil
}

func (f *fakeStore) DeleteConnection(_ context.Context, tenantID, connID int64) error {
	c, ok := f.conns[connID]
	if !ok || c.TenantID != tenantID {
		return &store.NotFoundError{Entity: "connection"}
	}
	delete(f.conns, connID)
	return nil
}

func (f *fakeStore) UpdateSecurity(_ context.Context, tenantID, connID int64, modsecState string, geoipDenied []string, crowdsecActive bool, ddosProtection bool) (*store.Connection, error) {
	c, ok := f.conns[connID]
	if !ok || c.TenantID != tenantID {
		return nil, &store.NotFoundError{Entity: "connection"}
	}
	c.ModsecState = modsecState
	c.GeoipDeniedCountries = geoipDenied
	c.CrowdsecActive = crowdsecActive
	c.DdosProtection = ddosProtection
	cp := *c
	return &cp, nil
}

func (f *fakeStore) UpdateProbeState(_ context.Context, tenantID, connID int64, p store.PollerState) (*store.Connection, error) {
	c, ok := f.conns[connID]
	if !ok || c.TenantID != tenantID {
		return nil, &store.NotFoundError{Entity: "connection"}
	}
	c.Status = p.Status
	c.StatusDetail = p.StatusDetail
	c.VerifiedAt = p.VerifiedAt
	c.AcmeNextRetryAt = p.AcmeNextRetryAt
	c.NextPollAt = p.NextPollAt
	c.DNSTTLSeconds = p.DNSTTLSeconds
	c.LastCheckedAt = p.LastCheckedAt
	cp := *c
	return &cp, nil
}

func (f *fakeStore) ListConnectionsForPoll(_ context.Context) ([]store.Connection, error) {
	var out []store.Connection
	now := time.Now().UTC()
	for _, c := range f.conns {
		if !c.Enabled {
			continue
		}
		active := c.Status == "pending_verification" || c.Status == "pending_dns" ||
			c.Status == "provisioning_cert" || c.Status == "error"
		if !active {
			continue
		}
		if c.NextPollAt == nil || c.NextPollAt.Before(now) || c.NextPollAt.Equal(now) {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (f *fakeStore) UpdatePollerState(_ context.Context, connID int64, p store.PollerState) (*store.Connection, error) {
	c, ok := f.conns[connID]
	if !ok {
		return nil, &store.NotFoundError{Entity: "connection"}
	}
	c.Status = p.Status
	c.StatusDetail = p.StatusDetail
	c.VerifiedAt = p.VerifiedAt
	c.AcmeRetryCount = p.AcmeRetryCount
	c.AcmeNextRetryAt = p.AcmeNextRetryAt
	c.NextPollAt = p.NextPollAt
	c.DNSTTLSeconds = p.DNSTTLSeconds
	c.LastCheckedAt = p.LastCheckedAt
	if p.SSLCertPath != nil {
		c.SSLCertPath = p.SSLCertPath
	}
	if p.SSLKeyPath != nil {
		c.SSLKeyPath = p.SSLKeyPath
	}
	cp := *c
	return &cp, nil
}

func (f *fakeStore) TenantHasVerifiedZone(_ context.Context, _ int64, _ string) (bool, error) {
	return f.verifiedZone, nil
}

func (f *fakeStore) GetTenantByID(_ context.Context, id int64) (*store.Tenant, error) {
	return &store.Tenant{ID: id, Name: "acme"}, nil
}

// fakeResolver is a fake conndns.Resolver.
type fakeResolver struct {
	txtRecords map[string][]string
	hosts      map[string][]string
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		txtRecords: make(map[string][]string),
		hosts:      make(map[string][]string),
	}
}

func (r *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return r.txtRecords[name], nil
}

func (r *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return r.hosts[host], nil
}

// fakeCfgWriter records Write/Delete calls.
type fakeCfgWriter struct {
	written  []angiecfg.ConnConfig
	deleted  []int64
	writeErr error
}

func (f *fakeCfgWriter) Write(_ string, cfg angiecfg.ConnConfig) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.written = append(f.written, cfg)
	return nil
}

func (f *fakeCfgWriter) Delete(_ string, connID int64) error {
	f.deleted = append(f.deleted, connID)
	return nil
}

// fakeCertManager records ACME calls and returns configurable results.
type fakeCertManager struct {
	acmeCalls        []int64
	acmeResult       certs.Result
	selfSignedCalls  []int64
	selfSignedResult certs.Result
}

func (f *fakeCertManager) TriggerACME(connID int64, _ []string, _ *int64) certs.Result {
	f.acmeCalls = append(f.acmeCalls, connID)
	return f.acmeResult
}

func (f *fakeCertManager) GenerateSelfSigned(connID int64, _ []string, _ *int64) (certs.Result, error) {
	f.selfSignedCalls = append(f.selfSignedCalls, connID)
	return f.selfSignedResult, nil
}

// fakeReloader records reload calls.
type fakeReloader struct {
	reloadCount int
}

func (f *fakeReloader) Reload(_ context.Context) {
	f.reloadCount++
}

// fakeEdge is a fake edge.Resolver.
type fakeEdge struct{ t edge.Targets }

func (f fakeEdge) Resolve(context.Context) edge.Targets { return f.t }

// ── Test helpers ──────────────────────────────────────────────────────────────

func tenantCtx(tenantID int64) context.Context {
	tid := tenantID
	id := &auth.Identity{UserID: 1, PlatformRole: "user", TenantID: &tid}
	return auth.WithIdentity(context.Background(), id)
}

func noTenantCtx() context.Context {
	id := &auth.Identity{UserID: 1, PlatformRole: "admin", TenantID: nil}
	return auth.WithIdentity(context.Background(), id)
}

func buildService(st *fakeStore, res *fakeResolver, cfg *fakeCfgWriter, certsM *fakeCertManager, rel *fakeReloader) *Service {
	return New(st, conndns.NewVerifier(res), fakeEdge{}, cfg, certsM, rel, slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

func buildServiceWithEdge(st *fakeStore, res *fakeResolver, cfg *fakeCfgWriter, certsM *fakeCertManager, rel *fakeReloader, e fakeEdge) *Service {
	return New(st, conndns.NewVerifier(res), e, cfg, certsM, rel, slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

func sampleConn(tenantID int64) store.Connection {
	now := time.Now().UTC()
	sd := "test detail"
	return store.Connection{
		TenantID:             tenantID,
		Name:                 "test",
		Domain:               "example.com",
		OriginHosts:          []string{"1.2.3.4"},
		OriginPort:           443,
		OriginTLSMode:        "strict",
		VerifyToken:          "tok123",
		Status:               "pending_verification",
		StatusDetail:         &sd,
		DNSTTLSeconds:        60,
		HTTPVersions:         "h1,h2",
		CompressionAlgo:      "auto",
		Enabled:              true,
		ModsecState:          "detection_only",
		GeoipDeniedCountries: []string{},
		CrowdsecActive:       true,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestCreateConnection_DuplicateDomain verifies that a duplicate domain
// (store ConflictError) → codes.AlreadyExists.
func TestCreateConnection_DuplicateDomain(t *testing.T) {
	st := newFakeStore()
	st.createErr = &store.ConflictError{Detail: `domain "example.com" is already onboarded`}

	res := newFakeResolver()
	cfg := &fakeCfgWriter{}
	certsM := &fakeCertManager{}
	rel := &fakeReloader{}
	svc := buildService(st, res, cfg, certsM, rel)

	ctx := tenantCtx(1)
	_, err := svc.CreateConnection(ctx, &connectionsv1.CreateConnectionRequest{
		Name:   "test",
		Domain: "example.com",
	})
	require.Error(t, err)
	st2 := status.Convert(err)
	assert.Equal(t, codes.AlreadyExists, st2.Code())
	assert.Contains(t, st2.Message(), "already onboarded")
}

// TestCreateConnection_Success verifies that a successful create writes config,
// triggers reload, and returns the correct verify instructions.
func TestCreateConnection_Success(t *testing.T) {
	st := newFakeStore()
	res := newFakeResolver()
	cfg := &fakeCfgWriter{}
	certsM := &fakeCertManager{}
	rel := &fakeReloader{}
	svc := buildService(st, res, cfg, certsM, rel)

	ctx := tenantCtx(10)
	resp, err := svc.CreateConnection(ctx, &connectionsv1.CreateConnectionRequest{
		Name:   "my-conn",
		Domain: "test.example.com",
	})
	require.NoError(t, err)

	// Verify instructions
	require.NotNil(t, resp.Instructions)
	assert.Equal(t, "_waf-verify.test.example.com", resp.Instructions.TxtRecordName)
	assert.NotEmpty(t, resp.Instructions.TxtRecordValue)

	// Config was written
	assert.Len(t, cfg.written, 1)
	assert.Equal(t, "test.example.com", cfg.written[0].Domain)

	// Reload triggered
	assert.Equal(t, 1, rel.reloadCount)

	// Connection is returned with pending_verification status
	require.NotNil(t, resp.Connection)
	assert.Equal(t, "pending_verification", resp.Connection.Status)
	assert.Equal(t, int64(10), resp.Connection.TenantId)
}

// TestGetConnection_CrossTenant verifies that fetching a connection with a
// wrong tenant → codes.NotFound (no existence leak).
func TestGetConnection_CrossTenant(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(99) // belongs to tenant 99
	st.addConn(&conn)

	res := newFakeResolver()
	svc := buildService(st, res, &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{})

	// Caller is tenant 1, not 99
	ctx := tenantCtx(1)
	_, err := svc.GetConnection(ctx, &connectionsv1.GetConnectionRequest{Id: conn.ID})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestDeleteConnection_CrossTenant verifies tenant isolation on delete.
func TestDeleteConnection_CrossTenant(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(99)
	st.addConn(&conn)

	svc := buildService(st, newFakeResolver(), &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{})

	ctx := tenantCtx(1)
	_, err := svc.DeleteConnection(ctx, &connectionsv1.DeleteConnectionRequest{Id: conn.ID})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestUpdateConnection_CrossTenant verifies tenant isolation on update.
func TestUpdateConnection_CrossTenant(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(99)
	st.addConn(&conn)

	svc := buildService(st, newFakeResolver(), &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{})

	ctx := tenantCtx(1)
	newName := "changed"
	_, err := svc.UpdateConnection(ctx, &connectionsv1.UpdateConnectionRequest{
		Id:   conn.ID,
		Name: &wrapperspb.StringValue{Value: newName},
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestProbeConnection_TXTVerified_NoACME verifies that when DNS returns the
// TXT token, the status flips to pending_dns but ACME is NOT triggered
// (ACME happens on provisioning_cert, not pending_dns).
func TestProbeConnection_TXTVerified_NoACME(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(5)
	conn.Status = "pending_verification"
	conn.VerifyToken = "mytok"
	st.addConn(&conn)

	res := newFakeResolver()
	// DNS returns the TXT token
	res.txtRecords["_waf-verify.example.com"] = []string{"mytok"}

	certsM := &fakeCertManager{}
	rel := &fakeReloader{}
	svc := buildService(st, res, &fakeCfgWriter{}, certsM, rel)

	ctx := tenantCtx(5)
	resp, err := svc.ProbeConnection(ctx, &connectionsv1.ProbeConnectionRequest{Id: conn.ID})
	require.NoError(t, err)

	// Status flipped to pending_dns
	assert.Equal(t, "pending_dns", resp.Status)
	// ACME NOT triggered
	assert.Empty(t, certsM.acmeCalls)
}

// TestProbeConnection_TXTNotYet verifies that when TXT is absent,
// status stays pending_verification with a clear message.
func TestProbeConnection_TXTNotYet(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(5)
	conn.Status = "pending_verification"
	conn.VerifyToken = "mytok"
	st.addConn(&conn)

	res := newFakeResolver() // empty DNS — TXT not found
	svc := buildService(st, res, &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{})

	ctx := tenantCtx(5)
	resp, err := svc.ProbeConnection(ctx, &connectionsv1.ProbeConnectionRequest{Id: conn.ID})
	require.NoError(t, err)

	assert.Equal(t, "pending_verification", resp.Status)
	assert.Contains(t, resp.StatusDetail, "TXT record not found")
}

// TestProbeConnection_DNSFlipped_TriggerACME verifies the full pending_dns →
// provisioning_cert path: when A record points to the edge, ACME is NOT
// directly triggered from probe (the probe flips to provisioning_cert and
// the poller runs ACME). The status should flip to provisioning_cert.
func TestProbeConnection_DNSFlipped_TriggerACME(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(5)
	conn.Status = "pending_dns"
	st.addConn(&conn)

	res := newFakeResolver()
	res.hosts["example.com"] = []string{"1.2.3.4"} // points to edge

	certsM := &fakeCertManager{}
	rel := &fakeReloader{}
	cfg := &fakeCfgWriter{}
	edgeR := fakeEdge{t: edge.Targets{IPs: []string{"1.2.3.4"}}}
	svc := buildServiceWithEdge(st, res, cfg, certsM, rel, edgeR)

	ctx := tenantCtx(5)
	resp, err := svc.ProbeConnection(ctx, &connectionsv1.ProbeConnectionRequest{Id: conn.ID})
	require.NoError(t, err)

	// Probe flips to provisioning_cert; ACME runs on the next poller tick
	assert.Equal(t, "provisioning_cert", resp.Status)
	// Config rewritten (status changed)
	assert.NotEmpty(t, cfg.written)
	assert.Equal(t, 1, rel.reloadCount)
}

// TestProbeConnection_CrossTenant verifies tenant isolation on probe.
func TestProbeConnection_CrossTenant(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(99)
	st.addConn(&conn)

	svc := buildService(st, newFakeResolver(), &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{})

	ctx := tenantCtx(1)
	_, err := svc.ProbeConnection(ctx, &connectionsv1.ProbeConnectionRequest{Id: conn.ID})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestUpdateConnectionSecurity_Success verifies that security update re-renders
// config with the new modsec_state / geoip list.
func TestUpdateConnectionSecurity_Success(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(7)
	conn.Enabled = true
	st.addConn(&conn)

	cfg := &fakeCfgWriter{}
	rel := &fakeReloader{}
	svc := buildService(st, newFakeResolver(), cfg, &fakeCertManager{}, rel)

	ctx := tenantCtx(7)
	resp, err := svc.UpdateConnectionSecurity(ctx, &connectionsv1.UpdateConnectionSecurityRequest{
		Id:                   conn.ID,
		ModsecState:          "blocking",
		GeoipDeniedCountries: []string{"RU", "CN"},
		CrowdsecActive:       false,
	})
	require.NoError(t, err)

	assert.Equal(t, "blocking", resp.ModsecState)
	assert.Equal(t, []string{"RU", "CN"}, resp.GeoipDeniedCountries)
	assert.False(t, resp.CrowdsecActive)

	// Config was rewritten with new settings
	require.NotEmpty(t, cfg.written)
	assert.Equal(t, "blocking", cfg.written[len(cfg.written)-1].ModsecState)

	// Reload triggered
	assert.Equal(t, 1, rel.reloadCount)
}

// TestUpdateConnectionSecurity_PersistsDdosProtection verifies the ddos_protection
// flag round-trips: it defaults off, flips on via UpdateConnectionSecurity (and is
// reflected in the rendered ConnConfig), and reads back on via GetConnectionSecurity.
func TestUpdateConnectionSecurity_PersistsDdosProtection(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(7)
	conn.Enabled = true
	st.addConn(&conn)

	cfg := &fakeCfgWriter{}
	rel := &fakeReloader{}
	svc := buildService(st, newFakeResolver(), cfg, &fakeCertManager{}, rel)

	ctx := tenantCtx(7)

	// Defaults off before any update.
	before, err := svc.GetConnectionSecurity(ctx, &connectionsv1.GetConnectionSecurityRequest{Id: conn.ID})
	require.NoError(t, err)
	assert.False(t, before.DdosProtection)

	// Turn it on.
	resp, err := svc.UpdateConnectionSecurity(ctx, &connectionsv1.UpdateConnectionSecurityRequest{
		Id:             conn.ID,
		ModsecState:    "blocking",
		CrowdsecActive: true,
		DdosProtection: true,
	})
	require.NoError(t, err)
	assert.True(t, resp.DdosProtection)

	// The rendered ConnConfig carries the flag so angiecfg emits limit_req/limit_conn.
	require.NotEmpty(t, cfg.written)
	assert.True(t, cfg.written[len(cfg.written)-1].DdosProtection)

	// And it reads back on.
	got, err := svc.GetConnectionSecurity(ctx, &connectionsv1.GetConnectionSecurityRequest{Id: conn.ID})
	require.NoError(t, err)
	assert.True(t, got.DdosProtection)
}

// TestUpdateConnectionSecurity_CrossTenant verifies tenant isolation.
func TestUpdateConnectionSecurity_CrossTenant(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(99)
	st.addConn(&conn)

	svc := buildService(st, newFakeResolver(), &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{})

	ctx := tenantCtx(1)
	_, err := svc.UpdateConnectionSecurity(ctx, &connectionsv1.UpdateConnectionSecurityRequest{
		Id:          conn.ID,
		ModsecState: "blocking",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestNoTenant_PermissionDenied verifies that requests without a tenant →
// codes.PermissionDenied.
func TestNoTenant_PermissionDenied(t *testing.T) {
	svc := buildService(newFakeStore(), newFakeResolver(), &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{})
	ctx := noTenantCtx()

	_, err := svc.ListConnections(ctx, &connectionsv1.ListConnectionsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestCreateConnection_InvalidDomain verifies that malformed domain → codes.InvalidArgument.
func TestCreateConnection_InvalidDomain(t *testing.T) {
	svc := buildService(newFakeStore(), newFakeResolver(), &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{})
	ctx := tenantCtx(1)

	_, err := svc.CreateConnection(ctx, &connectionsv1.CreateConnectionRequest{
		Name:   "bad",
		Domain: "not a domain!!",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestGetEdgeInfo_ReturnsIPv4 verifies GetEdgeInfo returns EdgeIpv4 when resolver
// has IPs but no BaseHostname.
func TestGetEdgeInfo_ReturnsIPv4(t *testing.T) {
	edgeR := fakeEdge{t: edge.Targets{IPs: []string{"5.5.5.5"}}}
	svc := buildServiceWithEdge(newFakeStore(), newFakeResolver(), &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{}, edgeR)
	ctx := tenantCtx(1)
	resp, err := svc.GetEdgeInfo(ctx, &connectionsv1.EdgeInfoRequest{})
	require.NoError(t, err)
	assert.Equal(t, "5.5.5.5", resp.EdgeIpv4)
	assert.Empty(t, resp.EdgeHostname)
}

// ── Poller tests ──────────────────────────────────────────────────────────────

// TestPoller_TXTVerified verifies pending_verification → pending_dns transition.
func TestPoller_TXTVerified(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(1)
	conn.Status = "pending_verification"
	conn.VerifyToken = "secrettok"
	st.addConn(&conn)

	res := newFakeResolver()
	res.txtRecords["_waf-verify.example.com"] = []string{"secrettok"}

	cfg := &fakeCfgWriter{}
	certsM := &fakeCertManager{}
	rel := &fakeReloader{}
	p := newTestPoller(st, res, cfg, certsM, rel)

	count, err := p.tickOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Status should be pending_dns in store
	stored := st.conns[conn.ID]
	assert.Equal(t, "pending_dns", stored.Status)
	// Config rewritten
	assert.NotEmpty(t, cfg.written)
}

// TestPoller_ACME_Success verifies provisioning_cert → active on ACME success.
func TestPoller_ACME_Success(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(1)
	conn.Status = "provisioning_cert"
	st.addConn(&conn)

	res := newFakeResolver()
	certsM := &fakeCertManager{
		acmeResult: certs.Result{
			Success:         true,
			CertificatePath: "/etc/angie/certs/conn_1.crt",
			KeyPath:         "/etc/angie/certs/conn_1.key",
			Message:         "cert issued",
		},
	}
	cfg := &fakeCfgWriter{}
	rel := &fakeReloader{}
	p := newTestPoller(st, res, cfg, certsM, rel)

	count, err := p.tickOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	stored := st.conns[conn.ID]
	assert.Equal(t, "active", stored.Status)
	assert.NotNil(t, stored.SSLCertPath)
	assert.Equal(t, "/etc/angie/certs/conn_1.crt", *stored.SSLCertPath)
	// ACME was called
	assert.Contains(t, certsM.acmeCalls, conn.ID)
}

// TestPoller_ACME_Fail_Backoff verifies that ACME failure goes back to pending_dns
// with a retry scheduled (retry count < max).
func TestPoller_ACME_Fail_Backoff(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(1)
	conn.Status = "provisioning_cert"
	conn.AcmeRetryCount = 0
	st.addConn(&conn)

	certsM := &fakeCertManager{
		acmeResult: certs.Result{Success: false, Message: "certbot failed"},
	}
	cfg := &fakeCfgWriter{}
	p := newTestPoller(st, newFakeResolver(), cfg, certsM, &fakeReloader{})

	_, err := p.tickOnce(context.Background())
	require.NoError(t, err)

	stored := st.conns[conn.ID]
	// Goes back to pending_dns with retries left
	assert.Equal(t, "pending_dns", stored.Status)
	assert.Equal(t, 1, stored.AcmeRetryCount)
	assert.NotNil(t, stored.AcmeNextRetryAt)
}

// TestPoller_ACME_Exhausted_SelfSigned verifies that after maxRetries with
// lenient TLS mode, self-signed fallback is used → status active.
func TestPoller_ACME_Exhausted_SelfSigned(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(1)
	conn.Status = "provisioning_cert"
	conn.OriginTLSMode = "lenient"
	conn.AcmeRetryCount = acmeMaxRetries - 1 // one more failure → exhausted
	st.addConn(&conn)

	certsM := &fakeCertManager{
		acmeResult: certs.Result{Success: false, Message: "LE down"},
		selfSignedResult: certs.Result{
			Success:         true,
			CertificatePath: "/etc/angie/certs/conn_1_ss.crt",
			KeyPath:         "/etc/angie/certs/conn_1_ss.key",
		},
	}
	cfg := &fakeCfgWriter{}
	p := newTestPoller(st, newFakeResolver(), cfg, certsM, &fakeReloader{})

	_, err := p.tickOnce(context.Background())
	require.NoError(t, err)

	stored := st.conns[conn.ID]
	assert.Equal(t, "active", stored.Status)
	assert.NotNil(t, stored.SSLCertPath)
	// Self-signed was called
	assert.Contains(t, certsM.selfSignedCalls, conn.ID)
}

// TestPoller_ACME_Exhausted_StrictTLS verifies that after maxRetries with
// strict TLS mode, status goes to error (no self-signed fallback).
func TestPoller_ACME_Exhausted_StrictTLS(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(1)
	conn.Status = "provisioning_cert"
	conn.OriginTLSMode = "strict"
	conn.AcmeRetryCount = acmeMaxRetries - 1
	st.addConn(&conn)

	certsM := &fakeCertManager{
		acmeResult: certs.Result{Success: false, Message: "LE unreachable"},
	}
	p := newTestPoller(st, newFakeResolver(), &fakeCfgWriter{}, certsM, &fakeReloader{})

	_, err := p.tickOnce(context.Background())
	require.NoError(t, err)

	stored := st.conns[conn.ID]
	assert.Equal(t, "error", stored.Status)
	// Self-signed NOT called
	assert.Empty(t, certsM.selfSignedCalls)
	assert.Contains(t, *stored.StatusDetail, "Strict TLS")
}

// TestISO_CodeValidation verifies that invalid country codes are rejected.
func TestISO_CodeValidation(t *testing.T) {
	_, err := validateISOCodes([]string{"RU", "XXX", "CN"})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "ISO 3166-1"))

	codes, err := validateISOCodes([]string{"ru", "cn", "RU"}) // dedup
	require.NoError(t, err)
	assert.Equal(t, []string{"RU", "CN"}, codes)
}

// newTestPoller builds a Poller with a short tick for tests (no goroutine).
func newTestPoller(st Store, res *fakeResolver, cfg *fakeCfgWriter, certsM *fakeCertManager, rel *fakeReloader) *Poller {
	return &Poller{
		store:        st,
		dns:          conndns.NewVerifier(res),
		edge:         fakeEdge{},
		cfg:          cfg,
		certs:        certsM,
		reloader:     rel,
		log:          slog.New(slog.NewTextHandler(os.Stderr, nil)),
		tickInterval: time.Second,
	}
}

// newTestPollerWithEdge builds a Poller with a specific edge resolver.
func newTestPollerWithEdge(st Store, res *fakeResolver, cfg *fakeCfgWriter, certsM *fakeCertManager, rel *fakeReloader, e fakeEdge) *Poller {
	return &Poller{
		store:        st,
		dns:          conndns.NewVerifier(res),
		edge:         e,
		cfg:          cfg,
		certs:        certsM,
		reloader:     rel,
		log:          slog.New(slog.NewTextHandler(os.Stderr, nil)),
		tickInterval: time.Second,
	}
}

// TestCreateConnection_DNSResolution verifies that creating a connection
// without origin hosts resolves them using DNS if possible.
func TestCreateConnection_DNSResolution(t *testing.T) {
	st := newFakeStore()
	res := newFakeResolver()
	res.hosts["my-conn.example.com"] = []string{"9.9.9.9", "8.8.8.8"}
	cfg := &fakeCfgWriter{}
	certsM := &fakeCertManager{}
	rel := &fakeReloader{}
	svc := buildService(st, res, cfg, certsM, rel)

	ctx := tenantCtx(10)
	resp, err := svc.CreateConnection(ctx, &connectionsv1.CreateConnectionRequest{
		Name:   "my-conn",
		Domain: "my-conn.example.com",
	})
	require.NoError(t, err)

	require.NotNil(t, resp.Connection)
	assert.Equal(t, []string{"9.9.9.9", "8.8.8.8"}, resp.Connection.OriginHosts)
}

// TestProbeConnection_DNSResolutionOnTXTVerify verifies that ProbeConnection
// resolves origin hosts if empty when transitioning from pending_verification.
func TestProbeConnection_DNSResolutionOnTXTVerify(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(5)
	conn.Status = "pending_verification"
	conn.VerifyToken = "mytok"
	conn.OriginHosts = []string{} // empty
	st.addConn(&conn)

	res := newFakeResolver()
	res.txtRecords["_waf-verify.example.com"] = []string{"mytok"}
	res.hosts["example.com"] = []string{"7.7.7.7"}

	svc := buildService(st, res, &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{})

	ctx := tenantCtx(5)
	resp, err := svc.ProbeConnection(ctx, &connectionsv1.ProbeConnectionRequest{Id: conn.ID})
	require.NoError(t, err)

	assert.Equal(t, "pending_dns", resp.Status)
	assert.Equal(t, []string{"7.7.7.7"}, resp.OriginHosts)
	assert.Equal(t, []string{"7.7.7.7"}, st.conns[conn.ID].OriginHosts)
}

// TestPoller_DNSResolutionOnTXTVerify verifies that Poller tickVerification
// resolves origin hosts if empty when transitioning from pending_verification.
func TestPoller_DNSResolutionOnTXTVerify(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(1)
	conn.Status = "pending_verification"
	conn.VerifyToken = "secrettok"
	conn.OriginHosts = []string{} // empty
	st.addConn(&conn)

	res := newFakeResolver()
	res.txtRecords["_waf-verify.example.com"] = []string{"secrettok"}
	res.hosts["example.com"] = []string{"6.6.6.6"}

	p := newTestPoller(st, res, &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{})

	_, err := p.tickOnce(context.Background())
	require.NoError(t, err)

	stored := st.conns[conn.ID]
	assert.Equal(t, "pending_dns", stored.Status)
	assert.Equal(t, []string{"6.6.6.6"}, stored.OriginHosts)
}

// TestCreateConnection_ZoneAlreadyVerified verifies that when TenantHasVerifiedZone
// returns true, CreateConnection skips the TXT step and sets status pending_dns.
func TestCreateConnection_ZoneAlreadyVerified(t *testing.T) {
	st := newFakeStore()
	st.verifiedZone = true
	res := newFakeResolver()
	cfg := &fakeCfgWriter{}
	rel := &fakeReloader{}
	svc := buildService(st, res, cfg, &fakeCertManager{}, rel)

	ctx := tenantCtx(10)
	resp, err := svc.CreateConnection(ctx, &connectionsv1.CreateConnectionRequest{
		Name:   "skip-txt",
		Domain: "sub.acme.com",
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Connection)
	assert.Equal(t, "pending_dns", resp.Connection.Status)
	assert.Contains(t, resp.Connection.StatusDetail, "already verified")
}

// TestGetEdgeInfo_ReturnsHostname verifies that GetEdgeInfo returns EdgeHostname
// (not EdgeIpv4) when the resolver has a BaseHostname set.
func TestGetEdgeInfo_ReturnsHostname(t *testing.T) {
	edgeR := fakeEdge{t: edge.Targets{BaseHostname: "edge.x"}}
	svc := buildServiceWithEdge(newFakeStore(), newFakeResolver(), &fakeCfgWriter{}, &fakeCertManager{}, &fakeReloader{}, edgeR)
	// fakeStore.GetTenantByID returns Name="acme" for any id
	ctx := tenantCtx(42)
	resp, err := svc.GetEdgeInfo(ctx, &connectionsv1.EdgeInfoRequest{})
	require.NoError(t, err)
	assert.Equal(t, "acme.edge.x", resp.EdgeHostname)
	assert.Empty(t, resp.EdgeIpv4)
}
