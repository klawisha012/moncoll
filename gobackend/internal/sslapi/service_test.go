package sslapi

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sslv1 "github.com/zwarder/waf/gobackend/gen/ssl/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/certs"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// ── fakes ─────────────────────────────────────────────────────────────────────

type fakeResolver struct {
	conn *store.Connection
	err  error
	// capture what was passed
	gotConnID   int64
	gotTenantID int64
}

func (f *fakeResolver) GetConnectionForTenant(_ context.Context, connID, tenantID int64) (*store.Connection, error) {
	f.gotConnID = connID
	f.gotTenantID = tenantID
	return f.conn, f.err
}

type fakeCertManager struct {
	statusResult   certs.StatusResult
	acmeResult     certs.Result
	regenResult    certs.Result
	gotACMEDomains []string
}

func (f *fakeCertManager) CheckStatus(_ int64, _ *int64) certs.StatusResult {
	return f.statusResult
}

func (f *fakeCertManager) TriggerACME(_ int64, domains []string, _ *int64) certs.Result {
	f.gotACMEDomains = domains
	return f.acmeResult
}

func (f *fakeCertManager) Regenerate(_ int64, _ []string, _ *int64) certs.Result {
	return f.regenResult
}

// ── helpers ───────────────────────────────────────────────────────────────────

func ctxWithTenant(tenantID int64) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		UserID:       1,
		PlatformRole: "client",
		TenantID:     &tenantID,
	})
}

func ctxAdmin() context.Context {
	// Admin has no TenantID (nil).
	return auth.WithIdentity(context.Background(), &auth.Identity{
		UserID:       99,
		PlatformRole: "admin",
		TenantID:     nil,
	})
}

func notFoundErr() error {
	return &store.NotFoundError{Entity: "connection"}
}

// ── tests ─────────────────────────────────────────────────────────────────────

// Admin (TenantID nil) → PermissionDenied on all three RPCs.
func TestAdminHasNoTenant_PermissionDenied(t *testing.T) {
	svc := New(&fakeResolver{}, &fakeCertManager{})
	ctx := ctxAdmin()

	_, err := svc.GetCertificateStatus(ctx, &sslv1.ConnIdRequest{ConnectionId: 1})
	assertCode(t, "GetCertificateStatus", err, codes.PermissionDenied)

	_, err = svc.RequestCertificate(ctx, &sslv1.RequestCertRequest{ConnectionId: 1})
	assertCode(t, "RequestCertificate", err, codes.PermissionDenied)

	_, err = svc.RegenerateCertificate(ctx, &sslv1.ConnIdRequest{ConnectionId: 1})
	assertCode(t, "RegenerateCertificate", err, codes.PermissionDenied)
}

// Unauthenticated context (no identity at all) → PermissionDenied.
func TestNoIdentity_PermissionDenied(t *testing.T) {
	svc := New(&fakeResolver{}, &fakeCertManager{})
	ctx := context.Background() // no identity attached

	_, err := svc.GetCertificateStatus(ctx, &sslv1.ConnIdRequest{ConnectionId: 1})
	assertCode(t, "GetCertificateStatus", err, codes.PermissionDenied)
}

// PermissionDenied message must match the Python detail string.
func TestPermissionDeniedMessage(t *testing.T) {
	svc := New(&fakeResolver{}, &fakeCertManager{})
	ctx := ctxAdmin()

	_, err := svc.GetCertificateStatus(ctx, &sslv1.ConnIdRequest{ConnectionId: 1})
	st := status.Convert(err)
	want := "user has no tenant"
	if st.Message() != want {
		t.Errorf("want %q, got %q", want, st.Message())
	}
}

// Connection not owned by tenant → codes.NotFound.
func TestConnectionNotOwned_NotFound(t *testing.T) {
	resolver := &fakeResolver{err: notFoundErr()}
	svc := New(resolver, &fakeCertManager{})
	ctx := ctxWithTenant(42)

	_, err := svc.GetCertificateStatus(ctx, &sslv1.ConnIdRequest{ConnectionId: 7})
	assertCode(t, "GetCertificateStatus", err, codes.NotFound)

	_, err = svc.RequestCertificate(ctx, &sslv1.RequestCertRequest{ConnectionId: 7})
	assertCode(t, "RequestCertificate", err, codes.NotFound)

	_, err = svc.RegenerateCertificate(ctx, &sslv1.ConnIdRequest{ConnectionId: 7})
	assertCode(t, "RegenerateCertificate", err, codes.NotFound)
}

// RequestCertificate with empty domains uses [conn.Domain].
func TestRequestCertificate_EmptyDomains_UsesConnDomain(t *testing.T) {
	conn := &store.Connection{ID: 5, Domain: "example.com", TenantID: 42}
	manager := &fakeCertManager{acmeResult: certs.Result{Success: true, Message: "ok"}}
	svc := New(&fakeResolver{conn: conn}, manager)
	ctx := ctxWithTenant(42)

	resp, err := svc.RequestCertificate(ctx, &sslv1.RequestCertRequest{
		ConnectionId: 5,
		Domains:      nil, // empty
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success")
	}
	if len(manager.gotACMEDomains) != 1 || manager.gotACMEDomains[0] != "example.com" {
		t.Errorf("expected domains=[example.com], got %v", manager.gotACMEDomains)
	}
}

// RequestCertificate with explicit domains uses them, not conn.Domain.
func TestRequestCertificate_ExplicitDomains_UsesThem(t *testing.T) {
	conn := &store.Connection{ID: 5, Domain: "example.com", TenantID: 42}
	manager := &fakeCertManager{acmeResult: certs.Result{Success: true, Message: "ok"}}
	svc := New(&fakeResolver{conn: conn}, manager)
	ctx := ctxWithTenant(42)

	resp, err := svc.RequestCertificate(ctx, &sslv1.RequestCertRequest{
		ConnectionId: 5,
		Domains:      []string{"a.example.com", "b.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success")
	}
	if len(manager.gotACMEDomains) != 2 ||
		manager.gotACMEDomains[0] != "a.example.com" ||
		manager.gotACMEDomains[1] != "b.example.com" {
		t.Errorf("expected explicit domains, got %v", manager.gotACMEDomains)
	}
}

// Happy path: GetCertificateStatus maps StatusResult → StatusResponse.
func TestGetCertificateStatus_HappyPath(t *testing.T) {
	certPath := "/etc/angie/http.d/conn_5/cert.pem"
	keyPath := "/etc/angie/http.d/conn_5/key.pem"
	bcert := "/var/lib/angie/http.d/conn_5/cert.pem"
	bkey := "/var/lib/angie/http.d/conn_5/key.pem"

	conn := &store.Connection{ID: 5, Domain: "example.com", TenantID: 42}
	manager := &fakeCertManager{
		statusResult: certs.StatusResult{
			CertificateExists: true,
			KeyExists:         true,
			CertificatePath:   &certPath,
			KeyPath:           &keyPath,
			BackendCertPath:   &bcert,
			BackendKeyPath:    &bkey,
		},
	}
	svc := New(&fakeResolver{conn: conn}, manager)
	ctx := ctxWithTenant(42)

	resp, err := svc.GetCertificateStatus(ctx, &sslv1.ConnIdRequest{ConnectionId: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.CertificateExists {
		t.Error("expected certificate_exists=true")
	}
	if !resp.KeyExists {
		t.Error("expected key_exists=true")
	}
	if resp.CertificatePath != certPath {
		t.Errorf("cert path: want %q, got %q", certPath, resp.CertificatePath)
	}
	if resp.BackendCertPath != bcert {
		t.Errorf("backend cert: want %q, got %q", bcert, resp.BackendCertPath)
	}
}

// Happy path: GetCertificateStatus when no cert exists → empty strings, false bools.
func TestGetCertificateStatus_NoCert(t *testing.T) {
	conn := &store.Connection{ID: 5, Domain: "example.com", TenantID: 42}
	manager := &fakeCertManager{
		statusResult: certs.StatusResult{
			CertificateExists: false,
			KeyExists:         false,
		},
	}
	svc := New(&fakeResolver{conn: conn}, manager)
	ctx := ctxWithTenant(42)

	resp, err := svc.GetCertificateStatus(ctx, &sslv1.ConnIdRequest{ConnectionId: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.CertificateExists {
		t.Error("expected certificate_exists=false")
	}
	if resp.CertificatePath != "" {
		t.Errorf("expected empty cert path, got %q", resp.CertificatePath)
	}
}

// Happy path: RequestCertificate maps Result → CertResponse.
func TestRequestCertificate_HappyPath(t *testing.T) {
	conn := &store.Connection{ID: 5, Domain: "example.com", TenantID: 42}
	manager := &fakeCertManager{
		acmeResult: certs.Result{
			Success:         true,
			Message:         "Let's Encrypt certificate issued for example.com",
			CertificatePath: "/etc/angie/http.d/conn_5/cert.pem",
			KeyPath:         "/etc/angie/http.d/conn_5/key.pem",
			BackendCertPath: "/var/lib/angie/http.d/conn_5/cert.pem",
			BackendKeyPath:  "/var/lib/angie/http.d/conn_5/key.pem",
		},
	}
	svc := New(&fakeResolver{conn: conn}, manager)
	ctx := ctxWithTenant(42)

	resp, err := svc.RequestCertificate(ctx, &sslv1.RequestCertRequest{ConnectionId: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success")
	}
	if resp.Message == "" {
		t.Error("expected non-empty message")
	}
}

// Happy path: RegenerateCertificate maps Result → CertResponse.
func TestRegenerateCertificate_HappyPath(t *testing.T) {
	conn := &store.Connection{ID: 5, Domain: "example.com", TenantID: 42}
	manager := &fakeCertManager{
		regenResult: certs.Result{
			Success:         false,
			Message:         "certbot is not installed in the backend container",
			CertificatePath: "",
			KeyPath:         "",
		},
	}
	svc := New(&fakeResolver{conn: conn}, manager)
	ctx := ctxWithTenant(42)

	// success=false is a valid response (Python returns 200 with success=false
	// when certbot fails — not a gRPC error)
	resp, err := svc.RegenerateCertificate(ctx, &sslv1.ConnIdRequest{ConnectionId: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Success {
		t.Error("expected success=false (certbot not installed)")
	}
	if resp.Message == "" {
		t.Error("expected non-empty message")
	}
}

// Internal DB error from resolver → codes.Internal.
func TestDBError_Internal(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("connection refused")}
	svc := New(resolver, &fakeCertManager{})
	ctx := ctxWithTenant(42)

	_, err := svc.GetCertificateStatus(ctx, &sslv1.ConnIdRequest{ConnectionId: 1})
	assertCode(t, "GetCertificateStatus", err, codes.Internal)
}

// ── assertion helper ──────────────────────────────────────────────────────────

func assertCode(t *testing.T, name string, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: expected error with code %v, got nil", name, want)
		return
	}
	st := status.Convert(err)
	if st.Code() != want {
		t.Errorf("%s: want code %v, got %v (msg=%q)", name, want, st.Code(), st.Message())
	}
}
