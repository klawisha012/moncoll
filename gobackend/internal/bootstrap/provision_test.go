package bootstrap

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/zwarder/waf/gobackend/internal/store"
)

type fakeProvisioner struct {
	systemTenantID int64
	backfilled     int64
	createdConn    *store.Connection
	createErr      error
}

func (f *fakeProvisioner) EnsureSystemTenant(_ context.Context) (*store.Tenant, error) {
	return &store.Tenant{ID: f.systemTenantID, Name: "system"}, nil
}
func (f *fakeProvisioner) BackfillAdminsIntoSystemTenant(_ context.Context, id int64) error {
	f.backfilled = id
	return nil
}
func (f *fakeProvisioner) CreateConnection(_ context.Context, c *store.Connection) (*store.Connection, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.createdConn = c
	return c, nil
}

func newLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestEnsureSystemProvisioning_NoSelfConnWithoutEnv(t *testing.T) {
	f := &fakeProvisioner{systemTenantID: 42}
	cfg := SelfSiteConfig{} // domain empty → no connection
	if err := EnsureSystemProvisioning(context.Background(), newLog(), f, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.backfilled != 42 {
		t.Errorf("admins not backfilled into system tenant 42, got %d", f.backfilled)
	}
	if f.createdConn != nil {
		t.Error("self-connection created despite empty WAF_SELF_SITE_DOMAIN")
	}
}

func TestEnsureSystemProvisioning_CreatesSelfConn(t *testing.T) {
	f := &fakeProvisioner{systemTenantID: 42}
	cfg := SelfSiteConfig{Domain: "zwarder.ru", OriginHost: "frontend", OriginPort: 3000}
	if err := EnsureSystemProvisioning(context.Background(), newLog(), f, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.createdConn == nil {
		t.Fatal("expected a self-connection to be created")
	}
	if f.createdConn.TenantID != 42 || f.createdConn.Domain != "zwarder.ru" {
		t.Errorf("self-connection wrong tenant/domain: %+v", f.createdConn)
	}
	if len(f.createdConn.OriginHosts) != 1 || f.createdConn.OriginHosts[0] != "frontend" || f.createdConn.OriginPort != 3000 {
		t.Errorf("self-connection wrong origin: %+v", f.createdConn)
	}
	if f.createdConn.OriginTLSMode != "strict" || f.createdConn.HTTPVersions != "h1,h2" {
		t.Errorf("self-connection missing required defaults: %+v", f.createdConn)
	}
}

func TestEnsureSystemProvisioning_SelfConnIdempotentOnConflict(t *testing.T) {
	f := &fakeProvisioner{systemTenantID: 42, createErr: &store.ConflictError{Detail: "domain taken"}}
	cfg := SelfSiteConfig{Domain: "zwarder.ru", OriginHost: "frontend", OriginPort: 3000}
	if err := EnsureSystemProvisioning(context.Background(), newLog(), f, cfg); err != nil {
		t.Fatalf("ConflictError should be treated as already-provisioned, got %v", err)
	}
}
