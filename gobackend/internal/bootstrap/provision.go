package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/zwarder/waf/gobackend/internal/store"
)

// Provisioner is the store surface EnsureSystemProvisioning needs. Implemented
// by *store.Store; faked in tests.
type Provisioner interface {
	EnsureSystemTenant(ctx context.Context) (*store.Tenant, error)
	BackfillAdminsIntoSystemTenant(ctx context.Context, systemTenantID int64) error
	CreateConnection(ctx context.Context, c *store.Connection) (*store.Connection, error)
}

// SelfSiteConfig configures the optional self-connection. Domain == "" disables it.
type SelfSiteConfig struct {
	Domain     string
	OriginHost string
	OriginPort int
}

// LoadSelfSiteConfig reads WAF_SELF_SITE_* from the environment. Domain empty
// (the default) means "no self-connection".
func LoadSelfSiteConfig() SelfSiteConfig {
	port := 3000
	if v := os.Getenv("WAF_SELF_SITE_ORIGIN_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			port = n
		}
	}
	host := os.Getenv("WAF_SELF_SITE_ORIGIN_HOST")
	if host == "" {
		host = "frontend"
	}
	return SelfSiteConfig{
		Domain:     os.Getenv("WAF_SELF_SITE_DOMAIN"),
		OriginHost: host,
		OriginPort: port,
	}
}

// EnsureSystemProvisioning is idempotent: ensure the system tenant, backfill all
// platform admins into it as owner-MEMBERS (never touching users.tenant_id),
// and (only when cfg.Domain is set) insert a single self-connection row owned
// by the system tenant. Returns the system tenant id so the caller can scope
// admins in the auth interceptor. Safe to run on every startup and inside
// create-admin. NOTE: it inserts the connection ROW only; SERVING it (Angie
// config + cert) happens once the deployment routes the domain through the WAF.
func EnsureSystemProvisioning(ctx context.Context, log *slog.Logger, p Provisioner, cfg SelfSiteConfig) (int64, error) {
	sys, err := p.EnsureSystemTenant(ctx)
	if err != nil {
		return 0, fmt.Errorf("ensure system tenant: %w", err)
	}
	if err := p.BackfillAdminsIntoSystemTenant(ctx, sys.ID); err != nil {
		return sys.ID, fmt.Errorf("backfill admins: %w", err)
	}
	if cfg.Domain == "" {
		return sys.ID, nil // self-connection disabled
	}
	conn := buildSelfConnection(sys.ID, cfg)
	if _, err := p.CreateConnection(ctx, conn); err != nil {
		var ce *store.ConflictError
		if errors.As(err, &ce) {
			log.Info("self-connection already provisioned", "domain", cfg.Domain)
			return sys.ID, nil // already exists → idempotent
		}
		return sys.ID, fmt.Errorf("create self-connection: %w", err)
	}
	log.Info("provisioned self-connection", "domain", cfg.Domain, "tenant", sys.ID)
	return sys.ID, nil
}

// buildSelfConnection fills a *store.Connection with the same defaults the
// connectionsapi handler applies (the store layer applies none). VerifiedAt is
// set because the platform owns its own domain — no TXT-verification step.
func buildSelfConnection(systemTenantID int64, cfg SelfSiteConfig) *store.Connection {
	now := time.Now().UTC()
	return &store.Connection{
		TenantID:             systemTenantID,
		Name:                 "WAF site",
		Domain:               cfg.Domain,
		OriginHosts:          []string{cfg.OriginHost},
		OriginPort:           cfg.OriginPort,
		// The self-connection's origin is the WAF's own frontend, which speaks
		// plain HTTP on :3000 — proxy without TLS (origin_tls_mode "off").
		OriginTLSMode:        "off",
		VerifyToken:          randomToken(),
		VerifiedAt:           &now,
		Status:               "pending_dns",
		DNSTTLSeconds:        60,
		HTTPVersions:         "h1,h2",
		CompressionAlgo:      "auto",
		Enabled:              true,
		ModsecState:          "detection_only",
		GeoipDeniedCountries: []string{},
		CrowdsecActive:       true,
	}
}

func randomToken() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
