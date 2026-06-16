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
// platform admins into it as owners, and (only when cfg.Domain is set) insert a
// single self-connection row owned by the system tenant. Safe to run on every
// startup and inside create-admin. NOTE: it inserts the connection ROW only;
// SERVING it (Angie config + cert) happens via the connections reconcile/poller
// once the deployment routes the domain through the WAF (edge host-split + DNS).
func EnsureSystemProvisioning(ctx context.Context, log *slog.Logger, p Provisioner, cfg SelfSiteConfig) error {
	sys, err := p.EnsureSystemTenant(ctx)
	if err != nil {
		return fmt.Errorf("ensure system tenant: %w", err)
	}
	if err := p.BackfillAdminsIntoSystemTenant(ctx, sys.ID); err != nil {
		return fmt.Errorf("backfill admins: %w", err)
	}
	if cfg.Domain == "" {
		return nil // self-connection disabled
	}
	conn := buildSelfConnection(sys.ID, cfg)
	if _, err := p.CreateConnection(ctx, conn); err != nil {
		var ce *store.ConflictError
		if errors.As(err, &ce) {
			log.Info("self-connection already provisioned", "domain", cfg.Domain)
			return nil // already exists → idempotent
		}
		return fmt.Errorf("create self-connection: %w", err)
	}
	log.Info("provisioned self-connection", "domain", cfg.Domain, "tenant", sys.ID)
	return nil
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
		OriginTLSMode:        "strict",
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
