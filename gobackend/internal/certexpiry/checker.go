package certexpiry

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/zwarder/waf/gobackend/internal/store"
)

const (
	defaultThreshold = 14 * 24 * time.Hour // notify when < 14 days remain
	defaultDedup     = 3 * 24 * time.Hour  // don't re-notify within 3 days
	defaultInterval  = 12 * time.Hour
)

// Store is the subset of *store.Store used by the checker.
type Store interface {
	ListActiveConnectionsWithCert(ctx context.Context) ([]store.Connection, error)
	HasRecentCertNotification(ctx context.Context, connID int64, since time.Time) (bool, error)
}

// Notifier is the subset of *notify.Notifier used by the checker.
type Notifier interface {
	NotifyTenantMembers(ctx context.Context, tenantID, excludeUserID int64, typ, title, body string, data map[string]any) error
}

// Checker is a background goroutine that periodically reads each active
// connection's TLS certificate from disk, checks the expiry date, and emits
// a "cert.expiring" notification to the tenant's members when fewer than
// defaultThreshold days remain and no recent notification was sent.
type Checker struct {
	store     Store
	notifier  Notifier
	log       *slog.Logger
	threshold time.Duration
	dedup     time.Duration
	interval  time.Duration
	now       func() time.Time
	notAfter  func(path string) (time.Time, error) // injectable for tests
}

// NewChecker returns a Checker wired to the given store and notifier.
// All durations use the package-level defaults; the clock and cert reader are
// real implementations that tests may override.
func NewChecker(s Store, n Notifier, log *slog.Logger) *Checker {
	return &Checker{
		store:     s,
		notifier:  n,
		log:       log,
		threshold: defaultThreshold,
		dedup:     defaultDedup,
		interval:  defaultInterval,
		now:       time.Now,
		notAfter:  certNotAfter,
	}
}

// certNotAfter reads a PEM cert file and returns the leaf cert's NotAfter.
func certNotAfter(path string) (time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// Run performs an initial check immediately, then repeats every interval until
// ctx is cancelled. Call as a goroutine: go checker.Run(ctx).
func (c *Checker) Run(ctx context.Context) {
	c.checkOnce(ctx)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.checkOnce(ctx)
		}
	}
}

// checkOnce iterates all active connections with a cert path and emits
// cert.expiring notifications for those whose certificate expires within the
// threshold window and have not been recently notified.
func (c *Checker) checkOnce(ctx context.Context) {
	conns, err := c.store.ListActiveConnectionsWithCert(ctx)
	if err != nil {
		if c.log != nil {
			c.log.Warn("certexpiry: list connections", "err", err)
		}
		return
	}

	now := c.now()
	for _, conn := range conns {
		if conn.SSLCertPath == nil {
			continue
		}
		na, err := c.notAfter(*conn.SSLCertPath)
		if err != nil {
			if c.log != nil {
				c.log.Warn("certexpiry: parse cert", "conn", conn.ID, "err", err)
			}
			continue
		}

		remaining := na.Sub(now)
		// Skip certs already expired (handled elsewhere) or not yet close to expiry.
		if remaining <= 0 || remaining >= c.threshold {
			continue
		}

		recent, err := c.store.HasRecentCertNotification(ctx, conn.ID, now.Add(-c.dedup))
		if err != nil {
			if c.log != nil {
				c.log.Warn("certexpiry: dedup check", "conn", conn.ID, "err", err)
			}
			continue
		}
		if recent {
			continue
		}

		days := int(remaining.Hours()/24) + 1
		body := fmt.Sprintf("The certificate for %s expires in %d days.", conn.Domain, days)
		if c.notifier != nil {
			_ = c.notifier.NotifyTenantMembers(
				ctx,
				conn.TenantID,
				0, // excludeUserID — notify all members
				"cert.expiring",
				"Certificate expiring",
				body,
				map[string]any{
					"connection_id": conn.ID,
					"name":          conn.Name,
					"domain":        conn.Domain,
					"days":          days,
				},
			)
		}
	}
}
