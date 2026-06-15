package certexpiry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zwarder/waf/gobackend/internal/store"
)

// ── Fakes ────────────────────────────────────────────────────────────────────

type fakeStore struct {
	conns  []store.Connection
	recent map[int64]bool // connID → hasRecent
}

func (f *fakeStore) ListActiveConnectionsWithCert(_ context.Context) ([]store.Connection, error) {
	return f.conns, nil
}

func (f *fakeStore) HasRecentCertNotification(_ context.Context, connID int64, _ time.Time) (bool, error) {
	return f.recent[connID], nil
}

type fakeNotifier struct {
	calls []notifyCall
}

type notifyCall struct {
	tenantID int64
	typ      string
	title    string
	body     string
	data     map[string]any
}

func (f *fakeNotifier) NotifyTenantMembers(_ context.Context, tenantID, _ int64, typ, title, body string, data map[string]any) error {
	f.calls = append(f.calls, notifyCall{tenantID: tenantID, typ: typ, title: title, body: body, data: data})
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func strPtr(s string) *string { return &s }

// fixedNow is the synthetic "now" used across all tests.
var fixedNow = time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)

func buildChecker(st Store, n Notifier, expiries map[string]time.Time) *Checker {
	c := NewChecker(st, n, nil)
	c.now = func() time.Time { return fixedNow }
	c.notAfter = func(path string) (time.Time, error) {
		t, ok := expiries[path]
		if !ok {
			return time.Time{}, errors.New("no expiry registered for " + path)
		}
		return t, nil
	}
	return c
}

// ── Tests ────────────────────────────────────────────────────────────────────

// Cert expiring in 5 days, no recent notification → one cert.expiring emitted.
func TestCheckOnce_ExpiringSoon_Notifies(t *testing.T) {
	certPath := "/certs/conn1.pem"
	expiry := fixedNow.Add(5 * 24 * time.Hour)

	st := &fakeStore{
		conns: []store.Connection{
			{ID: 1, TenantID: 10, Name: "web", Domain: "example.com", SSLCertPath: strPtr(certPath)},
		},
		recent: map[int64]bool{},
	}
	n := &fakeNotifier{}
	c := buildChecker(st, n, map[string]time.Time{certPath: expiry})

	c.checkOnce(context.Background())

	if len(n.calls) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(n.calls))
	}
	call := n.calls[0]
	if call.typ != "cert.expiring" {
		t.Errorf("type: want cert.expiring, got %q", call.typ)
	}
	if call.tenantID != 10 {
		t.Errorf("tenantID: want 10, got %d", call.tenantID)
	}
	days, ok := call.data["days"].(int)
	if !ok {
		t.Fatalf("data[days] is not int: %T", call.data["days"])
	}
	// remaining = 5*24h, days = int(120/24)+1 = 5+1 = 6 (ceiling rounding); accept 5 or 6.
	if days < 5 || days > 6 {
		t.Errorf("days: want 5 or 6, got %d", days)
	}
	if call.data["domain"] != "example.com" {
		t.Errorf("data[domain]: want example.com, got %v", call.data["domain"])
	}
}

// Cert expiring in 40 days (beyond 14-day threshold) → no notification.
func TestCheckOnce_NotExpiringSoon_NoNotify(t *testing.T) {
	certPath := "/certs/conn2.pem"
	expiry := fixedNow.Add(40 * 24 * time.Hour)

	st := &fakeStore{
		conns: []store.Connection{
			{ID: 2, TenantID: 20, Name: "api", Domain: "api.example.com", SSLCertPath: strPtr(certPath)},
		},
		recent: map[int64]bool{},
	}
	n := &fakeNotifier{}
	c := buildChecker(st, n, map[string]time.Time{certPath: expiry})

	c.checkOnce(context.Background())

	if len(n.calls) != 0 {
		t.Errorf("expected no notifications, got %d", len(n.calls))
	}
}

// Cert already expired (NotAfter in the past) → no notification.
func TestCheckOnce_AlreadyExpired_NoNotify(t *testing.T) {
	certPath := "/certs/conn3.pem"
	expiry := fixedNow.Add(-1 * time.Hour)

	st := &fakeStore{
		conns: []store.Connection{
			{ID: 3, TenantID: 30, Name: "old", Domain: "old.example.com", SSLCertPath: strPtr(certPath)},
		},
		recent: map[int64]bool{},
	}
	n := &fakeNotifier{}
	c := buildChecker(st, n, map[string]time.Time{certPath: expiry})

	c.checkOnce(context.Background())

	if len(n.calls) != 0 {
		t.Errorf("expected no notifications for expired cert, got %d", len(n.calls))
	}
}

// Recent notification exists within dedup window → no re-notification.
func TestCheckOnce_RecentNotification_Deduped(t *testing.T) {
	certPath := "/certs/conn4.pem"
	expiry := fixedNow.Add(3 * 24 * time.Hour)

	st := &fakeStore{
		conns: []store.Connection{
			{ID: 4, TenantID: 40, Name: "dup", Domain: "dup.example.com", SSLCertPath: strPtr(certPath)},
		},
		recent: map[int64]bool{4: true},
	}
	n := &fakeNotifier{}
	c := buildChecker(st, n, map[string]time.Time{certPath: expiry})

	c.checkOnce(context.Background())

	if len(n.calls) != 0 {
		t.Errorf("expected no notifications (dedup), got %d", len(n.calls))
	}
}

// notAfter errors for one connection → that conn skipped, others still processed.
func TestCheckOnce_CertReadError_SkipsOneProcessesOthers(t *testing.T) {
	goodPath := "/certs/conn_good.pem"
	badPath := "/certs/conn_bad.pem"
	expiry := fixedNow.Add(5 * 24 * time.Hour)

	st := &fakeStore{
		conns: []store.Connection{
			{ID: 5, TenantID: 50, Name: "bad", Domain: "bad.example.com", SSLCertPath: strPtr(badPath)},
			{ID: 6, TenantID: 50, Name: "good", Domain: "good.example.com", SSLCertPath: strPtr(goodPath)},
		},
		recent: map[int64]bool{},
	}
	n := &fakeNotifier{}
	// Only register the good path; bad path will return an error.
	c := buildChecker(st, n, map[string]time.Time{goodPath: expiry})

	c.checkOnce(context.Background())

	// Should get exactly one notification (for the good conn), bad conn skipped.
	if len(n.calls) != 1 {
		t.Fatalf("expected 1 notification (good conn), got %d", len(n.calls))
	}
	if n.calls[0].data["domain"] != "good.example.com" {
		t.Errorf("expected notification for good.example.com, got %v", n.calls[0].data["domain"])
	}
}
