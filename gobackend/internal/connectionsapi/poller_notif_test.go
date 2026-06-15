package connectionsapi

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zwarder/waf/gobackend/internal/certs"
	"github.com/zwarder/waf/gobackend/internal/edge"
)

// fakeNotifier records NotifyTenantMembers calls.
type fakeNotifier struct {
	calls []notifyCall
}

type notifyCall struct {
	tenantID      int64
	excludeUserID int64
	typ           string
	title         string
	body          string
	data          map[string]any
}

func (f *fakeNotifier) NotifyTenantMembers(_ context.Context, tenantID, excludeUserID int64, typ, title, body string, data map[string]any) error {
	f.calls = append(f.calls, notifyCall{
		tenantID:      tenantID,
		excludeUserID: excludeUserID,
		typ:           typ,
		title:         title,
		body:          body,
		data:          data,
	})
	return nil
}

func pollerWithNotif(st *fakeStore, certM *fakeCertManager, notif Notifier) *Poller {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	return NewPoller(
		st,
		nil,
		fakeEdge{t: edge.Targets{}},
		&fakeCfgWriter{},
		certM,
		&fakeReloader{},
		log,
		notif,
	)
}

// TestPoller_ActiveTransition_EmitsNotification verifies that
// provisioning_cert → active emits connection.active to the right tenant.
func TestPoller_ActiveTransition_EmitsNotification(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(42)
	conn.Status = "provisioning_cert"
	conn.Name = "my-site"
	st.addConn(&conn)

	certM := &fakeCertManager{
		acmeResult: certs.Result{Success: true, CertificatePath: "/cert.pem", KeyPath: "/key.pem"},
	}
	notif := &fakeNotifier{}
	p := pollerWithNotif(st, certM, notif)

	p.processOne(context.Background(), &conn)

	require.Len(t, notif.calls, 1, "expected exactly one notification")
	c := notif.calls[0]
	assert.Equal(t, int64(42), c.tenantID)
	assert.Equal(t, int64(0), c.excludeUserID, "excludeUserID must be 0 (notify all)")
	assert.Equal(t, "connection.active", c.typ)
	assert.Equal(t, "Connection active", c.title)
	assert.Contains(t, c.body, "my-site")
	assert.Equal(t, "my-site", c.data["name"])
}

// TestPoller_ErrorTransition_EmitsNotification verifies that
// provisioning_cert → error (strict TLS, retries exhausted) emits connection.error.
func TestPoller_ErrorTransition_EmitsNotification(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(7)
	conn.Status = "provisioning_cert"
	conn.Name = "bad-cert"
	conn.OriginTLSMode = "strict"
	conn.AcmeRetryCount = acmeMaxRetries // one more failure → error
	st.addConn(&conn)

	certM := &fakeCertManager{
		acmeResult: certs.Result{Success: false, Message: "ACME challenge failed"},
	}
	notif := &fakeNotifier{}
	p := pollerWithNotif(st, certM, notif)

	p.processOne(context.Background(), &conn)

	require.Len(t, notif.calls, 1, "expected exactly one notification")
	c := notif.calls[0]
	assert.Equal(t, int64(7), c.tenantID)
	assert.Equal(t, "connection.error", c.typ)
	assert.Equal(t, "Connection error", c.title)
	assert.Contains(t, c.body, "bad-cert")
}

// TestPoller_TransientTransition_NoNotification verifies that
// provisioning_cert → pending_dns (retries remain) emits nothing.
func TestPoller_TransientTransition_NoNotification(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(5)
	conn.Status = "provisioning_cert"
	conn.AcmeRetryCount = 0 // retries remain → back to pending_dns
	st.addConn(&conn)

	certM := &fakeCertManager{
		acmeResult: certs.Result{Success: false, Message: "timeout"},
	}
	notif := &fakeNotifier{}
	p := pollerWithNotif(st, certM, notif)

	p.processOne(context.Background(), &conn)

	assert.Empty(t, notif.calls, "expected no notification for transient status change")
}

// TestPoller_NilNotifier_DoesNotPanic verifies nil notifier is safe.
func TestPoller_NilNotifier_DoesNotPanic(t *testing.T) {
	st := newFakeStore()
	conn := sampleConn(1)
	conn.Status = "provisioning_cert"
	st.addConn(&conn)

	certM := &fakeCertManager{
		acmeResult: certs.Result{Success: true, CertificatePath: "/cert.pem", KeyPath: "/key.pem"},
	}
	p := pollerWithNotif(st, certM, nil)

	assert.NotPanics(t, func() {
		p.processOne(context.Background(), &conn)
	})
}
