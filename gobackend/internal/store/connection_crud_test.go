//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

// fullSchema creates the tenants + connections tables with the complete column
// set matching backend/src/db/models.py.
const fullSchema = `
CREATE TABLE IF NOT EXISTS tenants (
	id          BIGSERIAL PRIMARY KEY,
	name        VARCHAR(32) NOT NULL UNIQUE,
	display_name VARCHAR(64) NOT NULL DEFAULT '',
	suspended_at TIMESTAMPTZ,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS connections (
	id                    BIGSERIAL PRIMARY KEY,
	tenant_id             BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	name                  VARCHAR(128) NOT NULL,
	domain                VARCHAR(253) NOT NULL UNIQUE,
	origin_hosts          JSON NOT NULL DEFAULT '[]',
	origin_port           INT NOT NULL DEFAULT 443,
	origin_tls_mode       TEXT NOT NULL DEFAULT 'strict',
	verify_token          VARCHAR(64) NOT NULL DEFAULT '',
	verified_at           TIMESTAMPTZ,
	status                TEXT NOT NULL DEFAULT 'pending_verification',
	status_detail         TEXT,
	acme_retry_count      INT NOT NULL DEFAULT 0,
	acme_next_retry_at    TIMESTAMPTZ,
	next_poll_at          TIMESTAMPTZ,
	dns_ttl_seconds       INT NOT NULL DEFAULT 60,
	last_checked_at       TIMESTAMPTZ,
	http_versions         VARCHAR(32) NOT NULL DEFAULT 'h1,h2',
	compression_algo      VARCHAR(16) NOT NULL DEFAULT 'auto',
	enabled               BOOLEAN NOT NULL DEFAULT true,
	modsec_state          TEXT NOT NULL DEFAULT 'detection_only',
	geoip_denied_countries JSON NOT NULL DEFAULT '[]',
	crowdsec_active       BOOLEAN NOT NULL DEFAULT true,
	ssl_cert_path         VARCHAR(512),
	ssl_key_path          VARCHAR(512),
	created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
`

func newIntegrationStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	res, err := pool.Run("postgres", "16", []string{"POSTGRES_PASSWORD=pw", "POSTGRES_DB=waf"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Purge(res) })

	dsn := fmt.Sprintf("postgres://postgres:pw@localhost:%s/waf?sslmode=disable", res.GetPort("5432/tcp"))

	var st *Store
	require.NoError(t, pool.Retry(func() error {
		s, e := New(context.Background(), dsn)
		if e != nil {
			return e
		}
		st = s
		return st.pool.Ping(context.Background())
	}))
	t.Cleanup(st.Close)

	ctx := context.Background()
	_, err = st.pool.Exec(ctx, fullSchema)
	require.NoError(t, err)

	// Seed two tenants.
	_, err = st.pool.Exec(ctx, `
		INSERT INTO tenants (id, name, display_name) VALUES
			(1, 'acme', 'Acme Corp'),
			(2, 'beta', 'Beta LLC')
	`)
	require.NoError(t, err)

	return st, ctx
}

// strPtr is a small helper for *string literals.
func strPtr(s string) *string { return &s }

func TestConnectionCreate(t *testing.T) {
	st, ctx := newIntegrationStore(t)

	in := &Connection{
		TenantID:      1,
		Name:          "main",
		Domain:        "acme.example.com",
		OriginHosts:   []string{"1.2.3.4"},
		OriginPort:    443,
		OriginTLSMode: "strict",
		VerifyToken:   "tok123",
		Status:        "pending_verification",
		StatusDetail:  strPtr("Add the TXT record to verify ownership."),
		DNSTTLSeconds: 60,
		HTTPVersions:  "h1,h2",
		CompressionAlgo: "auto",
		Enabled:       true,
		ModsecState:   "detection_only",
		GeoipDeniedCountries: []string{},
		CrowdsecActive: true,
	}

	got, err := st.CreateConnection(ctx, in)
	require.NoError(t, err)
	require.NotZero(t, got.ID)
	require.Equal(t, int64(1), got.TenantID)
	require.Equal(t, "acme.example.com", got.Domain)
	require.Equal(t, "pending_verification", got.Status)
	require.Equal(t, []string{"1.2.3.4"}, got.OriginHosts)
	require.Equal(t, "tok123", got.VerifyToken)
	require.NotZero(t, got.CreatedAt)
	require.NotZero(t, got.UpdatedAt)
}

func TestConnectionCreate_DuplicateDomain_ConflictError(t *testing.T) {
	st, ctx := newIntegrationStore(t)

	in := &Connection{
		TenantID: 1, Name: "a", Domain: "dup.example.com",
		OriginHosts: []string{"1.2.3.4"}, OriginPort: 443,
		OriginTLSMode: "strict", VerifyToken: "x", Status: "pending_verification",
		DNSTTLSeconds: 60, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: true, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
	}
	_, err := st.CreateConnection(ctx, in)
	require.NoError(t, err)

	// Second insert with same domain — different tenant, still a conflict.
	in2 := *in
	in2.TenantID = 2
	in2.VerifyToken = "y"
	_, err = st.CreateConnection(ctx, &in2)
	require.Error(t, err)
	var ce *ConflictError
	require.ErrorAs(t, err, &ce, "expected ConflictError, got %T: %v", err, err)
}

func TestConnectionGetFull_TenantScope(t *testing.T) {
	st, ctx := newIntegrationStore(t)

	in := &Connection{
		TenantID: 1, Name: "main", Domain: "get.example.com",
		OriginHosts: []string{"5.5.5.5"}, OriginPort: 443,
		OriginTLSMode: "lenient", VerifyToken: "abc", Status: "active",
		DNSTTLSeconds: 120, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: true, ModsecState: "blocking", CrowdsecActive: false,
		GeoipDeniedCountries: []string{"CN", "RU"},
	}
	created, err := st.CreateConnection(ctx, in)
	require.NoError(t, err)

	t.Run("OwnerMatch", func(t *testing.T) {
		got, err := st.GetConnectionFull(ctx, 1, created.ID)
		require.NoError(t, err)
		require.Equal(t, created.ID, got.ID)
		require.Equal(t, "lenient", got.OriginTLSMode)
		require.Equal(t, []string{"5.5.5.5"}, got.OriginHosts)
		require.Equal(t, []string{"CN", "RU"}, got.GeoipDeniedCountries)
		require.Equal(t, "blocking", got.ModsecState)
	})

	t.Run("WrongTenant_NotFound", func(t *testing.T) {
		_, err := st.GetConnectionFull(ctx, 2, created.ID)
		var nf *NotFoundError
		require.ErrorAs(t, err, &nf)
	})

	t.Run("NonExistent_NotFound", func(t *testing.T) {
		_, err := st.GetConnectionFull(ctx, 1, 99999)
		var nf *NotFoundError
		require.ErrorAs(t, err, &nf)
	})
}

func TestConnectionGetInternal(t *testing.T) {
	st, ctx := newIntegrationStore(t)

	in := &Connection{
		TenantID: 2, Name: "internal", Domain: "internal.example.com",
		OriginHosts: []string{"10.0.0.1"}, OriginPort: 8080,
		OriginTLSMode: "strict", VerifyToken: "secret", Status: "pending_dns",
		DNSTTLSeconds: 300, HTTPVersions: "h1,h2,h3", CompressionAlgo: "gzip",
		Enabled: true, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
	}
	created, err := st.CreateConnection(ctx, in)
	require.NoError(t, err)

	got, err := st.GetConnectionInternal(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, created.ID, got.ID)
	require.Equal(t, int64(2), got.TenantID)
	require.Equal(t, "pending_dns", got.Status)
	require.Equal(t, 8080, got.OriginPort)
}

func TestConnectionUpdate_Partial(t *testing.T) {
	st, ctx := newIntegrationStore(t)

	in := &Connection{
		TenantID: 1, Name: "orig", Domain: "update.example.com",
		OriginHosts: []string{"1.1.1.1"}, OriginPort: 443,
		OriginTLSMode: "strict", VerifyToken: "v", Status: "active",
		DNSTTLSeconds: 60, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: true, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
	}
	created, err := st.CreateConnection(ctx, in)
	require.NoError(t, err)

	newName := "renamed"
	newPort := 8443
	updated, err := st.UpdateConnection(ctx, 1, created.ID, ConnectionUpdate{
		Name:       &newName,
		OriginPort: &newPort,
	})
	require.NoError(t, err)
	require.Equal(t, "renamed", updated.Name)
	require.Equal(t, 8443, updated.OriginPort)
	// Unchanged fields must be preserved.
	require.Equal(t, "strict", updated.OriginTLSMode)
	require.Equal(t, []string{"1.1.1.1"}, updated.OriginHosts)
}

func TestConnectionUpdate_WrongTenant_NotFound(t *testing.T) {
	st, ctx := newIntegrationStore(t)

	in := &Connection{
		TenantID: 1, Name: "x", Domain: "x.example.com",
		OriginHosts: []string{"2.2.2.2"}, OriginPort: 443,
		OriginTLSMode: "strict", VerifyToken: "v", Status: "active",
		DNSTTLSeconds: 60, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: true, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
	}
	created, err := st.CreateConnection(ctx, in)
	require.NoError(t, err)

	newName := "hacked"
	_, err = st.UpdateConnection(ctx, 2, created.ID, ConnectionUpdate{Name: &newName})
	var nf *NotFoundError
	require.ErrorAs(t, err, &nf)
}

func TestConnectionDelete(t *testing.T) {
	st, ctx := newIntegrationStore(t)

	in := &Connection{
		TenantID: 1, Name: "del", Domain: "del.example.com",
		OriginHosts: []string{"3.3.3.3"}, OriginPort: 443,
		OriginTLSMode: "strict", VerifyToken: "v", Status: "active",
		DNSTTLSeconds: 60, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: true, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
	}
	created, err := st.CreateConnection(ctx, in)
	require.NoError(t, err)

	// Deleting from wrong tenant must return NotFound.
	err = st.DeleteConnection(ctx, 2, created.ID)
	var nf *NotFoundError
	require.ErrorAs(t, err, &nf)

	// Correct tenant deletes successfully.
	err = st.DeleteConnection(ctx, 1, created.ID)
	require.NoError(t, err)

	// Subsequent delete → NotFound.
	err = st.DeleteConnection(ctx, 1, created.ID)
	require.ErrorAs(t, err, &nf)
}

func TestConnectionUpdateSecurity(t *testing.T) {
	st, ctx := newIntegrationStore(t)

	in := &Connection{
		TenantID: 1, Name: "sec", Domain: "sec.example.com",
		OriginHosts: []string{"4.4.4.4"}, OriginPort: 443,
		OriginTLSMode: "strict", VerifyToken: "v", Status: "active",
		DNSTTLSeconds: 60, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: true, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
	}
	created, err := st.CreateConnection(ctx, in)
	require.NoError(t, err)

	updated, err := st.UpdateSecurity(ctx, 1, created.ID, "blocking", []string{"CN", "KP"}, false)
	require.NoError(t, err)
	require.Equal(t, "blocking", updated.ModsecState)
	require.Equal(t, []string{"CN", "KP"}, updated.GeoipDeniedCountries)
	require.False(t, updated.CrowdsecActive)
}

func TestListConnectionsForPoll(t *testing.T) {
	st, ctx := newIntegrationStore(t)

	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)

	// Row due for poll (next_poll_at in past).
	due := &Connection{
		TenantID: 1, Name: "due", Domain: "due.example.com",
		OriginHosts: []string{"1.1.1.1"}, OriginPort: 443,
		OriginTLSMode: "strict", VerifyToken: "v", Status: "pending_verification",
		DNSTTLSeconds: 60, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: true, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
		NextPollAt: &past,
	}
	_, err := st.CreateConnection(ctx, due)
	require.NoError(t, err)

	// Row NOT due (next_poll_at in future).
	notDue := &Connection{
		TenantID: 1, Name: "notdue", Domain: "notdue.example.com",
		OriginHosts: []string{"2.2.2.2"}, OriginPort: 443,
		OriginTLSMode: "strict", VerifyToken: "w", Status: "pending_dns",
		DNSTTLSeconds: 60, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: true, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
		NextPollAt: &future,
	}
	_, err = st.CreateConnection(ctx, notDue)
	require.NoError(t, err)

	// Active row — must not appear (poller skips active).
	active := &Connection{
		TenantID: 1, Name: "active", Domain: "active.example.com",
		OriginHosts: []string{"3.3.3.3"}, OriginPort: 443,
		OriginTLSMode: "strict", VerifyToken: "z", Status: "active",
		DNSTTLSeconds: 60, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: true, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
	}
	_, err = st.CreateConnection(ctx, active)
	require.NoError(t, err)

	// Disabled row — must not appear.
	disabled := &Connection{
		TenantID: 1, Name: "disabled", Domain: "disabled.example.com",
		OriginHosts: []string{"4.4.4.4"}, OriginPort: 443,
		OriginTLSMode: "strict", VerifyToken: "d", Status: "pending_verification",
		DNSTTLSeconds: 60, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: false, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
	}
	_, err = st.CreateConnection(ctx, disabled)
	require.NoError(t, err)

	rows, err := st.ListConnectionsForPoll(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1, "only the 'due' row should be returned")
	require.Equal(t, "due.example.com", rows[0].Domain)
}

func TestListConnectionsForPoll_NullNextPollAt(t *testing.T) {
	st, ctx := newIntegrationStore(t)

	// next_poll_at IS NULL → due (poller picks it up immediately).
	c := &Connection{
		TenantID: 1, Name: "nullpoll", Domain: "nullpoll.example.com",
		OriginHosts: []string{"5.5.5.5"}, OriginPort: 443,
		OriginTLSMode: "strict", VerifyToken: "t", Status: "pending_verification",
		DNSTTLSeconds: 60, HTTPVersions: "h1,h2", CompressionAlgo: "auto",
		Enabled: true, ModsecState: "detection_only", CrowdsecActive: true,
		GeoipDeniedCountries: []string{},
		// NextPollAt left nil
	}
	_, err := st.CreateConnection(ctx, c)
	require.NoError(t, err)

	rows, err := st.ListConnectionsForPoll(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "nullpoll.example.com", rows[0].Domain)
}
