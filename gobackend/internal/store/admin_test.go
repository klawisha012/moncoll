//go:build integration

package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

// seedSchema creates the tables and seed rows used by both test functions.
func seedSchema(t *testing.T, st *Store, ctx context.Context) {
	t.Helper()
	_, err := st.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS tenants (id BIGINT PRIMARY KEY, name TEXT NOT NULL, display_name TEXT NOT NULL,
		    suspended_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
		CREATE TABLE IF NOT EXISTS users (id BIGINT PRIMARY KEY, email TEXT NOT NULL, tenant_role TEXT,
		    last_login_at TIMESTAMPTZ, email_verified_at TIMESTAMPTZ, totp_enabled_at TIMESTAMPTZ, tenant_id BIGINT);
		CREATE TABLE IF NOT EXISTS connections (id BIGINT PRIMARY KEY, tenant_id BIGINT NOT NULL, name TEXT NOT NULL,
		    domain TEXT NOT NULL, status TEXT NOT NULL);
	`)
	require.NoError(t, err)
}

func TestAdminQueries(t *testing.T) {
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
	seedSchema(t, st, ctx)
	_, err = st.pool.Exec(ctx, `
		INSERT INTO tenants (id,name,display_name,suspended_at) VALUES (3,'acme','Acme',NULL),(4,'beta','Beta',now());
		INSERT INTO users (id,email,tenant_role,last_login_at,email_verified_at,totp_enabled_at,tenant_id) VALUES
		  (10,'owner@acme.test','owner','2026-01-02T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',3),
		  (11,'member@acme.test','member','2026-01-03T00:00:00Z',NULL,NULL,3);
		INSERT INTO connections (id,tenant_id,name,domain,status) VALUES (100,3,'web','acme.test','active');
	`)
	require.NoError(t, err)

	t.Run("ListTenantSummaries", func(t *testing.T) {
		summaries, err := st.ListTenantSummaries(ctx)
		require.NoError(t, err)
		require.Len(t, summaries, 2)

		// find by id
		byID := make(map[int64]TenantSummary, len(summaries))
		for _, s := range summaries {
			byID[s.ID] = s
		}

		acme := byID[3]
		require.Equal(t, "acme", acme.Name)
		require.NotNil(t, acme.OwnerEmail)
		require.Equal(t, "owner@acme.test", *acme.OwnerEmail)
		require.Equal(t, int64(2), acme.UserCount)
		require.Equal(t, int64(1), acme.ConnectionCount)
		require.NotNil(t, acme.LastActivity)
		// max last_login_at is 2026-01-03
		expected := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
		require.True(t, acme.LastActivity.Equal(expected),
			"expected LastActivity %v, got %v", expected, *acme.LastActivity)
		require.Nil(t, acme.SuspendedAt)

		beta := byID[4]
		require.Equal(t, int64(0), beta.UserCount)
		require.Nil(t, beta.OwnerEmail)
		require.NotNil(t, beta.SuspendedAt)
	})

	t.Run("GetTenantDetail", func(t *testing.T) {
		detail, err := st.GetTenantDetail(ctx, 3)
		require.NoError(t, err)
		require.NotNil(t, detail)
		require.Equal(t, "acme", detail.Tenant.Name)
		require.Len(t, detail.Users, 2)
		require.Len(t, detail.Connections, 1)
		require.Equal(t, "acme.test", detail.Connections[0].Domain)

		// find owner user
		var owner *TenantUser
		for i := range detail.Users {
			if detail.Users[i].TenantRole != nil && *detail.Users[i].TenantRole == "owner" {
				owner = &detail.Users[i]
				break
			}
		}
		require.NotNil(t, owner)
		require.True(t, owner.EmailVerified)
		require.True(t, owner.TotpEnabled)
	})

	t.Run("GetTenantDetail_NotFound", func(t *testing.T) {
		detail, err := st.GetTenantDetail(ctx, 999)
		require.NoError(t, err)
		require.Nil(t, detail)
	})
}

func TestTenantWrites(t *testing.T) {
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
	seedSchema(t, st, ctx)
	_, err = st.pool.Exec(ctx, `
		INSERT INTO tenants (id,name,display_name,suspended_at) VALUES (3,'acme','Acme',NULL),(4,'beta','Beta',now());
	`)
	require.NoError(t, err)

	t.Run("SuspendTenant", func(t *testing.T) {
		tenant, err := st.SuspendTenant(ctx, 3)
		require.NoError(t, err)
		require.NotNil(t, tenant)
		require.Equal(t, "acme", tenant.Name)
		require.NotNil(t, tenant.SuspendedAt)
	})

	t.Run("UnsuspendTenant", func(t *testing.T) {
		tenant, err := st.UnsuspendTenant(ctx, 3)
		require.NoError(t, err)
		require.NotNil(t, tenant)
		require.Nil(t, tenant.SuspendedAt)
	})

	t.Run("DeleteTenant", func(t *testing.T) {
		err := st.DeleteTenant(ctx, 4)
		require.NoError(t, err)

		_, err = st.GetTenantByID(ctx, 4)
		var nfe *NotFoundError
		require.True(t, errors.As(err, &nfe), "expected *NotFoundError, got %v", err)
	})

	t.Run("DeleteTenant_NotFound", func(t *testing.T) {
		err := st.DeleteTenant(ctx, 999)
		var nfe *NotFoundError
		require.True(t, errors.As(err, &nfe), "expected *NotFoundError, got %v", err)
	})

	t.Run("SuspendTenant_NotFound", func(t *testing.T) {
		_, err := st.SuspendTenant(ctx, 999)
		var nfe *NotFoundError
		require.True(t, errors.As(err, &nfe), "expected *NotFoundError, got %v", err)
	})
}
