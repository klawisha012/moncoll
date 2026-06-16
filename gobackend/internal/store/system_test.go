//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

func systemTestStore(t *testing.T) (*Store, context.Context) {
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
	_, err = st.pool.Exec(ctx, `
		CREATE TABLE tenants (id SERIAL PRIMARY KEY, name VARCHAR(32) NOT NULL UNIQUE,
			display_name VARCHAR(64) NOT NULL, suspended_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
		CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT NOT NULL, platform_role TEXT NOT NULL DEFAULT 'client',
			tenant_role TEXT, tenant_id INTEGER);
		CREATE TABLE memberships (id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
			role TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (tenant_id, user_id));`)
	require.NoError(t, err)
	return st, ctx
}

func TestEnsureSystemTenantIdempotent(t *testing.T) {
	st, ctx := systemTestStore(t)

	first, err := st.EnsureSystemTenant(ctx)
	require.NoError(t, err)
	require.Equal(t, "system", first.Name)

	second, err := st.EnsureSystemTenant(ctx)
	require.NoError(t, err)
	require.Equal(t, first.ID, second.ID, "second call must return the same tenant, not create a new one")

	var count int
	require.NoError(t, st.pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE name='system'`).Scan(&count))
	require.Equal(t, 1, count)
}

func TestBackfillAdminsIntoSystemTenant(t *testing.T) {
	st, ctx := systemTestStore(t)
	sys, err := st.EnsureSystemTenant(ctx)
	require.NoError(t, err)

	_, err = st.pool.Exec(ctx, `
		INSERT INTO users (id, email, platform_role, tenant_id) VALUES
		  (1, 'admin1@test', 'admin', NULL),
		  (2, 'admin2@test', 'admin', 999),
		  (3, 'client@test', 'client', NULL);
	`)
	require.NoError(t, err)

	require.NoError(t, st.BackfillAdminsIntoSystemTenant(ctx, sys.ID))
	require.NoError(t, st.BackfillAdminsIntoSystemTenant(ctx, sys.ID)) // idempotent

	var t1 *int64
	require.NoError(t, st.pool.QueryRow(ctx, `SELECT tenant_id FROM users WHERE id=1`).Scan(&t1))
	require.NotNil(t, t1)
	require.Equal(t, sys.ID, *t1)

	var t2 *int64
	require.NoError(t, st.pool.QueryRow(ctx, `SELECT tenant_id FROM users WHERE id=2`).Scan(&t2))
	require.NotNil(t, t2)
	require.Equal(t, int64(999), *t2) // not clobbered

	var members int
	require.NoError(t, st.pool.QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE tenant_id=$1 AND role='owner'`, sys.ID).Scan(&members))
	require.Equal(t, 2, members)

	var clientMember int
	require.NoError(t, st.pool.QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE tenant_id=$1 AND user_id=3`, sys.ID).Scan(&clientMember))
	require.Equal(t, 0, clientMember)
}

func TestSystemTenantProtectedFromSuspendDelete(t *testing.T) {
	st, ctx := systemTestStore(t)
	sys, err := st.EnsureSystemTenant(ctx)
	require.NoError(t, err)

	_, err = st.SuspendTenant(ctx, sys.ID)
	require.ErrorIs(t, err, ErrSystemTenantProtected)
	require.ErrorIs(t, st.DeleteTenant(ctx, sys.ID), ErrSystemTenantProtected)

	// A normal tenant is still suspendable.
	other, err := st.CreateTenant(ctx, "acme", "Acme")
	require.NoError(t, err)
	_, err = st.SuspendTenant(ctx, other.ID)
	require.NoError(t, err)
}
