//go:build integration

package store

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zwarder/waf/gobackend/internal/migrate"
)

// TestConnectionsRLS_TenantIsolation proves the 0007 Row-Level Security policy
// scopes connections to the tenant set in app.tenant_id, as a backstop beneath
// the app-level WHERE tenant_id filters. RLS only binds a non-superuser role
// (superusers always bypass it), so the assertions run through a dedicated
// non-superuser role connected via Store.RunInTenantTx.
func TestConnectionsRLS_TenantIsolation(t *testing.T) {
	ctx := context.Background()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err, "connect to Docker")
	res, err := pool.Run("postgres", "16", []string{"POSTGRES_PASSWORD=pw", "POSTGRES_DB=waf"})
	require.NoError(t, err, "start postgres")
	t.Cleanup(func() { _ = pool.Purge(res) })
	port := res.GetPort("5432/tcp")
	superDSN := fmt.Sprintf("postgres://postgres:pw@localhost:%s/waf?sslmode=disable", port)

	var super *Store
	require.NoError(t, pool.Retry(func() error {
		s, e := New(ctx, superDSN)
		if e != nil {
			return e
		}
		if e = s.pool.Ping(ctx); e != nil {
			return e
		}
		super = s
		return nil
	}), "wait for postgres")
	t.Cleanup(super.Close)

	require.NoError(t, migrate.Run(superDSN, slog.Default()), "run migrations")

	// Seed two tenants and a connection each (as superuser → RLS bypassed).
	mkTenant := func(name string) int64 {
		var id int64
		require.NoError(t, super.pool.QueryRow(ctx,
			`INSERT INTO tenants (name, display_name) VALUES ($1, $1) RETURNING id`, name).Scan(&id))
		return id
	}
	mkConn := func(tenantID int64, domain string) int64 {
		var id int64
		require.NoError(t, super.pool.QueryRow(ctx,
			`INSERT INTO connections (tenant_id, name, domain) VALUES ($1, $2, $3) RETURNING id`,
			tenantID, domain, domain).Scan(&id))
		return id
	}
	tenantA := mkTenant("tenant-a")
	tenantB := mkTenant("tenant-b")
	mkConn(tenantA, "a.example.com")
	connB := mkConn(tenantB, "b.example.com")

	// A non-superuser role that RLS actually binds.
	for _, stmt := range []string{
		`CREATE ROLE rls_app LOGIN PASSWORD 'rlspw' NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO rls_app`,
		`GRANT SELECT ON connections TO rls_app`,
	} {
		_, err := super.pool.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	rlsDSN := fmt.Sprintf("postgres://rls_app:rlspw@localhost:%s/waf?sslmode=disable", port)
	rlsStore, err := New(ctx, rlsDSN)
	require.NoError(t, err, "connect as rls_app")
	t.Cleanup(rlsStore.Close)

	// (1) With tenant context set, a query WITHOUT a WHERE tenant_id returns only
	// that tenant's rows — the RLS backstop in action.
	var scoped int
	require.NoError(t, rlsStore.RunInTenantTx(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM connections`).Scan(&scoped)
	}))
	assert.Equal(t, 1, scoped, "with app.tenant_id=A, only A's connection is visible")

	// (2) Without tenant context, the non-superuser sees all rows (the permissive
	// backstop preserves system/admin/poller behaviour).
	var all int
	require.NoError(t, rlsStore.pool.QueryRow(ctx, `SELECT count(*) FROM connections`).Scan(&all))
	assert.Equal(t, 2, all, "no tenant context → all rows visible")

	// (3) RLS hides another tenant's row even from an unfiltered id lookup.
	require.NoError(t, rlsStore.RunInTenantTx(ctx, tenantA, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM connections WHERE id=$1`, connB).Scan(&n); err != nil {
			return err
		}
		assert.Equal(t, 0, n, "tenant A cannot see tenant B's connection under RLS")
		return nil
	}))

	// (4) App-level scoping is retained (independent of RLS): tenant A fetching
	// tenant B's connection returns NotFound, no existence leak.
	_, err = super.GetConnectionForTenant(ctx, connB, tenantA)
	var nfe *NotFoundError
	assert.ErrorAs(t, err, &nfe, "cross-tenant GetConnectionForTenant must be NotFound")
}
