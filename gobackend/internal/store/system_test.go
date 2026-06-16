//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsureSystemTenantIdempotent(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

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

// TestBackfillAdminsMembershipOnly is the regression guard for the reverted
// cce36bd bug: the backfill must make admins owner-MEMBERS of the system tenant
// WITHOUT writing users.tenant_id (which the CHECK forbids for admins). Run
// against the REAL migrated schema so the CHECK is actually exercised.
func TestBackfillAdminsMembershipOnly(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	sys, err := st.EnsureSystemTenant(ctx)
	require.NoError(t, err)

	// Two admins (tenant_id NULL per the CHECK) and one client (needs a tenant).
	clientTenant := seedTenant(t, st) // "acme", from auth_store_test.go
	_, err = st.pool.Exec(ctx, `
		INSERT INTO users (email, platform_role) VALUES
		  ('admin1@test', 'admin'),
		  ('admin2@test', 'admin')`)
	require.NoError(t, err)
	_, err = st.pool.Exec(ctx, `
		INSERT INTO users (email, platform_role, tenant_id, tenant_role)
		VALUES ('client@test', 'client', $1, 'owner')`, clientTenant)
	require.NoError(t, err)

	require.NoError(t, st.BackfillAdminsIntoSystemTenant(ctx, sys.ID))
	require.NoError(t, st.BackfillAdminsIntoSystemTenant(ctx, sys.ID)) // idempotent

	// Admins must remain tenant-less in the users table (invariant intact).
	var adminsWithTenant int
	require.NoError(t, st.pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE platform_role='admin' AND tenant_id IS NOT NULL`).Scan(&adminsWithTenant))
	require.Equal(t, 0, adminsWithTenant, "admins must keep tenant_id NULL — backfill must be membership-only")

	// Both admins are owner-members of the system tenant.
	var owners int
	require.NoError(t, st.pool.QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE tenant_id=$1 AND role='owner'`, sys.ID).Scan(&owners))
	require.Equal(t, 2, owners)

	// The client is NOT enrolled into the system tenant.
	var clientInSystem int
	require.NoError(t, st.pool.QueryRow(ctx,
		`SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id
		 WHERE m.tenant_id=$1 AND u.email='client@test'`, sys.ID).Scan(&clientInSystem))
	require.Equal(t, 0, clientInSystem)
}

func TestSystemTenantProtectedFromSuspendDelete(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	sys, err := st.EnsureSystemTenant(ctx)
	require.NoError(t, err)

	_, err = st.SuspendTenant(ctx, sys.ID)
	require.ErrorIs(t, err, ErrSystemTenantProtected)
	require.ErrorIs(t, st.DeleteTenant(ctx, sys.ID), ErrSystemTenantProtected)

	// A normal tenant is still suspendable/deletable.
	other, err := st.CreateTenant(ctx, "acme", "Acme")
	require.NoError(t, err)
	_, err = st.SuspendTenant(ctx, other.ID)
	require.NoError(t, err)
}
