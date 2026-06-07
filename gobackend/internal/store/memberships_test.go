//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedTenantUser(t *testing.T, st *Store, slug, email string) (tenantID, userID int64) {
	t.Helper()
	ctx := context.Background()
	ten, err := st.CreateTenant(ctx, slug, slug)
	require.NoError(t, err)
	role := "owner"
	u, err := st.CreateUser(ctx, &User{
		Email:        email,
		DisplayName:  email,
		PlatformRole: "client",
		TenantID:     &ten.ID,
		TenantRole:   &role,
	})
	require.NoError(t, err)
	return ten.ID, u.ID
}

func TestMembershipCRUD(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()
	tenantID, userID := seedTenantUser(t, st, "acme", "owner@acme.test")

	require.NoError(t, st.CreateMembership(ctx, tenantID, userID, "owner"))
	require.NoError(t, st.CreateMembership(ctx, tenantID, userID, "owner"))

	got, err := st.GetMembership(ctx, userID, tenantID)
	require.NoError(t, err)
	assert.Equal(t, "owner", got.Role)
	assert.Equal(t, tenantID, got.TenantID)

	_, err = st.GetMembership(ctx, userID, 999999)
	var nf *NotFoundError
	assert.ErrorAs(t, err, &nf)
}

func TestListMyTeamsAndSwitch(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()
	t1, userID := seedTenantUser(t, st, "alpha", "u@alpha.test")
	t2, _ := seedTenantUser(t, st, "beta", "owner@beta.test")

	require.NoError(t, st.CreateMembership(ctx, t1, userID, "owner"))
	require.NoError(t, st.CreateMembership(ctx, t2, userID, "member"))

	teams, err := st.ListMyTeams(ctx, userID)
	require.NoError(t, err)
	require.Len(t, teams, 2)

	require.NoError(t, st.SetActiveTenant(ctx, userID, t2))
	u, err := st.GetUserByID(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, u.TenantID)
	assert.Equal(t, t2, *u.TenantID)
}

func TestBackfillCreatesMembership(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()
	tenantID, userID := seedTenantUser(t, st, "legacy", "old@legacy.test")
	_, err := st.pool.Exec(ctx, `
		INSERT INTO memberships (tenant_id, user_id, role)
		SELECT tenant_id, id, COALESCE(tenant_role::text, 'owner')::membership_role
		FROM users WHERE tenant_id IS NOT NULL
		ON CONFLICT (tenant_id, user_id) DO NOTHING`)
	require.NoError(t, err)

	got, err := st.GetMembership(ctx, userID, tenantID)
	require.NoError(t, err)
	assert.Equal(t, "owner", got.Role)
}
