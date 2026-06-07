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

func TestMemberManagement(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()
	tid, ownerID := seedTenantUser(t, st, "mgmt", "owner@mgmt.test")
	_, memberID := seedTenantUser(t, st, "mgmt-personal", "member@mgmt.test")
	require.NoError(t, st.CreateMembership(ctx, tid, ownerID, "owner"))
	require.NoError(t, st.CreateMembership(ctx, tid, memberID, "member"))

	members, err := st.ListMembersForTenant(ctx, tid)
	require.NoError(t, err)
	require.Len(t, members, 2)
	assert.Equal(t, "owner", members[0].Role)

	n, err := st.CountOwners(ctx, tid)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	require.NoError(t, st.UpdateMembershipRole(ctx, tid, memberID, "admin"))
	m, err := st.GetMembership(ctx, memberID, tid)
	require.NoError(t, err)
	assert.Equal(t, "admin", m.Role)

	require.NoError(t, st.DeleteMembership(ctx, tid, memberID))
	_, err = st.GetMembership(ctx, memberID, tid)
	var nf *NotFoundError
	assert.ErrorAs(t, err, &nf)

	err = st.DeleteMembership(ctx, tid, memberID)
	assert.ErrorAs(t, err, &nf)
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
