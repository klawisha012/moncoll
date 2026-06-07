//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newInvite(tenantID, inviterID int64, email, role, tokenHash string) *Invitation {
	return &Invitation{
		TenantID:        tenantID,
		Email:           email,
		Role:            role,
		TokenHash:       tokenHash,
		InvitedByUserID: inviterID,
		ExpiresAt:       time.Now().UTC().Add(7 * 24 * time.Hour),
	}
}

func TestInvitationCreateAndLookup(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()
	tid, uid := seedTenantUser(t, st, "acme", "owner@acme.test")

	inv, err := st.CreateInvitation(ctx, newInvite(tid, uid, "invitee@x.test", "member", "hash1"))
	require.NoError(t, err)
	assert.Equal(t, "pending", inv.Status)

	_, err = st.CreateInvitation(ctx, newInvite(tid, uid, "invitee@x.test", "member", "hash2"))
	var ce *ConflictError
	assert.ErrorAs(t, err, &ce)

	byHash, err := st.GetInvitationByTokenHash(ctx, "hash1")
	require.NoError(t, err)
	assert.Equal(t, inv.ID, byHash.ID)

	pend, err := st.GetPendingInvitationForEmail(ctx, tid, "invitee@x.test")
	require.NoError(t, err)
	assert.Equal(t, inv.ID, pend.ID)

	incoming, err := st.ListPendingInvitationsForEmail(ctx, "invitee@x.test")
	require.NoError(t, err)
	require.Len(t, incoming, 1)
}

func TestInvitationResendAndRevoke(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()
	tid, uid := seedTenantUser(t, st, "beta", "owner@beta.test")
	inv, err := st.CreateInvitation(ctx, newInvite(tid, uid, "x@y.test", "admin", "h1"))
	require.NoError(t, err)

	newExp := time.Now().UTC().Add(7 * 24 * time.Hour)
	require.NoError(t, st.ResendInvitation(ctx, inv.ID, "h2", newExp))
	got, err := st.GetInvitationByTokenHash(ctx, "h2")
	require.NoError(t, err)
	assert.Equal(t, inv.ID, got.ID)

	require.NoError(t, st.SetInvitationStatus(ctx, inv.ID, "revoked"))
	err = st.SetInvitationStatus(ctx, inv.ID, "revoked")
	var nf *NotFoundError
	assert.ErrorAs(t, err, &nf)
}

func TestInvitationAcceptCreatesMembership(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()
	tid, ownerID := seedTenantUser(t, st, "gamma", "owner@gamma.test")
	_, inviteeID := seedTenantUser(t, st, "gamma-personal", "joiner@x.test")

	inv, err := st.CreateInvitation(ctx, newInvite(tid, ownerID, "joiner@x.test", "member", "h3"))
	require.NoError(t, err)

	require.NoError(t, st.AcceptInvitation(ctx, inv, inviteeID))

	m, err := st.GetMembership(ctx, inviteeID, tid)
	require.NoError(t, err)
	assert.Equal(t, "member", m.Role)

	err = st.AcceptInvitation(ctx, inv, inviteeID)
	var nf *NotFoundError
	assert.ErrorAs(t, err, &nf)
}
