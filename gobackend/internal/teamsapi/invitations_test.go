package teamsapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	"github.com/zwarder/waf/gobackend/internal/store"
)

func adminStore() *fakeStore {
	return &fakeStore{
		memberships: map[int64]string{1: "owner"},
		usersByID:   map[int64]*store.User{1: {ID: 1, Email: "owner@t.test"}},
		users:       map[string]*store.User{"owner@t.test": {ID: 1, Email: "owner@t.test"}},
		tenantNames: map[int64]string{1: "Team One"},
	}
}

func svcWithMailer(f *fakeStore) (*Service, *fakeMailer) {
	m := &fakeMailer{}
	return New(f, m, "https://waf.test", slog.New(slog.NewTextHandler(io.Discard, nil))), m
}

func TestCreateInvitationRequiresAdmin(t *testing.T) {
	f := adminStore()
	f.memberships = map[int64]string{1: "member"}
	svc, _ := svcWithMailer(f)
	_, err := svc.CreateInvitation(ctxWithUser(1, 1), &teamsv1.CreateInvitationRequest{Email: "x@y.test", Role: "member"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCreateInvitationSendsAndStores(t *testing.T) {
	f := adminStore()
	svc, mail := svcWithMailer(f)
	inv, err := svc.CreateInvitation(ctxWithUser(1, 1), &teamsv1.CreateInvitationRequest{Email: " New@Y.Test ", Role: "member"})
	require.NoError(t, err)
	assert.Equal(t, "new@y.test", inv.Email)
	assert.Equal(t, "pending", inv.Status)
	assert.Equal(t, []string{"new@y.test"}, mail.sent)
}

func TestCreateInvitationReturnsAcceptURLAndDeliveryStatus(t *testing.T) {
	// accept_url is always returned so an admin can share the link manually;
	// email_sent is true only when SMTP is configured and the send succeeded.
	t.Run("configured and sent", func(t *testing.T) {
		f := adminStore()
		svc, mail := svcWithMailer(f)
		mail.configured = true
		inv, err := svc.CreateInvitation(ctxWithUser(1, 1), &teamsv1.CreateInvitationRequest{Email: "a@y.test", Role: "member"})
		require.NoError(t, err)
		assert.Contains(t, inv.AcceptUrl, "https://waf.test/invite/accept?token=")
		assert.True(t, inv.EmailSent)
	})
	t.Run("not configured", func(t *testing.T) {
		f := adminStore()
		svc, mail := svcWithMailer(f)
		mail.configured = false
		inv, err := svc.CreateInvitation(ctxWithUser(1, 1), &teamsv1.CreateInvitationRequest{Email: "b@y.test", Role: "member"})
		require.NoError(t, err)
		assert.Contains(t, inv.AcceptUrl, "https://waf.test/invite/accept?token=")
		assert.False(t, inv.EmailSent)
	})
	t.Run("send fails but invite still created", func(t *testing.T) {
		f := adminStore()
		svc, mail := svcWithMailer(f)
		mail.configured = true
		mail.sendErr = errors.New("smtp dial timeout")
		inv, err := svc.CreateInvitation(ctxWithUser(1, 1), &teamsv1.CreateInvitationRequest{Email: "c@y.test", Role: "member"})
		require.NoError(t, err)
		assert.Equal(t, "pending", inv.Status)
		assert.NotEmpty(t, inv.AcceptUrl)
		assert.False(t, inv.EmailSent)
	})
}

func TestCreateInvitationResendsWhenPending(t *testing.T) {
	f := adminStore()
	svc, mail := svcWithMailer(f)
	_, err := svc.CreateInvitation(ctxWithUser(1, 1), &teamsv1.CreateInvitationRequest{Email: "dup@y.test", Role: "member"})
	require.NoError(t, err)
	_, err = svc.CreateInvitation(ctxWithUser(1, 1), &teamsv1.CreateInvitationRequest{Email: "dup@y.test", Role: "member"})
	require.NoError(t, err)
	require.Len(t, f.invites, 1)
	assert.Len(t, mail.sent, 2)
}

func TestPreviewInvitation(t *testing.T) {
	f := adminStore()
	raw := "previewtok"
	sum := sha256.Sum256([]byte(raw))
	f.invites = map[int64]*store.Invitation{9: {
		ID: 9, TenantID: 1, Email: "preview@y.test", Role: "admin", Status: "pending",
		TokenHash: hex.EncodeToString(sum[:]),
	}}
	svc, _ := svcWithMailer(f)

	// Public call (no identity in ctx) returns team/role/email for a valid token.
	out, err := svc.PreviewInvitation(context.Background(), &teamsv1.PreviewInvitationRequest{Token: raw})
	require.NoError(t, err)
	assert.True(t, out.Valid)
	assert.Equal(t, "Team One", out.TeamName)
	assert.Equal(t, "admin", out.Role)
	assert.Equal(t, "preview@y.test", out.Email)

	// Unknown token → valid=false, no error, no detail leaked.
	bad, err := svc.PreviewInvitation(context.Background(), &teamsv1.PreviewInvitationRequest{Token: "nope"})
	require.NoError(t, err)
	assert.False(t, bad.Valid)
	assert.Empty(t, bad.TeamName)
}

func TestPreviewInvitationReportsAccountExists(t *testing.T) {
	f := adminStore()
	raw := "previewtok2"
	sum := sha256.Sum256([]byte(raw))
	f.invites = map[int64]*store.Invitation{10: {
		ID: 10, TenantID: 1, Email: "known@y.test", Role: "member", Status: "pending",
		TokenHash: hex.EncodeToString(sum[:]),
	}}
	svc, _ := svcWithMailer(f)

	// No user with that email yet → account_exists false.
	out, err := svc.PreviewInvitation(context.Background(), &teamsv1.PreviewInvitationRequest{Token: raw})
	require.NoError(t, err)
	require.True(t, out.Valid)
	require.False(t, out.AccountExists)

	// Seed a user with the invited email → account_exists true.
	f.users["known@y.test"] = &store.User{ID: 2, Email: "known@y.test"}
	out2, err := svc.PreviewInvitation(context.Background(), &teamsv1.PreviewInvitationRequest{Token: raw})
	require.NoError(t, err)
	require.True(t, out2.AccountExists)
}

func TestAcceptInvitationMatchesEmail(t *testing.T) {
	f := adminStore()
	f.usersByID[2] = &store.User{ID: 2, Email: "joiner@y.test"}
	raw := "tok123"
	sum := sha256.Sum256([]byte(raw))
	f.invites = map[int64]*store.Invitation{7: {ID: 7, TenantID: 1, Email: "joiner@y.test", Role: "member", Status: "pending", TokenHash: hex.EncodeToString(sum[:])}}
	svc, _ := svcWithMailer(f)

	_, err := svc.AcceptInvitation(ctxWithUser(1, 1), &teamsv1.AcceptInvitationRequest{Token: raw})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = svc.AcceptInvitation(ctxWithUser(2, 0), &teamsv1.AcceptInvitationRequest{Token: raw})
	require.NoError(t, err)
	assert.Equal(t, "accepted", f.invites[7].Status)
	assert.Equal(t, "member", f.memberships[1])
}

func TestRevokeRequiresAdmin(t *testing.T) {
	f := adminStore()
	f.invites = map[int64]*store.Invitation{3: {ID: 3, TenantID: 1, Email: "x@y.test", Status: "pending"}}
	f.memberships = map[int64]string{1: "member"}
	svc, _ := svcWithMailer(f)
	_, err := svc.RevokeInvitation(ctxWithUser(1, 1), &teamsv1.InvitationIdRequest{Id: 3})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

