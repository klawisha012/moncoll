package teamsapi

import (
	"crypto/sha256"
	"encoding/hex"
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

