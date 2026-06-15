package teamsapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// fakeNotifier records notification emit calls for assertion in tests.
type fakeNotifier struct {
	mu    sync.Mutex
	calls []notifyCall
}

type notifyCall struct {
	method   string // "user" or "members"
	userID   int64
	tenantID *int64
	typ      string
}

func (n *fakeNotifier) NotifyUser(_ context.Context, userID int64, tenantID *int64, typ, _, _ string, _ map[string]any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, notifyCall{method: "user", userID: userID, tenantID: tenantID, typ: typ})
	return nil
}

func (n *fakeNotifier) NotifyTenantMembers(_ context.Context, tenantID, excludeUserID int64, typ, _, _ string, _ map[string]any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, notifyCall{method: "members", userID: excludeUserID, tenantID: &tenantID, typ: typ})
	return nil
}

func (n *fakeNotifier) findType(typ string) (notifyCall, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.calls {
		if c.typ == typ {
			return c, true
		}
	}
	return notifyCall{}, false
}

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
	return New(f, m, "https://waf.test", slog.New(slog.NewTextHandler(io.Discard, nil)), nil), m
}

func svcWithNotifier(f *fakeStore, n *fakeNotifier) *Service {
	return New(f, &fakeMailer{}, "https://waf.test", slog.New(slog.NewTextHandler(io.Discard, nil)), n)
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

// ── Notification tests ──────────────────────────────────────────────────────

func TestCreateInvitation_NotifiesRegisteredUser(t *testing.T) {
	// Use memberRoles so membership lookups are per-userID, not per-tenantID.
	// User 1 (owner) is a member; user 99 (invited) is not.
	f := &fakeStore{
		memberRoles: map[int64]string{1: "owner"},
		usersByID: map[int64]*store.User{
			1:  {ID: 1, Email: "owner@t.test"},
			99: {ID: 99, Email: "invited@y.test"},
		},
		users: map[string]*store.User{
			"owner@t.test":   {ID: 1, Email: "owner@t.test"},
			"invited@y.test": {ID: 99, Email: "invited@y.test"},
		},
		tenantNames: map[int64]string{1: "Team One"},
	}
	n := &fakeNotifier{}
	svc := svcWithNotifier(f, n)

	_, err := svc.CreateInvitation(ctxWithUser(1, 1), &teamsv1.CreateInvitationRequest{Email: "invited@y.test", Role: "member"})
	require.NoError(t, err)

	call, ok := n.findType("team.invitation")
	require.True(t, ok, "expected team.invitation notification")
	assert.Equal(t, int64(99), call.userID)
}

func TestCreateInvitation_NoNotifyForUnknownEmail(t *testing.T) {
	f := adminStore()
	// "unknown@y.test" has no account.
	n := &fakeNotifier{}
	svc := svcWithNotifier(f, n)

	_, err := svc.CreateInvitation(ctxWithUser(1, 1), &teamsv1.CreateInvitationRequest{Email: "unknown@y.test", Role: "member"})
	require.NoError(t, err)

	_, ok := n.findType("team.invitation")
	assert.False(t, ok, "no notification expected for unregistered email")
}

func TestAcceptInvitationById_MatchingEmail_AcceptsAndNotifies(t *testing.T) {
	f := adminStore()
	f.usersByID[2] = &store.User{ID: 2, Email: "joiner@y.test"}
	f.invites = map[int64]*store.Invitation{
		42: {ID: 42, TenantID: 1, Email: "joiner@y.test", Role: "member", Status: "pending"},
	}
	f.members = []store.TeamMember{{UserID: 1, Email: "owner@t.test"}}
	n := &fakeNotifier{}
	svc := svcWithNotifier(f, n)

	_, err := svc.AcceptInvitationById(ctxWithUser(2, 0), &teamsv1.InvitationIdRequest{Id: 42})
	require.NoError(t, err)
	assert.Equal(t, "accepted", f.invites[42].Status)

	call, ok := n.findType("team.member_joined")
	require.True(t, ok, "expected team.member_joined notification")
	assert.Equal(t, int64(2), call.userID) // excludeUserID = joiner
}

func TestAcceptInvitationById_WrongEmail_PermissionDenied(t *testing.T) {
	f := adminStore()
	// User 1 is "owner@t.test" but invitation is for "other@y.test".
	f.invites = map[int64]*store.Invitation{
		55: {ID: 55, TenantID: 1, Email: "other@y.test", Role: "member", Status: "pending"},
	}
	svc := svcWithNotifier(f, &fakeNotifier{})

	_, err := svc.AcceptInvitationById(ctxWithUser(1, 1), &teamsv1.InvitationIdRequest{Id: 55})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
