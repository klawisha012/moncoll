package teamsapi

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
)

type fakeStore struct {
	teams       []store.MyTeam
	memberships map[int64]string
	active      int64

	users       map[string]*store.User
	usersByID   map[int64]*store.User
	invites     map[int64]*store.Invitation
	nextInvID   int64
	tenantNames map[int64]string

	members     []store.TeamMember
	memberRoles map[int64]string
	deleted     []int64
	roleUpdates []string
	ownerCount  int
}

func (f *fakeStore) ListMyTeams(_ context.Context, _ int64) ([]store.MyTeam, error) {
	return f.teams, nil
}
func (f *fakeStore) GetMembership(_ context.Context, userID int64, tenantID int64) (*store.Membership, error) {
	if f.memberRoles != nil {
		role, ok := f.memberRoles[userID]
		if !ok {
			return nil, &store.NotFoundError{Entity: "membership"}
		}
		return &store.Membership{TenantID: tenantID, UserID: userID, Role: role}, nil
	}
	role, ok := f.memberships[tenantID]
	if !ok {
		return nil, &store.NotFoundError{Entity: "membership"}
	}
	return &store.Membership{TenantID: tenantID, UserID: 1, Role: role}, nil
}
func (f *fakeStore) SetActiveTenant(_ context.Context, _ int64, tenantID int64) error {
	f.active = tenantID
	return nil
}

func (f *fakeStore) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	if u, ok := f.users[email]; ok {
		return u, nil
	}
	return nil, &store.NotFoundError{Entity: "user"}
}
func (f *fakeStore) GetUserByIDFull(_ context.Context, id int64) (*store.User, error) {
	if u, ok := f.usersByID[id]; ok {
		return u, nil
	}
	return nil, &store.NotFoundError{Entity: "user"}
}
func (f *fakeStore) GetTenantDisplayName(_ context.Context, id int64) (string, error) {
	return f.tenantNames[id], nil
}
func (f *fakeStore) CreateInvitation(_ context.Context, inv *store.Invitation) (*store.Invitation, error) {
	for _, e := range f.invites {
		if e.TenantID == inv.TenantID && e.Email == inv.Email && e.Status == "pending" {
			return nil, &store.ConflictError{Detail: "pending invitation already exists"}
		}
	}
	f.nextInvID++
	inv.ID = f.nextInvID
	inv.Status = "pending"
	if f.invites == nil {
		f.invites = map[int64]*store.Invitation{}
	}
	cp := *inv
	f.invites[inv.ID] = &cp
	return &cp, nil
}
func (f *fakeStore) GetPendingInvitationForEmail(_ context.Context, tenantID int64, email string) (*store.Invitation, error) {
	for _, e := range f.invites {
		if e.TenantID == tenantID && e.Email == email && e.Status == "pending" {
			return e, nil
		}
	}
	return nil, &store.NotFoundError{Entity: "invitation"}
}
func (f *fakeStore) GetInvitationByTokenHash(_ context.Context, h string) (*store.Invitation, error) {
	for _, e := range f.invites {
		if e.TokenHash == h && e.Status == "pending" {
			return e, nil
		}
	}
	return nil, &store.NotFoundError{Entity: "invitation"}
}
func (f *fakeStore) GetInvitationByID(_ context.Context, id int64) (*store.Invitation, error) {
	if e, ok := f.invites[id]; ok {
		return e, nil
	}
	return nil, &store.NotFoundError{Entity: "invitation"}
}
func (f *fakeStore) ListInvitationsForTenant(_ context.Context, tenantID int64) ([]store.Invitation, error) {
	var out []store.Invitation
	for _, e := range f.invites {
		if e.TenantID == tenantID {
			out = append(out, *e)
		}
	}
	return out, nil
}
func (f *fakeStore) ListPendingInvitationsForEmail(_ context.Context, email string) ([]store.Invitation, error) {
	var out []store.Invitation
	for _, e := range f.invites {
		if e.Email == email && e.Status == "pending" {
			out = append(out, *e)
		}
	}
	return out, nil
}
func (f *fakeStore) ResendInvitation(_ context.Context, id int64, hash string, exp time.Time) error {
	if e, ok := f.invites[id]; ok && e.Status == "pending" {
		e.TokenHash, e.ExpiresAt = hash, exp
		return nil
	}
	return &store.NotFoundError{Entity: "invitation"}
}
func (f *fakeStore) SetInvitationStatus(_ context.Context, id int64, st string) error {
	if e, ok := f.invites[id]; ok && e.Status == "pending" {
		e.Status = st
		return nil
	}
	return &store.NotFoundError{Entity: "invitation"}
}
func (f *fakeStore) AcceptInvitation(_ context.Context, inv *store.Invitation, userID int64) error {
	e, ok := f.invites[inv.ID]
	if !ok || e.Status != "pending" {
		return &store.NotFoundError{Entity: "invitation"}
	}
	e.Status = "accepted"
	if f.memberships == nil {
		f.memberships = map[int64]string{}
	}
	f.memberships[inv.TenantID] = inv.Role
	return nil
}

func (f *fakeStore) ListMembersForTenant(_ context.Context, _ int64) ([]store.TeamMember, error) {
	return f.members, nil
}
func (f *fakeStore) DeleteMembership(_ context.Context, _ int64, userID int64) error {
	f.deleted = append(f.deleted, userID)
	return nil
}
func (f *fakeStore) UpdateMembershipRole(_ context.Context, _ int64, userID int64, role string) error {
	f.roleUpdates = append(f.roleUpdates, role)
	return nil
}
func (f *fakeStore) CountOwners(_ context.Context, _ int64) (int, error) {
	return f.ownerCount, nil
}

type fakeMailer struct {
	sent       []string
	configured bool
	sendErr    error
}

func (m *fakeMailer) SendInvitationEmail(_ context.Context, to, _, _ string) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, to)
	return nil
}

func (m *fakeMailer) Configured() bool { return m.configured }

func ctxWithUser(userID int64, tenantID int64) context.Context {
	tid := tenantID
	return auth.WithIdentity(context.Background(), &auth.Identity{
		UserID: userID, PlatformRole: "client", TenantID: &tid,
	})
}

func newSvc(f *fakeStore) *Service {
	return New(f, &fakeMailer{}, "https://waf.test", slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
}

func TestListMyTeamsMarksActive(t *testing.T) {
	f := &fakeStore{teams: []store.MyTeam{
		{TenantID: 1, Slug: "alpha", DisplayName: "Alpha", Role: "owner"},
		{TenantID: 2, Slug: "beta", DisplayName: "Beta", Role: "member"},
	}}
	resp, err := newSvc(f).ListMyTeams(ctxWithUser(1, 2), &teamsv1.ListMyTeamsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Teams, 2)
	assert.False(t, resp.Teams[0].Active)
	assert.True(t, resp.Teams[1].Active)
}

func TestSwitchTeamRequiresMembership(t *testing.T) {
	f := &fakeStore{memberships: map[int64]string{5: "member"}}
	svc := newSvc(f)

	_, err := svc.SwitchTeam(ctxWithUser(1, 5), &teamsv1.SwitchTeamRequest{TenantId: 9})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = svc.SwitchTeam(ctxWithUser(1, 5), &teamsv1.SwitchTeamRequest{TenantId: 5})
	require.NoError(t, err)
	assert.Equal(t, int64(5), f.active)
}

func TestSwitchTeamValidatesArg(t *testing.T) {
	_, err := newSvc(&fakeStore{}).SwitchTeam(ctxWithUser(1, 1), &teamsv1.SwitchTeamRequest{TenantId: 0})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
