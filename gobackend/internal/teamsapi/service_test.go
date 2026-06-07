package teamsapi

import (
	"context"
	"io"
	"log/slog"
	"testing"

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
}

func (f *fakeStore) ListMyTeams(_ context.Context, _ int64) ([]store.MyTeam, error) {
	return f.teams, nil
}
func (f *fakeStore) GetMembership(_ context.Context, _ int64, tenantID int64) (*store.Membership, error) {
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

func ctxWithUser(userID int64, tenantID int64) context.Context {
	tid := tenantID
	return auth.WithIdentity(context.Background(), &auth.Identity{
		UserID: userID, PlatformRole: "client", TenantID: &tid,
	})
}

func newSvc(f *fakeStore) *Service {
	return New(f, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
