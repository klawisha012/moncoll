package teamsapi

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	"github.com/zwarder/waf/gobackend/internal/store"
)

func newSvcWithNotifier(f *fakeStore, n *fakeNotifier) *Service {
	return New(f, &fakeMailer{}, "https://waf.test", slog.New(slog.NewTextHandler(io.Discard, nil)), n)
}

const (
	callerID int64 = 10
	targetID int64 = 20
	tenantID int64 = 1
)

// TestRemoveMember_AdminCannotRemoveAdmin: caller admin, target admin → PermissionDenied.
func TestRemoveMember_AdminCannotRemoveAdmin(t *testing.T) {
	f := &fakeStore{
		memberRoles: map[int64]string{
			callerID: "admin",
			targetID: "admin",
		},
	}
	ctx := ctxWithUser(callerID, tenantID)
	_, err := newSvc(f).RemoveMember(ctx, &teamsv1.MemberRequest{UserId: targetID})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestRemoveMember_OwnerRemovesMember: caller owner removes member → ok, deleted contains targetID.
func TestRemoveMember_OwnerRemovesMember(t *testing.T) {
	f := &fakeStore{
		memberRoles: map[int64]string{
			callerID: "owner",
			targetID: "member",
		},
		ownerCount: 1,
	}
	ctx := ctxWithUser(callerID, tenantID)
	_, err := newSvc(f).RemoveMember(ctx, &teamsv1.MemberRequest{UserId: targetID})
	require.NoError(t, err)
	assert.Contains(t, f.deleted, targetID)
}

// TestRemoveMember_LastOwnerBlocked: removing the last owner → FailedPrecondition.
func TestRemoveMember_LastOwnerBlocked(t *testing.T) {
	f := &fakeStore{
		memberRoles: map[int64]string{
			callerID: "owner",
			targetID: "owner",
		},
		ownerCount: 1,
	}
	ctx := ctxWithUser(callerID, tenantID)
	_, err := newSvc(f).RemoveMember(ctx, &teamsv1.MemberRequest{UserId: targetID})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// TestChangeRole_NonOwnerDenied: caller admin tries to change role → PermissionDenied.
func TestChangeRole_NonOwnerDenied(t *testing.T) {
	f := &fakeStore{
		memberRoles: map[int64]string{
			callerID: "admin",
			targetID: "member",
		},
	}
	ctx := ctxWithUser(callerID, tenantID)
	_, err := newSvc(f).ChangeRole(ctx, &teamsv1.ChangeRoleRequest{UserId: targetID, Role: "admin"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestChangeRole_OwnerChangesRole: caller owner, target member → ok, roleUpdates contains "admin".
func TestChangeRole_OwnerChangesRole(t *testing.T) {
	f := &fakeStore{
		memberRoles: map[int64]string{
			callerID: "owner",
			targetID: "member",
		},
	}
	ctx := ctxWithUser(callerID, tenantID)
	_, err := newSvc(f).ChangeRole(ctx, &teamsv1.ChangeRoleRequest{UserId: targetID, Role: "admin"})
	require.NoError(t, err)
	assert.Contains(t, f.roleUpdates, "admin")
}

// TestLeaveTeam_LastOwnerBlocked: sole owner tries to leave → FailedPrecondition.
func TestLeaveTeam_LastOwnerBlocked(t *testing.T) {
	f := &fakeStore{
		memberRoles: map[int64]string{
			callerID: "owner",
		},
		ownerCount: 1,
	}
	ctx := ctxWithUser(callerID, tenantID)
	_, err := newSvc(f).LeaveTeam(ctx, &teamsv1.LeaveTeamRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// ── Notification tests ──────────────────────────────────────────────────────

// TestChangeRole_EmitsNotification: successful ChangeRole notifies the target user.
func TestChangeRole_EmitsNotification(t *testing.T) {
	f := &fakeStore{
		memberRoles: map[int64]string{
			callerID: "owner",
			targetID: "member",
		},
	}
	n := &fakeNotifier{}
	ctx := ctxWithUser(callerID, tenantID)
	_, err := newSvcWithNotifier(f, n).ChangeRole(ctx, &teamsv1.ChangeRoleRequest{UserId: targetID, Role: "admin"})
	require.NoError(t, err)

	call, ok := n.findType("team.role_changed")
	require.True(t, ok, "expected team.role_changed notification")
	assert.Equal(t, targetID, call.userID)
}

// TestRemoveMember_EmitsNotification: successful RemoveMember notifies the removed user.
func TestRemoveMember_EmitsNotification(t *testing.T) {
	f := &fakeStore{
		memberRoles: map[int64]string{
			callerID: "owner",
			targetID: "member",
		},
		ownerCount: 2,
	}
	n := &fakeNotifier{}
	ctx := ctxWithUser(callerID, tenantID)
	_, err := newSvcWithNotifier(f, n).RemoveMember(ctx, &teamsv1.MemberRequest{UserId: targetID})
	require.NoError(t, err)

	call, ok := n.findType("team.member_removed")
	require.True(t, ok, "expected team.member_removed notification")
	assert.Equal(t, targetID, call.userID)
}

// ── RenameTeam ───────────────────────────────────────────────────────────────

// TestRenameTeam_OwnerOk: owner renames; name is trimmed and persisted.
func TestRenameTeam_OwnerOk(t *testing.T) {
	f := &fakeStore{
		memberRoles: map[int64]string{callerID: "owner"},
		teams: []store.MyTeam{
			{TenantID: tenantID, Slug: "acme", DisplayName: "Acme", Role: "owner"},
		},
		tenantNames: map[int64]string{tenantID: "Acme"},
	}
	ctx := ctxWithUser(callerID, tenantID)
	_, err := newSvc(f).RenameTeam(ctx, &teamsv1.RenameTeamRequest{DisplayName: "  Acme Corp  "})
	require.NoError(t, err)
	assert.Equal(t, "Acme Corp", f.tenantNames[tenantID])
}

// TestRenameTeam_NonOwnerDenied: a non-owner cannot rename.
func TestRenameTeam_NonOwnerDenied(t *testing.T) {
	f := &fakeStore{memberRoles: map[int64]string{callerID: "admin"}}
	_, err := newSvc(f).RenameTeam(ctxWithUser(callerID, tenantID), &teamsv1.RenameTeamRequest{DisplayName: "X"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestRenameTeam_ValidatesName: empty/whitespace and >64 chars are rejected.
func TestRenameTeam_ValidatesName(t *testing.T) {
	f := &fakeStore{memberRoles: map[int64]string{callerID: "owner"}}
	ctx := ctxWithUser(callerID, tenantID)

	_, err := newSvc(f).RenameTeam(ctx, &teamsv1.RenameTeamRequest{DisplayName: "   "})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = newSvc(f).RenameTeam(ctx, &teamsv1.RenameTeamRequest{DisplayName: strings.Repeat("a", 65)})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestRenameTeam_RejectsDuplicateAmongMyTeams: renaming to a name the caller
// already uses for another of their teams is rejected (case-insensitive).
func TestRenameTeam_RejectsDuplicateAmongMyTeams(t *testing.T) {
	f := &fakeStore{
		memberRoles: map[int64]string{callerID: "owner"},
		teams: []store.MyTeam{
			{TenantID: tenantID, Slug: "acme", DisplayName: "Acme", Role: "owner"},
			{TenantID: 2, Slug: "beta", DisplayName: "Beta", Role: "member"},
		},
		tenantNames: map[int64]string{tenantID: "Acme"},
	}
	ctx := ctxWithUser(callerID, tenantID)
	_, err := newSvc(f).RenameTeam(ctx, &teamsv1.RenameTeamRequest{DisplayName: "beta"})
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	assert.Equal(t, "Acme", f.tenantNames[tenantID])
}
