package teamsapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
)

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
