package teamsapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
)

func (s *Service) activeMembership(ctx context.Context) (*auth.Identity, string, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, "", err
	}
	if id.TenantID == nil {
		return nil, "", status.Error(codes.PermissionDenied, "no active team")
	}
	m, err := s.store.GetMembership(ctx, id.UserID, *id.TenantID)
	if err != nil {
		return nil, "", status.Error(codes.PermissionDenied, "not a member of the active team")
	}
	return id, m.Role, nil
}

func (s *Service) ListMembers(ctx context.Context, _ *teamsv1.ListMembersRequest) (*teamsv1.ListMembersResponse, error) {
	id, myRole, err := s.activeMembership(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.ListMembersForTenant(ctx, *id.TenantID)
	if err != nil {
		s.log.Error("ListMembers", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	out := make([]*teamsv1.Member, 0, len(rows))
	for _, r := range rows {
		out = append(out, &teamsv1.Member{UserId: r.UserID, Email: r.Email, DisplayName: r.DisplayName, Role: r.Role})
	}
	return &teamsv1.ListMembersResponse{Members: out, MyRole: myRole}, nil
}

func (s *Service) RemoveMember(ctx context.Context, req *teamsv1.MemberRequest) (*emptypb.Empty, error) {
	id, myRole, err := s.activeMembership(ctx)
	if err != nil {
		return nil, err
	}
	if myRole != "owner" && myRole != "admin" {
		return nil, status.Error(codes.PermissionDenied, "requires owner or admin")
	}
	target, err := s.store.GetMembership(ctx, req.GetUserId(), *id.TenantID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "not a member")
	}
	if myRole == "admin" && (target.Role == "owner" || target.Role == "admin") {
		return nil, status.Error(codes.PermissionDenied, "admins cannot remove owners or admins")
	}
	if target.Role == "owner" {
		if n, _ := s.store.CountOwners(ctx, *id.TenantID); n <= 1 {
			return nil, status.Error(codes.FailedPrecondition, "cannot remove the last owner")
		}
	}
	if err := s.store.DeleteMembership(ctx, *id.TenantID, req.GetUserId()); err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Best-effort: notify the removed member.
	if s.notifier != nil {
		if nErr := s.notifier.NotifyUser(ctx, req.GetUserId(), id.TenantID, "team.member_removed",
			"Removed from team", "You were removed from the team",
			map[string]any{}); nErr != nil {
			s.log.Warn("RemoveMember notify user", "err", nErr)
		}
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) ChangeRole(ctx context.Context, req *teamsv1.ChangeRoleRequest) (*emptypb.Empty, error) {
	id, myRole, err := s.activeMembership(ctx)
	if err != nil {
		return nil, err
	}
	if myRole != "owner" {
		return nil, status.Error(codes.PermissionDenied, "only the owner can change roles")
	}
	role := req.GetRole()
	if role != "admin" && role != "member" {
		return nil, status.Error(codes.InvalidArgument, "role must be admin or member")
	}
	target, err := s.store.GetMembership(ctx, req.GetUserId(), *id.TenantID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "not a member")
	}
	if target.Role == "owner" {
		return nil, status.Error(codes.FailedPrecondition, "cannot change an owner's role")
	}
	if err := s.store.UpdateMembershipRole(ctx, *id.TenantID, req.GetUserId(), role); err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Best-effort: notify the member whose role changed.
	if s.notifier != nil {
		if nErr := s.notifier.NotifyUser(ctx, req.GetUserId(), id.TenantID, "team.role_changed",
			"Role changed", "Your role is now "+req.GetRole(),
			map[string]any{"role": req.GetRole()}); nErr != nil {
			s.log.Warn("ChangeRole notify user", "err", nErr)
		}
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) LeaveTeam(ctx context.Context, _ *teamsv1.LeaveTeamRequest) (*emptypb.Empty, error) {
	id, myRole, err := s.activeMembership(ctx)
	if err != nil {
		return nil, err
	}
	if myRole == "owner" {
		if n, _ := s.store.CountOwners(ctx, *id.TenantID); n <= 1 {
			return nil, status.Error(codes.FailedPrecondition, "the last owner cannot leave the team")
		}
	}
	if err := s.store.DeleteMembership(ctx, *id.TenantID, id.UserID); err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &emptypb.Empty{}, nil
}
