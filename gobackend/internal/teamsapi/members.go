package teamsapi

import (
	"context"
	"strings"

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
	// team_name lets the Team page show/edit the current name without an extra
	// round-trip. Best-effort: a lookup failure leaves it empty rather than
	// breaking the members list.
	name, _ := s.store.GetTenantDisplayName(ctx, *id.TenantID)
	return &teamsv1.ListMembersResponse{Members: out, MyRole: myRole, TeamName: name}, nil
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

// maxTeamNameLen matches tenants.display_name VARCHAR(64).
const maxTeamNameLen = 64

// RenameTeam lets the owner change the active team's display name. The slug
// (tenants.name) is never touched. Rejects a name the caller already uses for
// another of their own teams so the team switcher stays unambiguous.
func (s *Service) RenameTeam(ctx context.Context, req *teamsv1.RenameTeamRequest) (*emptypb.Empty, error) {
	id, myRole, err := s.activeMembership(ctx)
	if err != nil {
		return nil, err
	}
	if myRole != "owner" {
		return nil, status.Error(codes.PermissionDenied, "only the owner can rename the team")
	}
	name := strings.TrimSpace(req.GetDisplayName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "team name must not be empty")
	}
	if len([]rune(name)) > maxTeamNameLen {
		return nil, status.Error(codes.InvalidArgument, "team name too long (max 64 characters)")
	}
	teams, err := s.store.ListMyTeams(ctx, id.UserID)
	if err != nil {
		s.log.Error("RenameTeam list teams", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	for _, t := range teams {
		if t.TenantID != *id.TenantID && strings.EqualFold(strings.TrimSpace(t.DisplayName), name) {
			return nil, status.Error(codes.AlreadyExists, "you already have a team with this name")
		}
	}
	if err := s.store.SetTenantDisplayName(ctx, *id.TenantID, name); err != nil {
		s.log.Error("RenameTeam set name", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &emptypb.Empty{}, nil
}
