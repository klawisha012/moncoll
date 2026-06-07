package teamsapi

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// Store is the persistence surface teamsapi needs. Implemented by *store.Store.
type Store interface {
	ListMyTeams(ctx context.Context, userID int64) ([]store.MyTeam, error)
	GetMembership(ctx context.Context, userID, tenantID int64) (*store.Membership, error)
	SetActiveTenant(ctx context.Context, userID, tenantID int64) error
}

// Service implements teamsv1.TeamsServiceServer.
type Service struct {
	teamsv1.UnimplementedTeamsServiceServer
	store Store
	log   *slog.Logger
}

// New constructs a Service.
func New(st Store, log *slog.Logger) *Service {
	return &Service{store: st, log: log}
}

func identity(ctx context.Context) (*auth.Identity, error) {
	id, ok := auth.IdentityFromContext(ctx)
	if !ok || id == nil {
		return nil, status.Error(codes.Unauthenticated, "not authenticated")
	}
	return id, nil
}

// ListMyTeams returns the caller's teams, marking the active one.
func (s *Service) ListMyTeams(ctx context.Context, _ *teamsv1.ListMyTeamsRequest) (*teamsv1.ListMyTeamsResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	teams, err := s.store.ListMyTeams(ctx, id.UserID)
	if err != nil {
		s.log.Error("ListMyTeams store error", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	out := make([]*teamsv1.Team, 0, len(teams))
	for _, t := range teams {
		active := id.TenantID != nil && *id.TenantID == t.TenantID
		out = append(out, &teamsv1.Team{
			TenantId:    t.TenantID,
			Slug:        t.Slug,
			DisplayName: t.DisplayName,
			Role:        t.Role,
			Active:      active,
		})
	}
	return &teamsv1.ListMyTeamsResponse{Teams: out}, nil
}

// SwitchTeam points the caller's active team at the requested tenant, after
// verifying membership.
func (s *Service) SwitchTeam(ctx context.Context, req *teamsv1.SwitchTeamRequest) (*emptypb.Empty, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetTenantId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if _, err := s.store.GetMembership(ctx, id.UserID, req.GetTenantId()); err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, status.Error(codes.PermissionDenied, "not a member of this team")
		}
		s.log.Error("SwitchTeam membership lookup", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if err := s.store.SetActiveTenant(ctx, id.UserID, req.GetTenantId()); err != nil {
		s.log.Error("SwitchTeam set active", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &emptypb.Empty{}, nil
}
