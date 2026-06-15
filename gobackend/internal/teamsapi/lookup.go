package teamsapi

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// LookupUserByEmail resolves an exact email to a platform user so a team admin
// can confirm registration before inviting. Admin-only; exact match only.
func (s *Service) LookupUserByEmail(ctx context.Context, req *teamsv1.LookupUserByEmailRequest) (*teamsv1.UserLookupResponse, error) {
	id, err := s.requireActiveTeamAdmin(ctx)
	if err != nil {
		return nil, err
	}
	email := normalizeEmail(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	u, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return &teamsv1.UserLookupResponse{Found: false}, nil
		}
		s.log.Error("LookupUserByEmail", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	alreadyMember := false
	if _, mErr := s.store.GetMembership(ctx, u.ID, *id.TenantID); mErr == nil {
		alreadyMember = true
	}
	return &teamsv1.UserLookupResponse{
		Found:         true,
		UserId:        u.ID,
		Email:         u.Email,
		DisplayName:   u.DisplayName,
		AlreadyMember: alreadyMember,
	}, nil
}
