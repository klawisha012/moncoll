package authapi

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// SignupViaInvite creates an account for the email bound to a pending team
// invitation, auto-verifies it (the token was delivered to that inbox, proving
// control — the same property the verify-email link relies on), provisions a
// personal team owned by the new user, joins the invited team, makes it the
// active team, and logs the user in. Public (no session, no captcha): the
// unguessable invitation token is the only thing that gates this endpoint.
//
// SECURITY: the email comes from the invitation, never the client, so a token
// holder cannot create an account for an arbitrary address. An email that
// already has an account is refused (AlreadyExists) — passwords are never reset
// through an invite.
func (s *Service) SignupViaInvite(ctx context.Context, req *authv1.SignupViaInviteRequest) (*authv1.LoginResponse, error) {
	token := strings.TrimSpace(req.GetToken())
	if token == "" {
		return nil, status.Error(codes.InvalidArgument, "token required")
	}
	inv, err := s.store.GetInvitationByTokenHash(ctx, sha256Hex(token))
	if err != nil {
		return nil, status.Error(codes.NotFound, "invitation not found or expired")
	}
	email := normalizeEmail(inv.Email)

	if u, gErr := s.store.GetUserByEmail(ctx, email); gErr == nil && u != nil {
		return nil, status.Error(codes.AlreadyExists, "account already exists; please sign in")
	}

	if l := len(req.GetPassword()); l < 8 || l > 256 {
		return nil, status.Error(codes.InvalidArgument, "password must be 8-256 chars")
	}
	pwHash, err := auth.HashPassword(req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "password hashing failed")
	}

	// Personal team (auto-named from the email local-part), owned by the user.
	tenant, err := s.store.AutoCreateTenantForUser(ctx, email, "")
	if err != nil {
		s.log.Error("SignupViaInvite tenant", "err", err)
		return nil, status.Error(codes.Internal, "tenant creation failed")
	}

	now := time.Now().UTC()
	ownerRole := "owner"
	created, err := s.store.CreateUser(ctx, &store.User{
		Email:           email,
		DisplayName:     localPart(email),
		PasswordHash:    &pwHash,
		PlatformRole:    "client",
		TenantID:        &tenant.ID,
		TenantRole:      &ownerRole,
		EmailVerifiedAt: &now, // auto-verified via the invite token
	})
	if err != nil {
		if errIsConflict(err) {
			return nil, status.Error(codes.AlreadyExists, "account already exists; please sign in")
		}
		s.log.Error("SignupViaInvite create user", "err", err)
		return nil, status.Error(codes.Internal, "user creation failed")
	}
	if err := s.store.CreateMembership(ctx, tenant.ID, created.ID, "owner"); err != nil {
		s.log.Error("SignupViaInvite membership", "err", err)
		return nil, status.Error(codes.Internal, "membership persist failed")
	}

	// Join the invited team. If the invite was consumed concurrently, the user
	// still keeps their personal team active — log and continue, no hard failure.
	if aErr := s.store.AcceptInvitation(ctx, inv, created.ID); aErr != nil {
		var nf *store.NotFoundError
		if errors.As(aErr, &nf) {
			s.log.Warn("SignupViaInvite invite already used", "inv", inv.ID)
		} else {
			s.log.Error("SignupViaInvite accept", "err", aErr)
			return nil, status.Error(codes.Internal, "internal error")
		}
	} else if sErr := s.store.SetActiveTenant(ctx, created.ID, inv.TenantID); sErr != nil {
		s.log.Warn("SignupViaInvite set active team", "err", sErr)
	}

	tok, err := s.mintSessionToken(created)
	if err != nil {
		return nil, err
	}
	// keepCurrent=true preserves any already-signed-in account in the stash.
	if err := s.setActiveWithStash(ctx, tok, created.ID, true); err != nil {
		return nil, err
	}
	return &authv1.LoginResponse{User: userPublic(created)}, nil
}
