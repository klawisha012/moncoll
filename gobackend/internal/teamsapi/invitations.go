package teamsapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
)

const invitationTTL = 7 * 24 * time.Hour

func normalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func newInviteToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

func invToProto(inv *store.Invitation, teamName string) *teamsv1.Invitation {
	return &teamsv1.Invitation{
		Id:        inv.ID,
		TenantId:  inv.TenantID,
		Email:     inv.Email,
		Role:      inv.Role,
		Status:    inv.Status,
		TeamName:  teamName,
		ExpiresAt: inv.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

func (s *Service) requireActiveTeamAdmin(ctx context.Context) (*auth.Identity, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if id.TenantID == nil {
		return nil, status.Error(codes.PermissionDenied, "no active team")
	}
	m, err := s.store.GetMembership(ctx, id.UserID, *id.TenantID)
	if err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, status.Error(codes.PermissionDenied, "not a member of the active team")
		}
		s.log.Error("requireActiveTeamAdmin membership", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if m.Role != "owner" && m.Role != "admin" {
		return nil, status.Error(codes.PermissionDenied, "requires owner or admin")
	}
	return id, nil
}

func (s *Service) inviteURL(token string) string {
	return s.publicBaseURL + "/invite/accept?token=" + token
}

// callerEmail returns the calling user's email for the invitation email-match
// checks below. It MUST use GetUserByIDFull, not GetUserByID: the latter selects
// only the auth-gate columns (id, platform_role, tenant_id, ...) and leaves
// Email empty, which silently made every check compare "" against inv.Email and
// reject all callers with "not your invitation".
func (s *Service) callerEmail(ctx context.Context, id *auth.Identity) string {
	u, err := s.store.GetUserByIDFull(ctx, id.UserID)
	if err != nil || u == nil {
		return ""
	}
	return u.Email
}

func (s *Service) CreateInvitation(ctx context.Context, req *teamsv1.CreateInvitationRequest) (*teamsv1.Invitation, error) {
	id, err := s.requireActiveTeamAdmin(ctx)
	if err != nil {
		return nil, err
	}
	tenantID := *id.TenantID
	email := normalizeEmail(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	role := req.GetRole()
	if role != "admin" && role != "member" {
		return nil, status.Error(codes.InvalidArgument, "role must be admin or member")
	}
	if u, uErr := s.store.GetUserByEmail(ctx, email); uErr == nil && u != nil {
		if _, mErr := s.store.GetMembership(ctx, u.ID, tenantID); mErr == nil {
			return nil, status.Error(codes.AlreadyExists, "already a member of this team")
		}
	}
	raw, hash, err := newInviteToken()
	if err != nil {
		return nil, status.Error(codes.Internal, "token generation failed")
	}
	expiresAt := time.Now().UTC().Add(invitationTTL)
	teamName, _ := s.store.GetTenantDisplayName(ctx, tenantID)

	var inv *store.Invitation
	if existing, gErr := s.store.GetPendingInvitationForEmail(ctx, tenantID, email); gErr == nil {
		if err := s.store.ResendInvitation(ctx, existing.ID, hash, expiresAt); err != nil {
			s.log.Error("CreateInvitation resend", "err", err)
			return nil, status.Error(codes.Internal, "internal error")
		}
		existing.TokenHash = hash
		existing.ExpiresAt = expiresAt
		inv = existing
	} else {
		created, cErr := s.store.CreateInvitation(ctx, &store.Invitation{
			TenantID: tenantID, Email: email, Role: role, TokenHash: hash, InvitedByUserID: id.UserID, ExpiresAt: expiresAt,
		})
		if cErr != nil {
			s.log.Error("CreateInvitation insert", "err", cErr)
			return nil, status.Error(codes.Internal, "internal error")
		}
		inv = created
	}
	url := s.inviteURL(raw)
	sendErr := s.mail.SendInvitationEmail(ctx, email, teamName, url)
	if sendErr != nil {
		s.log.Warn("CreateInvitation send email", "err", sendErr)
	}
	out := invToProto(inv, teamName)
	out.AcceptUrl = url
	out.EmailSent = sendErr == nil && s.mail.Configured()

	// Best-effort: notify a registered user with the invited email address.
	if s.notifier != nil {
		if u, uErr := s.store.GetUserByEmail(ctx, email); uErr == nil && u != nil {
			tid := tenantID
			if nErr := s.notifier.NotifyUser(ctx, u.ID, &tid, "team.invitation", "Team invitation",
				"You've been invited to "+teamName,
				map[string]any{"invitation_id": inv.ID, "team_name": teamName, "role": role}); nErr != nil {
				s.log.Warn("CreateInvitation notify user", "err", nErr)
			}
		}
	}

	return out, nil
}

func (s *Service) ListInvitations(ctx context.Context, _ *teamsv1.ListInvitationsRequest) (*teamsv1.ListInvitationsResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	resp := &teamsv1.ListInvitationsResponse{}
	if id.TenantID != nil {
		if m, mErr := s.store.GetMembership(ctx, id.UserID, *id.TenantID); mErr == nil && (m.Role == "owner" || m.Role == "admin") {
			rows, lErr := s.store.ListInvitationsForTenant(ctx, *id.TenantID)
			if lErr != nil {
				s.log.Error("ListInvitations outgoing", "err", lErr)
				return nil, status.Error(codes.Internal, "internal error")
			}
			teamName, _ := s.store.GetTenantDisplayName(ctx, *id.TenantID)
			for i := range rows {
				resp.Outgoing = append(resp.Outgoing, invToProto(&rows[i], teamName))
			}
		}
	}
	email := normalizeEmail(s.callerEmail(ctx, id))
	if email != "" {
		rows, lErr := s.store.ListPendingInvitationsForEmail(ctx, email)
		if lErr != nil {
			s.log.Error("ListInvitations incoming", "err", lErr)
			return nil, status.Error(codes.Internal, "internal error")
		}
		for i := range rows {
			teamName, _ := s.store.GetTenantDisplayName(ctx, rows[i].TenantID)
			resp.Incoming = append(resp.Incoming, invToProto(&rows[i], teamName))
		}
	}
	return resp, nil
}

// PreviewInvitation resolves a raw token to its team/role/email without a
// session, so the accept page can show what the user is joining. It never
// reveals whether the lookup failed for "not found" vs "expired" — both yield
// valid=false — to avoid leaking which tokens ever existed.
func (s *Service) PreviewInvitation(ctx context.Context, req *teamsv1.PreviewInvitationRequest) (*teamsv1.InvitationPreview, error) {
	token := strings.TrimSpace(req.GetToken())
	if token == "" {
		return &teamsv1.InvitationPreview{Valid: false}, nil
	}
	sum := sha256.Sum256([]byte(token))
	inv, err := s.store.GetInvitationByTokenHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		return &teamsv1.InvitationPreview{Valid: false}, nil
	}
	teamName, _ := s.store.GetTenantDisplayName(ctx, inv.TenantID)
	accountExists := false
	if u, uErr := s.store.GetUserByEmail(ctx, inv.Email); uErr == nil && u != nil {
		accountExists = true
	}
	return &teamsv1.InvitationPreview{
		Valid:         true,
		TeamName:      teamName,
		Role:          inv.Role,
		Email:         inv.Email,
		AccountExists: accountExists,
	}, nil
}

func (s *Service) AcceptInvitation(ctx context.Context, req *teamsv1.AcceptInvitationRequest) (*emptypb.Empty, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(req.GetToken())
	if token == "" {
		return nil, status.Error(codes.InvalidArgument, "token required")
	}
	sum := sha256.Sum256([]byte(token))
	inv, err := s.store.GetInvitationByTokenHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, status.Error(codes.NotFound, "invitation not found or expired")
	}
	if normalizeEmail(s.callerEmail(ctx, id)) != inv.Email {
		return nil, status.Error(codes.PermissionDenied, "invitation addressed to a different email")
	}
	if err := s.store.AcceptInvitation(ctx, inv, id.UserID); err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, status.Error(codes.FailedPrecondition, "invitation already used")
		}
		s.log.Error("AcceptInvitation", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Best-effort: notify remaining team members that someone joined.
	if s.notifier != nil {
		joinerEmail := s.callerEmail(ctx, id)
		if nErr := s.notifier.NotifyTenantMembers(ctx, inv.TenantID, id.UserID, "team.member_joined",
			"New team member", joinerEmail+" joined the team",
			map[string]any{"user_id": id.UserID}); nErr != nil {
			s.log.Warn("AcceptInvitation notify members", "err", nErr)
		}
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) DeclineInvitation(ctx context.Context, req *teamsv1.InvitationIdRequest) (*emptypb.Empty, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	inv, err := s.store.GetInvitationByID(ctx, req.GetId())
	if err != nil {
		return nil, status.Error(codes.NotFound, "invitation not found")
	}
	if normalizeEmail(s.callerEmail(ctx, id)) != inv.Email {
		return nil, status.Error(codes.PermissionDenied, "not your invitation")
	}
	if err := s.store.SetInvitationStatus(ctx, inv.ID, "revoked"); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "invitation not pending")
	}
	return &emptypb.Empty{}, nil
}

func (s *Service) RevokeInvitation(ctx context.Context, req *teamsv1.InvitationIdRequest) (*emptypb.Empty, error) {
	if _, _, err := s.adminOwnsInvitation(ctx, req.GetId()); err != nil {
		return nil, err
	}
	if err := s.store.SetInvitationStatus(ctx, req.GetId(), "revoked"); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "invitation not pending")
	}
	return &emptypb.Empty{}, nil
}

func (s *Service) ResendInvitation(ctx context.Context, req *teamsv1.InvitationIdRequest) (*teamsv1.Invitation, error) {
	_, inv, err := s.adminOwnsInvitation(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	raw, hash, tErr := newInviteToken()
	if tErr != nil {
		return nil, status.Error(codes.Internal, "token generation failed")
	}
	expiresAt := time.Now().UTC().Add(invitationTTL)
	if err := s.store.ResendInvitation(ctx, inv.ID, hash, expiresAt); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "invitation not pending")
	}
	inv.TokenHash, inv.ExpiresAt = hash, expiresAt
	teamName, _ := s.store.GetTenantDisplayName(ctx, inv.TenantID)
	url := s.inviteURL(raw)
	sendErr := s.mail.SendInvitationEmail(ctx, inv.Email, teamName, url)
	if sendErr != nil {
		s.log.Warn("ResendInvitation send email", "err", sendErr)
	}
	out := invToProto(inv, teamName)
	out.AcceptUrl = url
	out.EmailSent = sendErr == nil && s.mail.Configured()
	return out, nil
}

// AcceptInvitationById accepts a pending invitation by its numeric ID.
// The caller must be authenticated and their email must match the invitation.
func (s *Service) AcceptInvitationById(ctx context.Context, req *teamsv1.InvitationIdRequest) (*emptypb.Empty, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	inv, err := s.store.GetInvitationByID(ctx, req.GetId())
	if err != nil {
		return nil, status.Error(codes.NotFound, "invitation not found")
	}
	if normalizeEmail(s.callerEmail(ctx, id)) != inv.Email {
		return nil, status.Error(codes.PermissionDenied, "not your invitation")
	}
	if err := s.store.AcceptInvitation(ctx, inv, id.UserID); err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, status.Error(codes.FailedPrecondition, "invitation already used")
		}
		s.log.Error("AcceptInvitationById", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Best-effort: notify remaining team members that someone joined.
	if s.notifier != nil {
		joinerEmail := s.callerEmail(ctx, id)
		if nErr := s.notifier.NotifyTenantMembers(ctx, inv.TenantID, id.UserID, "team.member_joined",
			"New team member", joinerEmail+" joined the team",
			map[string]any{"user_id": id.UserID}); nErr != nil {
			s.log.Warn("AcceptInvitationById notify members", "err", nErr)
		}
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) adminOwnsInvitation(ctx context.Context, invID int64) (*auth.Identity, *store.Invitation, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, nil, err
	}
	inv, err := s.store.GetInvitationByID(ctx, invID)
	if err != nil {
		return nil, nil, status.Error(codes.NotFound, "invitation not found")
	}
	m, err := s.store.GetMembership(ctx, id.UserID, inv.TenantID)
	if err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, nil, status.Error(codes.PermissionDenied, "not a member of this team")
		}
		return nil, nil, status.Error(codes.Internal, "internal error")
	}
	if m.Role != "owner" && m.Role != "admin" {
		return nil, nil, status.Error(codes.PermissionDenied, "requires owner or admin")
	}
	return id, inv, nil
}
