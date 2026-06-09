package authapi

// password.go — providers, signup, verify-email, login, logout, me, forgot,
// reset. Faithful port of backend/src/auth/routers/password.py.

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// GetProviders mirrors GET /providers — feature flags from config.
func (s *Service) GetProviders(_ context.Context, _ *authv1.ProvidersRequest) (*authv1.ProvidersResponse, error) {
	siteKey := s.cfg.CaptchaSiteKey
	if siteKey == "" {
		siteKey = turnstileDevSiteKey
	}
	return &authv1.ProvidersResponse{
		Google:         s.cfg.GoogleEnabled,
		Github:         s.cfg.GitHubEnabled,
		CaptchaSiteKey: siteKey,
		CaptchaDevMode: s.cfg.CaptchaSiteKey == "",
		SmtpDevMode:    !s.cfg.SMTPConfigured,
	}, nil
}

// Signup mirrors POST /signup (202). Validates captcha, creates tenant + client
// user (unverified), issues a verify token, sends the email (best-effort).
func (s *Service) Signup(ctx context.Context, req *authv1.SignupRequest) (*authv1.SignupResponse, error) {
	if err := s.checkCaptcha(ctx, req.GetCaptchaToken()); err != nil {
		return nil, err
	}

	email := normalizeEmail(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}
	if l := len(req.GetPassword()); l < 8 || l > 256 {
		return nil, status.Error(codes.InvalidArgument, "password must be 8-256 chars")
	}

	// Create tenant (validates name; 400 invalid / 409 taken).
	tenant, err := s.store.CreateTenant(ctx, req.GetTenantName(), req.GetTenantName())
	if err != nil {
		if errIsNotFound(err) || isInvalidTenantName(err) {
			return nil, status.Error(codes.InvalidArgument, "invalid tenant name")
		}
		if errIsConflict(err) {
			return nil, status.Error(codes.AlreadyExists, "tenant name taken")
		}
		return nil, status.Error(codes.Internal, "tenant creation failed")
	}

	// Create the client user (owner of the new tenant), unverified.
	pwHash, err := auth.HashPassword(req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "password hashing failed")
	}
	displayName := req.GetDisplayName()
	if displayName == "" {
		displayName = localPart(email)
	}
	ownerRole := "owner"
	newUser := &store.User{
		Email:        email,
		DisplayName:  displayName,
		PasswordHash: &pwHash,
		PlatformRole: "client",
		TenantID:     &tenant.ID,
		TenantRole:   &ownerRole,
		// EmailVerifiedAt nil → unverified.
	}
	created, err := s.store.CreateUser(ctx, newUser)
	if err != nil {
		if errIsConflict(err) {
			return nil, status.Error(codes.AlreadyExists, "email already in use")
		}
		return nil, status.Error(codes.Internal, "user creation failed")
	}

	// New owner of the freshly created tenant also gets a membership row.
	if err := s.store.CreateMembership(ctx, tenant.ID, created.ID, "owner"); err != nil {
		return nil, status.Error(codes.Internal, "membership persist failed")
	}

	// Issue verification token (store its hash).
	token, err := randomURLToken()
	if err != nil {
		return nil, status.Error(codes.Internal, "token generation failed")
	}
	if err := s.store.CreateEmailVerification(ctx, created.ID, sha256Hex(token), "verify_email",
		time.Now().UTC().Add(verifyEmailTTL)); err != nil {
		return nil, status.Error(codes.Internal, "verification token persist failed")
	}

	verifyURL := s.publicBaseURL() + "/verify-email?token=" + token

	// Best-effort email send. Failure MUST NOT fail signup (mirrors Python).
	smtpFailed := false
	if err := s.email.SendVerificationEmail(ctx, created.Email, created.DisplayName, verifyURL); err != nil {
		s.log.Warn("verify-email send failed", "err", err)
		smtpFailed = true
	}

	resp := &authv1.SignupResponse{Message: "check your email"}
	// Surface verify URL in dev (no smtp) OR when the send failed.
	if !s.cfg.SMTPConfigured || smtpFailed {
		resp.DevVerifyUrl = verifyURL
		if smtpFailed {
			resp.SmtpSendFailed = true
		}
	}
	return resp, nil
}

// VerifyEmail mirrors POST /verify-email → LoginResponse + session cookie.
func (s *Service) VerifyEmail(ctx context.Context, req *authv1.VerifyEmailRequest) (*authv1.LoginResponse, error) {
	u, err := s.consumeVerification(ctx, req.GetToken(), "verify_email")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid or expired token")
	}
	now := time.Now().UTC()
	if err := s.store.UpdateUser(ctx, u.ID, store.UserUpdate{EmailVerifiedAt: &now}); err != nil {
		return nil, status.Error(codes.Internal, "verify update failed")
	}
	u.EmailVerifiedAt = &now
	// Auto-accept any pending team invitations addressed to this (now verified)
	// email: the user joins those teams; switch their active team to the first.
	if invites, iErr := s.store.ListPendingInvitationsForEmail(ctx, strings.ToLower(u.Email)); iErr == nil {
		for i := range invites {
			if aErr := s.store.AcceptInvitation(ctx, &invites[i], u.ID); aErr != nil {
				s.log.Warn("verify: auto-accept invite failed", "inv", invites[i].ID, "err", aErr)
				continue
			}
		}
		if len(invites) > 0 {
			if aErr := s.store.SetActiveTenant(ctx, u.ID, invites[0].TenantID); aErr != nil {
				s.log.Warn("verify: set active team failed", "err", aErr)
			}
		}
	}
	if err := s.issueSessionCookie(ctx, u); err != nil {
		return nil, err
	}
	return &authv1.LoginResponse{User: userPublic(u)}, nil
}

// Login mirrors POST /login. Validates captcha + credentials + (admin/totp)
// TOTP, then issues a session cookie. Faithfully reproduces the Python status
// codes / detail strings.
func (s *Service) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	if err := s.checkCaptcha(ctx, req.GetCaptchaToken()); err != nil {
		return nil, err
	}

	email := normalizeEmail(req.GetEmail())
	u, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errIsNotFound(err) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "login lookup failed")
	}
	// Verify password (constant behaviour: returns false on nil hash).
	pw := ""
	if u.PasswordHash != nil {
		pw = *u.PasswordHash
	}
	if !auth.VerifyPassword(req.GetPassword(), pw) {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	if u.EmailVerifiedAt == nil {
		return nil, status.Error(codes.PermissionDenied, "email not verified")
	}

	needsTotp := u.PlatformRole == "admin" ||
		(u.PlatformRole == "client" && u.TotpEnabledAt != nil)
	if needsTotp {
		if u.TotpSecret == nil {
			// Admin first-login: issue the short-lived enrol cookie + 403
			// totp_enrol_required (mirrors the JSONResponse-with-cookie path so
			// the Set-Cookie survives the error response).
			enrol, err := s.issuer.SignShortLived(
				map[string]any{"user_id": float64(u.ID)}, shortLivedTTL, "totp_enrol")
			if err != nil {
				return nil, status.Error(codes.Internal, "enrol token failed")
			}
			emitSetCookie(ctx, buildCookie(totpEnrolCookie, enrol, 600, s.cfg.CookieSecure))
			return nil, status.Error(codes.PermissionDenied, "totp_enrol_required")
		}
		if req.GetTotpCode() == "" {
			return nil, status.Error(codes.Unauthenticated, "totp_required")
		}
		if !(s.verifyStoredTotp(u, req.GetTotpCode()) ||
			s.verifyRecoveryAndConsume(ctx, u, req.GetTotpCode())) {
			return nil, status.Error(codes.Unauthenticated, "invalid totp")
		}
	}

	// Touch last_login_at.
	now := time.Now().UTC()
	if err := s.store.UpdateUser(ctx, u.ID, store.UserUpdate{LastLoginAt: &now}); err != nil {
		s.log.Warn("login: touch last_login_at failed", "err", err)
	}
	tok, err := s.mintSessionToken(u)
	if err != nil {
		return nil, err
	}
	if err := s.setActiveWithStash(ctx, tok, u.ID, req.GetKeepCurrent()); err != nil {
		return nil, err
	}
	return &authv1.LoginResponse{User: userPublic(u)}, nil
}

// Logout clears the active session. With all=true it also clears the stash; with
// all=false it promotes the first valid stashed account to active.
func (s *Service) Logout(ctx context.Context, req *authv1.LogoutRequest) (*emptypb.Empty, error) {
	if req.GetAll() {
		emitSetCookie(ctx, clearCookie(sessionCookie, s.cfg.CookieSecure))
		emitSetCookie(ctx, clearCookie(stashCookie, s.cfg.CookieSecure))
		return &emptypb.Empty{}, nil
	}
	stash := decodeStash(auth.CookieFromMetadata(ctx, stashCookie))
	for i, t := range stash {
		uid, ok := s.tokenUID(t)
		if !ok {
			continue
		}
		emitSetCookie(ctx, buildCookie(sessionCookie, t, sessionMaxAge, s.cfg.CookieSecure))
		rest := append(append([]string{}, stash[:i]...), stash[i+1:]...)
		s.emitStash(ctx, s.pruneStash(rest, uid))
		return &emptypb.Empty{}, nil
	}
	emitSetCookie(ctx, clearCookie(sessionCookie, s.cfg.CookieSecure))
	emitSetCookie(ctx, clearCookie(stashCookie, s.cfg.CookieSecure))
	return &emptypb.Empty{}, nil
}

// Me mirrors GET /me — reads the session cookie, decodes, loads the user.
func (s *Service) Me(ctx context.Context, _ *authv1.MeRequest) (*authv1.UserPublic, error) {
	token := auth.CookieFromMetadata(ctx, sessionCookie)
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "not authenticated")
	}
	claims, err := s.decoder.Decode(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired session")
	}
	uid, ok := parseUserID(claims.Sub)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	u, err := s.store.GetUserByIDFull(ctx, uid)
	if err != nil {
		if errIsNotFound(err) {
			return nil, status.Error(codes.Unauthenticated, "user no longer exists")
		}
		return nil, status.Error(codes.Internal, "user lookup failed")
	}
	return userPublic(u), nil
}

// ForgotPassword mirrors POST /password/forgot (202). Always returns 202 with a
// constant-shape body — NEVER leaks whether the email exists.
func (s *Service) ForgotPassword(ctx context.Context, req *authv1.ForgotPasswordRequest) (*authv1.ForgotPasswordResponse, error) {
	if err := s.checkCaptcha(ctx, req.GetCaptchaToken()); err != nil {
		return nil, err
	}
	email := normalizeEmail(req.GetEmail())
	resp := &authv1.ForgotPasswordResponse{Message: "if that email exists, a reset link was sent"}

	u, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		// NotFound or any error → still 202 (no existence leak). Log internal errs.
		if !errIsNotFound(err) {
			s.log.Warn("forgot: lookup error", "err", err)
		}
		return resp, nil
	}
	if u.EmailVerifiedAt == nil {
		// Unverified accounts get no reset email; same constant-shape response.
		return resp, nil
	}

	token, err := randomURLToken()
	if err != nil {
		return resp, nil
	}
	if err := s.store.CreateEmailVerification(ctx, u.ID, sha256Hex(token), "reset_password",
		time.Now().UTC().Add(resetPasswordTTL)); err != nil {
		s.log.Warn("forgot: persist reset token failed", "err", err)
		return resp, nil
	}
	resetURL := s.publicBaseURL() + "/reset-password?token=" + token
	// Best-effort send; failures stay out of the response body.
	if err := s.email.SendPasswordResetEmail(ctx, u.Email, u.DisplayName, resetURL); err != nil {
		s.log.Warn("forgot: reset email send failed", "err", err)
	}
	// Dev convenience: only when SMTP is unconfigured (config-time, never prod).
	if !s.cfg.SMTPConfigured {
		resp.DevResetUrl = resetURL
	}
	return resp, nil
}

// ResetPassword mirrors POST /password/reset (204).
func (s *Service) ResetPassword(ctx context.Context, req *authv1.ResetPasswordRequest) (*emptypb.Empty, error) {
	if l := len(req.GetNewPassword()); l < 8 || l > 256 {
		return nil, status.Error(codes.InvalidArgument, "password must be 8-256 chars")
	}
	u, err := s.consumeVerification(ctx, req.GetToken(), "reset_password")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid or expired token")
	}
	pwHash, err := auth.HashPassword(req.GetNewPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "password hashing failed")
	}
	if err := s.store.UpdateUser(ctx, u.ID, store.UserUpdate{PasswordHash: &pwHash}); err != nil {
		return nil, status.Error(codes.Internal, "password update failed")
	}
	return &emptypb.Empty{}, nil
}

// consumeVerification mirrors verification.py consume: look up by token hash +
// purpose (unused, unexpired), mark used, return the user.
func (s *Service) consumeVerification(ctx context.Context, token, purpose string) (*store.User, error) {
	if token == "" {
		return nil, errInvalidToken
	}
	row, err := s.store.GetEmailVerification(ctx, sha256Hex(token), purpose)
	if err != nil {
		return nil, errInvalidToken
	}
	if err := s.store.MarkEmailVerificationUsed(ctx, row.ID); err != nil {
		return nil, errInvalidToken
	}
	u, err := s.store.GetUserByIDFull(ctx, row.UserID)
	if err != nil {
		return nil, errInvalidToken
	}
	return u, nil
}
