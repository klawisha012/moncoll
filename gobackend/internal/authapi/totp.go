package authapi

// totp.go — TOTP enrolment endpoints. Faithful port of
// backend/src/auth/routers/totp.py (totp_setup + totp_confirm), including the
// session-or-enrol cookie resolution, the encrypted pending-secret cookie, and
// the per-user confirm rate-limit.

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
	"github.com/zwarder/waf/gobackend/internal/totp"
)

// resolveTotpUser reproduces routers/totp.py _resolve_user: try the session
// cookie first (logged-in user adding 2FA), then fall back to the short-lived
// enrol cookie (admin first-login). The enrol path is gated on
// totp_enabled_at IS NULL — a stolen enrol cookie can't re-enroll once TOTP is
// already active. Returns nil if neither path resolves a user.
func (s *Service) resolveTotpUser(ctx context.Context) *store.User {
	// 1. Session cookie. Enforce the revocation watermark: a token whose tv is
	// behind the user's current token_version (password change / logout-
	// everywhere) must NOT resolve a user here, or a revoked-but-unexpired
	// session could still enrol attacker-controlled 2FA. Mismatches fall
	// through to the enrol-cookie path (and ultimately nil).
	if tok := auth.CookieFromMetadata(ctx, sessionCookie); tok != "" {
		if claims, err := s.decoder.Decode(tok); err == nil {
			if uid, ok := parseUserID(claims.Sub); ok {
				if u, err := s.store.GetUserByIDFull(ctx, uid); err == nil && claims.TokenVersion == u.TokenVersion {
					return u
				}
			}
		}
	}
	// 2. Short-lived enrol cookie.
	if enrol := auth.CookieFromMetadata(ctx, totpEnrolCookie); enrol != "" {
		if payload, err := s.issuer.VerifyShortLived(enrol, "totp_enrol"); err == nil {
			if uidF, ok := payload["user_id"].(float64); ok {
				u, err := s.store.GetUserByIDFull(ctx, int64(uidF))
				// Single-use: enrol cookie only works while TOTP is un-activated.
				if err == nil && u.TotpEnabledAt == nil {
					return u
				}
			}
		}
	}
	return nil
}

// TotpSetup mirrors POST /totp/setup. Generates a fresh secret + recovery codes,
// stores them in an encrypted short-lived "pending" cookie (NOT the DB yet), and
// returns the provisioning URI + QR + plaintext recovery codes.
func (s *Service) TotpSetup(ctx context.Context, _ *authv1.TotpSetupRequest) (*authv1.TotpSetupResponse, error) {
	u := s.resolveTotpUser(ctx)
	if u == nil {
		return nil, status.Error(codes.Unauthenticated, "not authorized for totp enrol")
	}

	// Re-enrolment guard: if TOTP is already active, require the current code.
	// (The Python router reads it from the X-WAF-Current-TOTP header; that
	// header is not plumbed through the gateway, so we conservatively reject
	// re-enrolment of an already-active account here. Noted in the report.)
	if u.TotpEnabledAt != nil {
		return nil, status.Error(codes.PermissionDenied,
			"Verification with current TOTP or recovery code required to re-enroll 2FA")
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, status.Error(codes.Internal, "totp secret generation failed")
	}
	plain, hashes := totp.GenerateRecoveryCodes(10)

	// Stash the pending secret + hashes in an encrypted short-lived cookie,
	// mirroring encrypt_short_lived(purpose="totp_pending").
	pendingCookie, err := s.issuer.EncryptShortLived(map[string]any{
		"user_id": float64(u.ID),
		"secret":  secret,
		"hashes":  toAnySlice(hashes),
	}, shortLivedTTL, "totp_pending")
	if err != nil {
		return nil, status.Error(codes.Internal, "totp pending token failed")
	}
	emitSetCookie(ctx, buildCookie(totpPendingCookie, pendingCookie, 600, s.cfg.CookieSecure))

	uri := totp.ProvisioningURI(secret, u.Email, "WAF")
	qr, err := totp.QRDataURI(uri)
	if err != nil {
		// QR is non-essential (frontend can render from secret_base32); log + continue.
		s.log.Warn("totp setup: QR generation failed", "err", err)
	}
	return &authv1.TotpSetupResponse{
		SecretBase32:  secret,
		QrCodeDataUri: qr,
		RecoveryCodes: plain,
	}, nil
}

// TotpConfirm mirrors POST /totp/confirm. Verifies the code against the pending
// (or existing) secret, activates TOTP, persists the encrypted secret +
// recovery-code hashes, clears the pending/enrol cookies, and issues a full
// session cookie. Rate-limited per user_id.
func (s *Service) TotpConfirm(ctx context.Context, req *authv1.TotpConfirmRequest) (*authv1.TotpConfirmResponse, error) {
	u := s.resolveTotpUser(ctx)
	if u == nil {
		return nil, status.Error(codes.Unauthenticated, "not authorized")
	}

	// Determine the secret + hashes to confirm against: pending cookie if
	// present, else the user's existing (encrypted) secret.
	var secret string
	var hashes []string
	if pending := auth.CookieFromMetadata(ctx, totpPendingCookie); pending != "" {
		payload, err := s.issuer.DecryptShortLived(pending, "totp_pending")
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid or expired setup session")
		}
		if uidF, ok := payload["user_id"].(float64); !ok || int64(uidF) != u.ID {
			return nil, status.Error(codes.InvalidArgument, "invalid or expired setup session")
		}
		secret, _ = payload["secret"].(string)
		hashes = fromAnySlice(payload["hashes"])
	} else {
		if u.TotpSecret == nil {
			return nil, status.Error(codes.Unauthenticated, "not enrolled")
		}
		secret = s.decryptTotpSecret(*u.TotpSecret)
		hashes = u.RecoveryCodesHash
	}

	// Rate-limit check BEFORE verifying (bound attempts, not just successes).
	if s.totpConfirmTripped(u.ID) {
		s.log.Warn("totp.confirm: rate-limit tripped", "user_id", u.ID)
		return nil, status.Error(codes.ResourceExhausted, "too many failed attempts; try again later")
	}

	if !totp.Verify(secret, req.GetCode()) {
		s.recordTotpFail(u.ID)
		return nil, status.Error(codes.InvalidArgument, "invalid code")
	}
	s.clearTotpFails(u.ID)

	// Persist: encrypt the secret, store recovery hashes, set totp_enabled_at.
	encSecret, err := auth.FernetEncrypt(s.cfg.PasetoKey, secret)
	if err != nil {
		return nil, status.Error(codes.Internal, "totp secret encryption failed")
	}
	now := time.Now().UTC()
	if err := s.store.UpdateUser(ctx, u.ID, store.UserUpdate{
		TotpSecret:        &encSecret,
		RecoveryCodesHash: hashes,
		TotpEnabledAt:     &now,
	}); err != nil {
		return nil, status.Error(codes.Internal, "totp activation persist failed")
	}
	u.TotpEnabledAt = &now

	// Clear pending + enrol cookies, issue a full session cookie.
	emitSetCookie(ctx, clearCookie(totpPendingCookie, s.cfg.CookieSecure))
	emitSetCookie(ctx, clearCookie(totpEnrolCookie, s.cfg.CookieSecure))
	if err := s.issueSessionCookie(ctx, u); err != nil {
		return nil, err
	}
	return &authv1.TotpConfirmResponse{Ok: true, User: userPublic(u)}, nil
}

// ── per-user TOTP-confirm rate limiter (in-process, mirrors totp.py) ───────────

func (s *Service) totpConfirmTripped(userID int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-totpConfirmWindow)
	kept := s.confirmFails[userID][:0]
	for _, t := range s.confirmFails[userID] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.confirmFails[userID] = kept
	return len(kept) >= totpConfirmMaxFails
}

func (s *Service) recordTotpFail(userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.confirmFails[userID] = append(s.confirmFails[userID], time.Now())
}

func (s *Service) clearTotpFails(userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.confirmFails, userID)
}

// toAnySlice / fromAnySlice convert []string ↔ []any for JSON round-trip through
// the PASETO claims map (json.Unmarshal decodes arrays as []any of strings).
func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func fromAnySlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
