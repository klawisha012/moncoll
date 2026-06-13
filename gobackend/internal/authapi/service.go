// Package authapi implements the AuthService gRPC server — a faithful port of
// backend/src/auth/routers/{password,totp,oauth}.py. It owns credential checks,
// TOTP enforcement (Fernet-encrypted secret, cross-compatible with Python),
// session-cookie issuance (via response metadata), OAuth state CSRF, and the
// no-user-existence-leak forgot-password flow.
//
// SECURITY-CRITICAL. Every credential / TOTP / state check below mirrors the
// Python original; do not weaken any of them.
package authapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/oauth"
	"github.com/zwarder/waf/gobackend/internal/store"
	"github.com/zwarder/waf/gobackend/internal/totp"
)

// ── Injected dependency interfaces (unit-testable with fakes) ──────────────────

// Store is the persistence surface the auth service needs.
type Store interface {
	GetUserByEmail(ctx context.Context, email string) (*store.User, error)
	GetUserByIDFull(ctx context.Context, id int64) (*store.User, error)
	CreateUser(ctx context.Context, u *store.User) (*store.User, error)
	UpdateUser(ctx context.Context, id int64, patch store.UserUpdate) error

	CreateEmailVerification(ctx context.Context, userID int64, tokenHash, purpose string, expiresAt time.Time) error
	GetEmailVerification(ctx context.Context, tokenHash, purpose string) (*store.EmailVerification, error)
	MarkEmailVerificationUsed(ctx context.Context, id int64) error

	GetOAuthAccount(ctx context.Context, provider, providerAccountID string) (*store.OAuthAccount, error)
	CreateOAuthAccount(ctx context.Context, userID int64, provider, providerAccountID, emailAtProvider string) (*store.OAuthAccount, error)

	CreateTenant(ctx context.Context, name, displayName string) (*store.Tenant, error)
	AutoCreateTenantForUser(ctx context.Context, email, displayName string) (*store.Tenant, error)

	CreateMembership(ctx context.Context, tenantID, userID int64, role string) error

	ListPendingInvitationsForEmail(ctx context.Context, email string) ([]store.Invitation, error)
	AcceptInvitation(ctx context.Context, inv *store.Invitation, userID int64) error
	SetActiveTenant(ctx context.Context, userID, tenantID int64) error
}

// EmailSender mirrors internal/email.Sender (verify + reset emails).
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, to, displayName, verifyURL string) error
	SendPasswordResetEmail(ctx context.Context, to, displayName, resetURL string) error
}

// CaptchaVerifier mirrors internal/captcha.Verifier.
type CaptchaVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
}

// OAuthProviderFactory builds an oauth.Provider for a named provider, returning
// (nil,false) when the provider is not configured. Mirrors oauth.NewProvider.
type OAuthProviderFactory interface {
	Provider(name string) (OAuthProvider, bool)
}

// OAuthProvider is the per-provider surface the service uses. redirectURI is
// the dynamic callback URL (derived from the incoming host) and must be the
// same value for both calls within one flow.
type OAuthProvider interface {
	AuthCodeURL(state, redirectURI string) string
	Exchange(ctx context.Context, code, redirectURI string) (*oauth.UserInfo, error)
}

// Config carries runtime feature flags + the PASETO key (for Fernet).
type Config struct {
	PasetoKey      []byte
	CookieSecure   bool
	PublicBaseURL  string // e.g. https://waf.example.com
	GoogleEnabled  bool
	GitHubEnabled  bool
	CaptchaSiteKey string // turnstile_site_key (may be empty → dev key used)
	CaptchaConfig  bool   // true when WAF_TURNSTILE_SECRET_KEY set
	SMTPConfigured bool   // true when WAF_SMTP_HOST set
	GoogleRedirect string // WAF_OAUTH_GOOGLE_REDIRECT_URI
	GitHubRedirect string // WAF_OAUTH_GITHUB_REDIRECT_URI
}

// turnstileDevSiteKey mirrors _TURNSTILE_DEV_SITE_KEY in password.py — the
// Cloudflare test key that always passes, surfaced so the widget renders in dev.
const turnstileDevSiteKey = "1x00000000000000000000AA"

// Verification TTLs mirror verification.py TTL map.
const (
	verifyEmailTTL   = 24 * time.Hour
	resetPasswordTTL = 1 * time.Hour
)

// TOTP confirm rate-limit mirrors routers/totp.py.
const (
	totpConfirmWindow   = 5 * time.Minute
	totpConfirmMaxFails = 5
)

// shortLivedTTL for enrol / pending / oauth-state cookies (600s in Python).
const shortLivedTTL = 600 * time.Second

// Service implements authv1.AuthServiceServer.
type Service struct {
	authv1.UnimplementedAuthServiceServer

	store   Store
	issuer  *auth.Issuer
	decoder *auth.Decoder
	email   EmailSender
	captcha CaptchaVerifier
	oauth   OAuthProviderFactory
	cfg     Config
	log     *slog.Logger

	// In-process per-user TOTP-confirm failure budget (mirrors the Python
	// in-process counter). Best-effort; resets on restart.
	mu           sync.Mutex
	confirmFails map[int64][]time.Time
}

// New constructs the auth service.
func New(
	st Store,
	issuer *auth.Issuer,
	decoder *auth.Decoder,
	mailer EmailSender,
	cap CaptchaVerifier,
	oauthFactory OAuthProviderFactory,
	cfg Config,
	log *slog.Logger,
) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		store:        st,
		issuer:       issuer,
		decoder:      decoder,
		email:        mailer,
		captcha:      cap,
		oauth:        oauthFactory,
		cfg:          cfg,
		log:          log,
		confirmFails: make(map[int64][]time.Time),
	}
}

func (s *Service) AuthLevels() map[string]auth.Level {
	return map[string]auth.Level{
		authv1.AuthService_GetProviders_FullMethodName:   auth.LevelPublic,
		authv1.AuthService_Signup_FullMethodName:         auth.LevelPublic,
		authv1.AuthService_VerifyEmail_FullMethodName:    auth.LevelPublic,
		authv1.AuthService_Login_FullMethodName:          auth.LevelPublic,
		authv1.AuthService_Logout_FullMethodName:         auth.LevelPublic,
		authv1.AuthService_Me_FullMethodName:             auth.LevelPublic,
		authv1.AuthService_ForgotPassword_FullMethodName: auth.LevelPublic,
		authv1.AuthService_ResetPassword_FullMethodName:  auth.LevelPublic,
		authv1.AuthService_TotpSetup_FullMethodName:      auth.LevelPublic,
		authv1.AuthService_TotpConfirm_FullMethodName:    auth.LevelPublic,
		authv1.AuthService_OauthStart_FullMethodName:     auth.LevelPublic,
		authv1.AuthService_OauthCallback_FullMethodName:  auth.LevelPublic,
		authv1.AuthService_ListAccounts_FullMethodName:   auth.LevelPublic,
		authv1.AuthService_SwitchAccount_FullMethodName:  auth.LevelPublic,
	}
}

// ── helpers ────────────────────────────────────────────────────────────────────

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// randomURLToken mirrors secrets.token_urlsafe(32) — 32 random bytes, base64url
// without padding.
func randomURLToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// userPublic builds the proto UserPublic from a store.User, mirroring
// schemas.py UserPublic.from_user.
func userPublic(u *store.User) *authv1.UserPublic {
	up := &authv1.UserPublic{
		Id:            u.ID,
		Email:         u.Email,
		DisplayName:   u.DisplayName,
		PlatformRole:  u.PlatformRole,
		EmailVerified: u.EmailVerifiedAt != nil,
		TotpEnabled:   u.TotpEnabledAt != nil,
	}
	if u.TenantID != nil {
		up.TenantId = *u.TenantID
		up.HasTenantId = true
	}
	if u.TenantRole != nil {
		up.TenantRole = *u.TenantRole
		up.HasTenantRole = true
	}
	return up
}

// mintSessionToken creates a session token for u (no cookie emission).
func (s *Service) mintSessionToken(u *store.User) (string, error) {
	tok, err := s.issuer.CreateSessionToken(u.ID, u.PlatformRole, u.TenantID, u.TenantRole, u.TokenVersion)
	if err != nil {
		return "", status.Error(codes.Internal, "session token issuance failed")
	}
	return tok, nil
}

// issueSessionCookie mints a session token for u and emits it as the active
// session cookie. Mirrors _set_session_cookie.
func (s *Service) issueSessionCookie(ctx context.Context, u *store.User) error {
	tok, err := s.mintSessionToken(u)
	if err != nil {
		return err
	}
	emitSetCookie(ctx, buildCookie(sessionCookie, tok, sessionMaxAge(), s.cfg.CookieSecure))
	return nil
}

// decryptTotpSecret reproduces totp.py decrypt_secret: Fernet-decrypt; on any
// failure fall back to the raw value (legacy-unencrypted secret transition).
func (s *Service) decryptTotpSecret(enc string) string {
	if enc == "" {
		return ""
	}
	plain, err := auth.FernetDecrypt(s.cfg.PasetoKey, enc)
	if err != nil {
		return enc // legacy unencrypted fallback (matches Python)
	}
	return plain
}

// verifyStoredTotp checks code against the user's Fernet-encrypted secret,
// mirroring totp.py verify_code (decrypt then pyotp verify, valid_window=1).
func (s *Service) verifyStoredTotp(u *store.User, code string) bool {
	if u.TotpSecret == nil {
		return false
	}
	secret := s.decryptTotpSecret(*u.TotpSecret)
	return totp.Verify(secret, code)
}

// verifyRecoveryAndConsume checks code against the user's recovery-code hashes
// and, on match, removes the used hash (single-use). Mirrors totp.py
// verify_recovery. Returns true if consumed.
func (s *Service) verifyRecoveryAndConsume(ctx context.Context, u *store.User, code string) bool {
	if len(u.RecoveryCodesHash) == 0 {
		return false
	}
	idx, ok := totp.VerifyRecoveryCode(code, u.RecoveryCodesHash)
	if !ok {
		return false
	}
	remaining := make([]string, 0, len(u.RecoveryCodesHash)-1)
	for i, h := range u.RecoveryCodesHash {
		if i != idx {
			remaining = append(remaining, h)
		}
	}
	if err := s.store.UpdateUser(ctx, u.ID, store.UserUpdate{RecoveryCodesHash: remaining}); err != nil {
		s.log.Warn("recovery code consume: UpdateUser failed", "err", err)
		return false
	}
	u.RecoveryCodesHash = remaining
	return true
}

// publicBaseURL returns the configured public base URL or a localhost default,
// mirroring Settings.public_base_url default ("http://localhost").
func (s *Service) publicBaseURL() string {
	if s.cfg.PublicBaseURL != "" {
		return strings.TrimRight(s.cfg.PublicBaseURL, "/")
	}
	return "http://localhost"
}

// captchaErr maps a captcha failure to PermissionDenied("captcha failed"),
// mirroring captcha.verify_or_raise raising 403. Returns nil when verified.
func (s *Service) checkCaptcha(ctx context.Context, token string) error {
	ok, err := s.captcha.Verify(ctx, token, "")
	if err != nil {
		return status.Error(codes.Internal, "captcha verification error")
	}
	if !ok {
		return status.Error(codes.PermissionDenied, "captcha failed")
	}
	return nil
}

// errIsNotFound reports whether err is a store.NotFoundError.
func errIsNotFound(err error) bool {
	var nf *store.NotFoundError
	return errors.As(err, &nf)
}

// errIsConflict reports whether err is a store.ConflictError.
func errIsConflict(err error) bool {
	var c *store.ConflictError
	return errors.As(err, &c)
}

// parseUserID parses a token "sub" claim into int64.
func parseUserID(sub string) (int64, bool) {
	id, err := strconv.ParseInt(sub, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// errInvalidToken is the sentinel used by consumeVerification on any failure
// (mirrors verification.consume returning None for all failure modes).
var errInvalidToken = errors.New("invalid or expired token")

// normalizeEmail lowercases + trims the email, mirroring email.lower() in
// service.py / get_by_email.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// localPart returns the part of an email before "@", mirroring
// email.split("@")[0] used as a default display name.
func localPart(email string) string {
	if i := strings.Index(email, "@"); i >= 0 {
		return email[:i]
	}
	return email
}

// isInvalidTenantName reports whether err is store.ErrInvalidTenantName.
func isInvalidTenantName(err error) bool {
	return errors.Is(err, store.ErrInvalidTenantName)
}
