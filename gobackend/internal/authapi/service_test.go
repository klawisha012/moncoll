package authapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/oauth"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// ── test key + fakes ───────────────────────────────────────────────────────────

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// fakeStore is an in-memory Store with overridable behaviour per test.
type fakeStore struct {
	usersByEmail map[string]*store.User
	usersByID    map[int64]*store.User
	verifs       map[string]*store.EmailVerification // key: tokenHash|purpose
	oauthAccts   map[string]*store.OAuthAccount      // key: provider|providerAccountID
	tenants      map[string]*store.Tenant
	nextID       int64

	createUserErr error
	updates       []store.UserUpdate
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		usersByEmail: map[string]*store.User{},
		usersByID:    map[int64]*store.User{},
		verifs:       map[string]*store.EmailVerification{},
		oauthAccts:   map[string]*store.OAuthAccount{},
		tenants:      map[string]*store.Tenant{},
		nextID:       1,
	}
}

func (f *fakeStore) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	u, ok := f.usersByEmail[email]
	if !ok {
		return nil, &store.NotFoundError{Entity: "user"}
	}
	return u, nil
}
func (f *fakeStore) GetUserByIDFull(_ context.Context, id int64) (*store.User, error) {
	u, ok := f.usersByID[id]
	if !ok {
		return nil, &store.NotFoundError{Entity: "user"}
	}
	return u, nil
}
func (f *fakeStore) CreateUser(_ context.Context, u *store.User) (*store.User, error) {
	if f.createUserErr != nil {
		return nil, f.createUserErr
	}
	if _, exists := f.usersByEmail[u.Email]; exists {
		return nil, &store.ConflictError{Detail: "email already taken"}
	}
	u.ID = f.nextID
	f.nextID++
	cp := *u
	f.usersByEmail[u.Email] = &cp
	f.usersByID[u.ID] = &cp
	return &cp, nil
}
func (f *fakeStore) UpdateUser(_ context.Context, id int64, patch store.UserUpdate) error {
	f.updates = append(f.updates, patch)
	u, ok := f.usersByID[id]
	if !ok {
		return &store.NotFoundError{Entity: "user"}
	}
	if patch.EmailVerifiedAt != nil {
		u.EmailVerifiedAt = patch.EmailVerifiedAt
	}
	if patch.PasswordHash != nil {
		u.PasswordHash = patch.PasswordHash
	}
	if patch.TotpSecret != nil {
		u.TotpSecret = patch.TotpSecret
	}
	if patch.TotpEnabledAt != nil {
		u.TotpEnabledAt = patch.TotpEnabledAt
	}
	if patch.RecoveryCodesHash != nil {
		u.RecoveryCodesHash = patch.RecoveryCodesHash
	}
	if patch.LastLoginAt != nil {
		u.LastLoginAt = patch.LastLoginAt
	}
	return nil
}
func (f *fakeStore) CreateEmailVerification(_ context.Context, userID int64, tokenHash, purpose string, expiresAt time.Time) error {
	f.verifs[tokenHash+"|"+purpose] = &store.EmailVerification{
		ID: f.nextID, UserID: userID, Purpose: purpose, TokenHash: tokenHash, ExpiresAt: expiresAt,
	}
	f.nextID++
	return nil
}
func (f *fakeStore) GetEmailVerification(_ context.Context, tokenHash, purpose string) (*store.EmailVerification, error) {
	v, ok := f.verifs[tokenHash+"|"+purpose]
	if !ok || v.UsedAt != nil {
		return nil, &store.NotFoundError{Entity: "email_verification"}
	}
	return v, nil
}
func (f *fakeStore) MarkEmailVerificationUsed(_ context.Context, id int64) error {
	for _, v := range f.verifs {
		if v.ID == id {
			now := time.Now()
			v.UsedAt = &now
			return nil
		}
	}
	return &store.NotFoundError{Entity: "email_verification"}
}
func (f *fakeStore) GetOAuthAccount(_ context.Context, provider, pid string) (*store.OAuthAccount, error) {
	a, ok := f.oauthAccts[provider+"|"+pid]
	if !ok {
		return nil, &store.NotFoundError{Entity: "oauth_account"}
	}
	return a, nil
}
func (f *fakeStore) CreateOAuthAccount(_ context.Context, userID int64, provider, pid, email string) (*store.OAuthAccount, error) {
	a := &store.OAuthAccount{ID: f.nextID, UserID: userID, Provider: provider, ProviderAccountID: pid, EmailAtProvider: email}
	f.nextID++
	f.oauthAccts[provider+"|"+pid] = a
	return a, nil
}
func (f *fakeStore) CreateTenant(_ context.Context, name, displayName string) (*store.Tenant, error) {
	if err := store.ValidateTenantName(name); err != nil {
		return nil, err
	}
	if _, ok := f.tenants[name]; ok {
		return nil, &store.ConflictError{Detail: "tenant name taken"}
	}
	t := &store.Tenant{ID: f.nextID, Name: name}
	f.nextID++
	f.tenants[name] = t
	return t, nil
}
func (f *fakeStore) AutoCreateTenantForUser(_ context.Context, email, displayName string) (*store.Tenant, error) {
	name := "auto-tenant"
	t := &store.Tenant{ID: f.nextID, Name: name}
	f.nextID++
	f.tenants[name] = t
	return t, nil
}

// fakeEmail records sends.
type fakeEmail struct {
	verifySent int
	resetSent  int
	failVerify bool
}

func (f *fakeEmail) SendVerificationEmail(_ context.Context, _, _, _ string) error {
	f.verifySent++
	if f.failVerify {
		return errors.New("smtp down")
	}
	return nil
}
func (f *fakeEmail) SendPasswordResetEmail(_ context.Context, _, _, _ string) error {
	f.resetSent++
	return nil
}

// fakeCaptcha returns a fixed result.
type fakeCaptcha struct {
	ok     bool
	called int
	err    error
}

func (f *fakeCaptcha) Verify(_ context.Context, _, _ string) (bool, error) {
	f.called++
	return f.ok, f.err
}

// fakeOAuth factory + provider.
type fakeOAuthFactory struct {
	prov *fakeOAuthProvider
	ok   bool
}

func (f *fakeOAuthFactory) Provider(string) (OAuthProvider, bool) {
	if !f.ok {
		return nil, false
	}
	return f.prov, true
}

type fakeOAuthProvider struct {
	authURL string
	info    *oauth.UserInfo
	exchErr error
}

func (p *fakeOAuthProvider) AuthCodeURL(state string) string {
	return p.authURL + "?state=" + state
}
func (p *fakeOAuthProvider) Exchange(_ context.Context, _ string) (*oauth.UserInfo, error) {
	return p.info, p.exchErr
}

// ── harness ─────────────────────────────────────────────────────────────────────

type harness struct {
	svc     *Service
	st      *fakeStore
	email   *fakeEmail
	captcha *fakeCaptcha
	oauth   *fakeOAuthFactory
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	if cfg.PasetoKey == nil {
		cfg.PasetoKey = testKey()
	}
	st := newFakeStore()
	em := &fakeEmail{}
	cap := &fakeCaptcha{ok: true}
	of := &fakeOAuthFactory{ok: false}
	svc := New(st, auth.NewIssuer(cfg.PasetoKey), auth.NewDecoder(cfg.PasetoKey), em, cap, of, cfg, nil)
	return &harness{svc: svc, st: st, email: em, captcha: cap, oauth: of}
}

// captureCtx returns a context + a recorder for emitted response metadata.
// We run handlers inside a fake grpc server stream so grpc.SetHeader works.
type mdRecorder struct {
	md metadata.MD
}

// runWithMD executes fn inside a server context where grpc.SetHeader records
// into rec. grpc.SetHeader requires a server transport stream; we emulate it by
// using the grpc test helper of attaching a header carrier.
func runWithMD(ctx context.Context, fn func(context.Context) error) (metadata.MD, error) {
	// grpc.SetHeader writes to the stream's header. We use
	// grpc.NewContextWithServerTransportStream with a recording stream.
	rec := &recordingStream{md: metadata.MD{}}
	sctx := grpc.NewContextWithServerTransportStream(ctx, rec)
	err := fn(sctx)
	return rec.md, err
}

type recordingStream struct {
	md metadata.MD
}

func (r *recordingStream) Method() string { return "test" }
func (r *recordingStream) SetHeader(md metadata.MD) error {
	for k, v := range md {
		r.md[k] = append(r.md[k], v...)
	}
	return nil
}
func (r *recordingStream) SendHeader(md metadata.MD) error { return r.SetHeader(md) }
func (r *recordingStream) SetTrailer(md metadata.MD) error { return nil }

// hasCookie reports whether any x-set-cookie value contains substr.
func hasCookie(md metadata.MD, substr string) bool {
	for _, c := range md.Get(mdSetCookie) {
		if substrContains(c, substr) {
			return true
		}
	}
	return false
}
func substrContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ctxWithCookie attaches a Cookie header to the incoming metadata.
func ctxWithCookie(cookie string) context.Context {
	md := metadata.New(map[string]string{"grpcgateway-cookie": cookie})
	return metadata.NewIncomingContext(context.Background(), md)
}

// ── providers ─────────────────────────────────────────────────────────────────

func TestProvidersReflectsConfig(t *testing.T) {
	h := newHarness(t, Config{GoogleEnabled: true, GitHubEnabled: false, CaptchaSiteKey: "", SMTPConfigured: false})
	resp, err := h.svc.GetProviders(context.Background(), &authv1.ProvidersRequest{})
	require.NoError(t, err)
	require.True(t, resp.Google)
	require.False(t, resp.Github)
	require.Equal(t, turnstileDevSiteKey, resp.CaptchaSiteKey)
	require.True(t, resp.CaptchaDevMode)
	require.True(t, resp.SmtpDevMode)

	h2 := newHarness(t, Config{CaptchaSiteKey: "realkey", SMTPConfigured: true})
	resp2, _ := h2.svc.GetProviders(context.Background(), &authv1.ProvidersRequest{})
	require.Equal(t, "realkey", resp2.CaptchaSiteKey)
	require.False(t, resp2.CaptchaDevMode)
	require.False(t, resp2.SmtpDevMode)
}

// ── signup ────────────────────────────────────────────────────────────────────

func TestSignupCreatesUserTokenEmail(t *testing.T) {
	h := newHarness(t, Config{SMTPConfigured: true})
	resp, err := h.svc.Signup(context.Background(), &authv1.SignupRequest{
		Email: "Alice@Example.com", Password: "supersecret", TenantName: "acme-co", CaptchaToken: "t",
	})
	require.NoError(t, err)
	require.Equal(t, 1, h.captcha.called)
	require.Equal(t, 1, h.email.verifySent)
	require.Equal(t, "check your email", resp.Message)
	require.Empty(t, resp.DevVerifyUrl) // smtp configured + send ok → no dev url
	// user created (lowercased email), unverified
	u, ok := h.st.usersByEmail["alice@example.com"]
	require.True(t, ok)
	require.Nil(t, u.EmailVerifiedAt)
	require.Equal(t, "client", u.PlatformRole)
	require.Len(t, h.st.verifs, 1)
}

func TestSignupCaptchaRejected(t *testing.T) {
	h := newHarness(t, Config{})
	h.captcha.ok = false
	_, err := h.svc.Signup(context.Background(), &authv1.SignupRequest{
		Email: "a@b.com", Password: "supersecret", TenantName: "acme-co", CaptchaToken: "bad",
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Empty(t, h.st.usersByEmail)
}

func TestSignupDevVerifyURLWhenNoSMTP(t *testing.T) {
	h := newHarness(t, Config{SMTPConfigured: false})
	resp, err := h.svc.Signup(context.Background(), &authv1.SignupRequest{
		Email: "a@b.com", Password: "supersecret", TenantName: "acme-co", CaptchaToken: "t",
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.DevVerifyUrl)
}

// ── verify-email ────────────────────────────────────────────────────────────────

func TestVerifyEmailSetsCookieAndVerifies(t *testing.T) {
	h := newHarness(t, Config{})
	// seed an unverified user + a verify token.
	u := &store.User{ID: 5, Email: "a@b.com", PlatformRole: "client", DisplayName: "a"}
	h.st.usersByID[5] = u
	h.st.verifs[sha256Hex("tok123")+"|verify_email"] = &store.EmailVerification{ID: 9, UserID: 5, Purpose: "verify_email"}

	md, err := runWithMD(context.Background(), func(ctx context.Context) error {
		_, e := h.svc.VerifyEmail(ctx, &authv1.VerifyEmailRequest{Token: "tok123"})
		return e
	})
	require.NoError(t, err)
	require.True(t, hasCookie(md, sessionCookie+"="))
	require.NotNil(t, h.st.usersByID[5].EmailVerifiedAt)
}

func TestVerifyEmailBadToken(t *testing.T) {
	h := newHarness(t, Config{})
	_, err := h.svc.VerifyEmail(context.Background(), &authv1.VerifyEmailRequest{Token: "nope"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ── login ─────────────────────────────────────────────────────────────────────

func seedVerifiedClient(t *testing.T, h *harness, email, password string) *store.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	require.NoError(t, err)
	now := time.Now()
	u := &store.User{
		ID: 11, Email: email, DisplayName: "u", PlatformRole: "client",
		PasswordHash: &hash, EmailVerifiedAt: &now,
	}
	h.st.usersByEmail[email] = u
	h.st.usersByID[11] = u
	return u
}

func TestLoginGoodCredsSetsCookie(t *testing.T) {
	h := newHarness(t, Config{})
	seedVerifiedClient(t, h, "a@b.com", "supersecret")
	md, err := runWithMD(context.Background(), func(ctx context.Context) error {
		_, e := h.svc.Login(ctx, &authv1.LoginRequest{Email: "A@B.com", Password: "supersecret", CaptchaToken: "t"})
		return e
	})
	require.NoError(t, err)
	require.True(t, hasCookie(md, sessionCookie+"="))
}

func TestLoginBadCredsUnauthenticated(t *testing.T) {
	h := newHarness(t, Config{})
	seedVerifiedClient(t, h, "a@b.com", "supersecret")
	_, err := h.svc.Login(context.Background(), &authv1.LoginRequest{Email: "a@b.com", Password: "wrong", CaptchaToken: "t"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.Equal(t, "invalid credentials", status.Convert(err).Message())
}

func TestLoginUnknownUserUnauthenticated(t *testing.T) {
	h := newHarness(t, Config{})
	_, err := h.svc.Login(context.Background(), &authv1.LoginRequest{Email: "ghost@b.com", Password: "x", CaptchaToken: "t"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestLoginUnverifiedEmail(t *testing.T) {
	h := newHarness(t, Config{})
	hash, _ := auth.HashPassword("supersecret")
	u := &store.User{ID: 12, Email: "a@b.com", PlatformRole: "client", PasswordHash: &hash}
	h.st.usersByEmail["a@b.com"] = u
	h.st.usersByID[12] = u
	_, err := h.svc.Login(context.Background(), &authv1.LoginRequest{Email: "a@b.com", Password: "supersecret", CaptchaToken: "t"})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Equal(t, "email not verified", status.Convert(err).Message())
}

func TestLoginTotpEnabledRequiresCode(t *testing.T) {
	h := newHarness(t, Config{})
	u := seedVerifiedClient(t, h, "a@b.com", "supersecret")
	// enable totp with a known secret (Fernet-encrypted).
	secret := "JBSWY3DPEHPK3PXP"
	enc, err := auth.FernetEncrypt(testKey(), secret)
	require.NoError(t, err)
	now := time.Now()
	u.TotpSecret = &enc
	u.TotpEnabledAt = &now

	// no code → totp_required
	_, err = h.svc.Login(context.Background(), &authv1.LoginRequest{Email: "a@b.com", Password: "supersecret", CaptchaToken: "t"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.Equal(t, "totp_required", status.Convert(err).Message())

	// wrong code → invalid totp
	_, err = h.svc.Login(context.Background(), &authv1.LoginRequest{Email: "a@b.com", Password: "supersecret", CaptchaToken: "t", TotpCode: "000000"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.Equal(t, "invalid totp", status.Convert(err).Message())
}

// ── logout ───────────────────────────────────────────────────────────────────

func TestLogoutClearsCookie(t *testing.T) {
	h := newHarness(t, Config{})
	md, err := runWithMD(context.Background(), func(ctx context.Context) error {
		_, e := h.svc.Logout(ctx, &authv1.LogoutRequest{})
		return e
	})
	require.NoError(t, err)
	require.True(t, hasCookie(md, sessionCookie+"=")) // cleared cookie still names the key
	require.True(t, hasCookie(md, "Max-Age=0"))
}

// ── me ─────────────────────────────────────────────────────────────────────────

func TestMeValidCookie(t *testing.T) {
	h := newHarness(t, Config{})
	now := time.Now()
	u := &store.User{ID: 7, Email: "a@b.com", DisplayName: "a", PlatformRole: "client", EmailVerifiedAt: &now}
	h.st.usersByID[7] = u
	tok, err := auth.NewIssuer(testKey()).CreateSessionToken(7, "client", nil, nil)
	require.NoError(t, err)

	resp, err := h.svc.Me(ctxWithCookie(sessionCookie+"="+tok), &authv1.MeRequest{})
	require.NoError(t, err)
	require.Equal(t, int64(7), resp.Id)
	require.Equal(t, "a@b.com", resp.Email)
}

func TestMeNoCookieUnauthenticated(t *testing.T) {
	h := newHarness(t, Config{})
	_, err := h.svc.Me(context.Background(), &authv1.MeRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ── forgot ───────────────────────────────────────────────────────────────────

func TestForgotAlways202NoLeak(t *testing.T) {
	h := newHarness(t, Config{SMTPConfigured: true})
	// unknown email → still 202, no email sent
	resp, err := h.svc.ForgotPassword(context.Background(), &authv1.ForgotPasswordRequest{Email: "ghost@b.com", CaptchaToken: "t"})
	require.NoError(t, err)
	require.Equal(t, "if that email exists, a reset link was sent", resp.Message)
	require.Equal(t, 0, h.email.resetSent)
	require.Empty(t, resp.DevResetUrl)

	// known verified email → 202 + email sent, same message
	seedVerifiedClient(t, h, "a@b.com", "supersecret")
	resp2, err := h.svc.ForgotPassword(context.Background(), &authv1.ForgotPasswordRequest{Email: "a@b.com", CaptchaToken: "t"})
	require.NoError(t, err)
	require.Equal(t, resp.Message, resp2.Message)
	require.Equal(t, 1, h.email.resetSent)
}

// ── reset ─────────────────────────────────────────────────────────────────────

func TestResetUpdatesPassword(t *testing.T) {
	h := newHarness(t, Config{})
	u := &store.User{ID: 3, Email: "a@b.com", PlatformRole: "client"}
	h.st.usersByID[3] = u
	h.st.verifs[sha256Hex("rt")+"|reset_password"] = &store.EmailVerification{ID: 21, UserID: 3, Purpose: "reset_password"}

	_, err := h.svc.ResetPassword(context.Background(), &authv1.ResetPasswordRequest{Token: "rt", NewPassword: "brandnewpass"})
	require.NoError(t, err)
	require.NotNil(t, h.st.usersByID[3].PasswordHash)
	require.True(t, auth.VerifyPassword("brandnewpass", *h.st.usersByID[3].PasswordHash))
}

func TestResetBadToken(t *testing.T) {
	h := newHarness(t, Config{})
	_, err := h.svc.ResetPassword(context.Background(), &authv1.ResetPasswordRequest{Token: "nope", NewPassword: "brandnewpass"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ── totp setup + confirm ────────────────────────────────────────────────────────

func TestTotpSetupAndConfirmRoundTrip(t *testing.T) {
	h := newHarness(t, Config{})
	now := time.Now()
	u := &store.User{ID: 30, Email: "a@b.com", DisplayName: "a", PlatformRole: "client", EmailVerifiedAt: &now}
	h.st.usersByID[30] = u
	sessTok, _ := auth.NewIssuer(testKey()).CreateSessionToken(30, "client", nil, nil)
	baseCtx := ctxWithCookie(sessionCookie + "=" + sessTok)

	// setup → returns secret + recovery codes + sets pending cookie.
	var setupResp *authv1.TotpSetupResponse
	md, err := runWithMD(baseCtx, func(ctx context.Context) error {
		r, e := h.svc.TotpSetup(ctx, &authv1.TotpSetupRequest{})
		setupResp = r
		return e
	})
	require.NoError(t, err)
	require.NotEmpty(t, setupResp.SecretBase32)
	require.Len(t, setupResp.RecoveryCodes, 10)
	require.True(t, hasCookie(md, totpPendingCookie+"="))

	// Extract the pending cookie value from the emitted Set-Cookie.
	pendingVal := extractCookieVal(md, totpPendingCookie)
	require.NotEmpty(t, pendingVal)

	// Generate a valid current code from the secret.
	code := genCode(t, setupResp.SecretBase32)

	// confirm with the pending cookie + session cookie.
	confirmCtx := ctxWithCookie(sessionCookie + "=" + sessTok + "; " + totpPendingCookie + "=" + pendingVal)
	var confirmResp *authv1.TotpConfirmResponse
	md2, err := runWithMD(confirmCtx, func(ctx context.Context) error {
		r, e := h.svc.TotpConfirm(ctx, &authv1.TotpConfirmRequest{Code: code})
		confirmResp = r
		return e
	})
	require.NoError(t, err)
	require.True(t, confirmResp.Ok)
	require.True(t, hasCookie(md2, sessionCookie+"="))
	// TOTP secret stored encrypted; decrypts back to the original secret.
	require.NotNil(t, h.st.usersByID[30].TotpSecret)
	dec, err := auth.FernetDecrypt(testKey(), *h.st.usersByID[30].TotpSecret)
	require.NoError(t, err)
	require.Equal(t, setupResp.SecretBase32, dec)
	require.NotNil(t, h.st.usersByID[30].TotpEnabledAt)
}

func TestTotpConfirmWrongCodeRejected(t *testing.T) {
	h := newHarness(t, Config{})
	now := time.Now()
	u := &store.User{ID: 31, Email: "a@b.com", DisplayName: "a", PlatformRole: "client", EmailVerifiedAt: &now}
	h.st.usersByID[31] = u
	sessTok, _ := auth.NewIssuer(testKey()).CreateSessionToken(31, "client", nil, nil)

	var setupResp *authv1.TotpSetupResponse
	md, _ := runWithMD(ctxWithCookie(sessionCookie+"="+sessTok), func(ctx context.Context) error {
		r, e := h.svc.TotpSetup(ctx, &authv1.TotpSetupRequest{})
		setupResp = r
		return e
	})
	pendingVal := extractCookieVal(md, totpPendingCookie)
	_ = setupResp

	confirmCtx := ctxWithCookie(sessionCookie + "=" + sessTok + "; " + totpPendingCookie + "=" + pendingVal)
	_, err := h.svc.TotpConfirm(confirmCtx, &authv1.TotpConfirmRequest{Code: "000000"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Nil(t, h.st.usersByID[31].TotpEnabledAt)
}

func TestTotpSetupNoAuthRejected(t *testing.T) {
	h := newHarness(t, Config{})
	_, err := h.svc.TotpSetup(context.Background(), &authv1.TotpSetupRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ── oauth ─────────────────────────────────────────────────────────────────────

func TestOauthStartRedirectsWithState(t *testing.T) {
	h := newHarness(t, Config{})
	h.oauth.ok = true
	h.oauth.prov = &fakeOAuthProvider{authURL: "https://accounts.google.com/o/oauth2/auth"}
	h.svc.cfg.GoogleRedirect = "http://localhost/api/auth/oauth/google/callback"

	md, err := runWithMD(context.Background(), func(ctx context.Context) error {
		_, e := h.svc.OauthStart(ctx, &authv1.OauthStartRequest{Provider: "google", Intent: "login"})
		return e
	})
	require.NoError(t, err)
	require.True(t, hasCookie(md, oauthStateCookie+"="))
	require.NotEmpty(t, md.Get(mdRedirect))
}

func TestOauthStartUnconfiguredRedirectsError(t *testing.T) {
	h := newHarness(t, Config{})
	h.oauth.ok = false
	md, err := runWithMD(context.Background(), func(ctx context.Context) error {
		_, e := h.svc.OauthStart(ctx, &authv1.OauthStartRequest{Provider: "google", Intent: "login"})
		return e
	})
	require.NoError(t, err)
	loc := md.Get(mdRedirect)
	require.NotEmpty(t, loc)
	require.Contains(t, loc[0], "provider_unavailable")
}

func TestOauthCallbackStateMismatchRejected(t *testing.T) {
	h := newHarness(t, Config{})
	h.oauth.ok = true
	h.oauth.prov = &fakeOAuthProvider{}
	// sign a valid state but send a different cookie.
	state, err := h.svc.issuer.SignShortLived(map[string]any{"intent": "login", "provider": "google"}, shortLivedTTL, "oauth_state")
	require.NoError(t, err)

	ctx := ctxWithCookie(oauthStateCookie + "=DIFFERENT")
	md, err := runWithMD(ctx, func(c context.Context) error {
		_, e := h.svc.OauthCallback(c, &authv1.OauthCallbackRequest{Provider: "google", Code: "x", State: state})
		return e
	})
	require.NoError(t, err)
	require.Contains(t, md.Get(mdRedirect)[0], "state_mismatch")
}

func TestOauthCallbackSuccessCreatesUserAndCookie(t *testing.T) {
	h := newHarness(t, Config{})
	h.oauth.ok = true
	h.oauth.prov = &fakeOAuthProvider{info: &oauth.UserInfo{
		ProviderAccountID: "sub-123", Email: "new@user.com", EmailVerified: true, DisplayName: "New User",
	}}
	state, err := h.svc.issuer.SignShortLived(map[string]any{"intent": "signup", "provider": "google"}, shortLivedTTL, "oauth_state")
	require.NoError(t, err)
	ctx := ctxWithCookie(oauthStateCookie + "=" + state)

	md, err := runWithMD(ctx, func(c context.Context) error {
		_, e := h.svc.OauthCallback(c, &authv1.OauthCallbackRequest{Provider: "google", Code: "code", State: state})
		return e
	})
	require.NoError(t, err)
	require.True(t, hasCookie(md, sessionCookie+"="))
	require.Contains(t, md.Get(mdRedirect)[0], "/home")
	// user + oauth account created
	u, ok := h.st.usersByEmail["new@user.com"]
	require.True(t, ok)
	require.NotNil(t, u.EmailVerifiedAt)
	_, ok = h.st.oauthAccts["google|sub-123"]
	require.True(t, ok)
}

func TestOauthCallbackUnverifiedEmailRejected(t *testing.T) {
	h := newHarness(t, Config{})
	h.oauth.ok = true
	h.oauth.prov = &fakeOAuthProvider{info: &oauth.UserInfo{ProviderAccountID: "s", Email: "x@y.com", EmailVerified: false}}
	state, _ := h.svc.issuer.SignShortLived(map[string]any{"intent": "login", "provider": "google"}, shortLivedTTL, "oauth_state")
	ctx := ctxWithCookie(oauthStateCookie + "=" + state)
	md, err := runWithMD(ctx, func(c context.Context) error {
		_, e := h.svc.OauthCallback(c, &authv1.OauthCallbackRequest{Provider: "google", Code: "code", State: state})
		return e
	})
	require.NoError(t, err)
	require.Contains(t, md.Get(mdRedirect)[0], "email_not_verified")
}
