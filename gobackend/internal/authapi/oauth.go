package authapi

// oauth.go — OAuth2 start + callback. Faithful port of
// backend/src/auth/routers/oauth.py. Both endpoints return a 302 redirect
// carried via response metadata (x-redirect); the callback also sets the
// session cookie via x-set-cookie. State is HMAC-signed (SignShortLived) and
// double-submitted against a cookie (CSRF protection).

import (
	"context"
	"net/url"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
	"time"
)

// nowUTC is a thin wrapper so OAuth timestamps are consistent + testable.
func nowUTC() time.Time { return time.Now().UTC() }

func configuredPublicBaseURL(cfg Config) string {
	return strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/")
}

// providerRedirectURI computes the OAuth callback redirect URI from trusted
// configuration only. Client-supplied Host/X-Forwarded-Host metadata must not
// influence OAuth provider callbacks.
func (s *Service) providerRedirectURI(ctx context.Context, provider string) string {
	_ = ctx
	if base := configuredPublicBaseURL(s.cfg); base != "" {
		return base + "/api/auth/oauth/" + provider + "/callback"
	}
	switch provider {
	case "google":
		return s.cfg.GoogleRedirect
	case "github":
		return s.cfg.GitHubRedirect
	}
	return ""
}

// frontendBase returns the trusted scheme://host prefix for redirects back to
// the SPA. With no configured public URL, handlers return relative redirects.
func (s *Service) frontendBase(ctx context.Context) string {
	_ = ctx
	return configuredPublicBaseURL(s.cfg)
}

// redirectWithError sends the user back to /signup or /login with ?oauth_error=,
// clearing the state cookie. Mirrors _redirect_with_error.
func (s *Service) redirectWithError(ctx context.Context, intent, code string) (*authv1.OauthRedirect, error) {
	target := "/login"
	if intent == "signup" {
		target = "/signup"
	}
	loc := s.frontendBase(ctx) + target + "?oauth_error=" + url.QueryEscape(code)
	emitSetCookie(ctx, clearCookie(oauthStateCookie, s.cfg.CookieSecure))
	emitRedirect(ctx, loc)
	return &authv1.OauthRedirect{Location: loc}, nil
}

// OauthStart mirrors GET /oauth/{provider}/start → 302 to the provider, sets the
// signed state cookie.
func (s *Service) OauthStart(ctx context.Context, req *authv1.OauthStartRequest) (*authv1.OauthRedirect, error) {
	provider := req.GetProvider()
	intent := req.GetIntent()

	prov, ok := s.oauth.Provider(provider)
	ru := s.providerRedirectURI(ctx, provider)
	if !ok || ru == "" {
		safeIntent := intent
		if safeIntent != "signup" && safeIntent != "login" && safeIntent != "add" {
			safeIntent = "login"
		}
		return s.redirectWithError(ctx, safeIntent, "provider_unavailable")
	}
	if intent != "signup" && intent != "login" && intent != "add" {
		return s.redirectWithError(ctx, "login", "invalid_intent")
	}

	state, err := s.issuer.SignShortLived(map[string]any{
		"intent":      intent,
		"tenant_name": req.GetTenantName(),
		"provider":    provider,
	}, shortLivedTTL, "oauth_state")
	if err != nil {
		return nil, status.Error(codes.Internal, "oauth state sign failed")
	}

	// Use the dynamic redirect_uri (public host) so the provider returns to the
	// same host that set the state cookie. The exchange in OauthCallback must
	// recompute and pass the identical value.
	authURL := prov.AuthCodeURL(state, ru)
	emitSetCookie(ctx, buildCookie(oauthStateCookie, state, 600, s.cfg.CookieSecure))
	emitRedirect(ctx, authURL)
	return &authv1.OauthRedirect{Location: authURL}, nil
}

// OauthCallback mirrors GET /oauth/{provider}/callback → exchange code, fetch
// profile, find-or-create user, issue session cookie, 302 to /home.
func (s *Service) OauthCallback(ctx context.Context, req *authv1.OauthCallbackRequest) (*authv1.OauthRedirect, error) {
	provider := req.GetProvider()
	state := req.GetState()

	// 1. Validate state HMAC first (gives us the intent for error redirects).
	payload, err := s.issuer.VerifyShortLived(state, "oauth_state")
	if err != nil || asString(payload["provider"]) != provider {
		s.log.Warn("oauth callback: state HMAC invalid", "provider", provider)
		return s.redirectWithError(ctx, "login", "invalid_state")
	}
	intent := asString(payload["intent"])
	if intent == "" {
		intent = "login"
	}

	// 2. Double-submit: state cookie must match the state param.
	cookieState := cookieFromCtx(ctx, oauthStateCookie)
	if cookieState == "" {
		s.log.Warn("oauth callback: state cookie missing", "provider", provider)
		return s.redirectWithError(ctx, intent, "state_cookie_missing")
	}
	if cookieState != state {
		s.log.Warn("oauth callback: state cookie/param mismatch", "provider", provider)
		return s.redirectWithError(ctx, intent, "state_mismatch")
	}

	prov, ok := s.oauth.Provider(provider)
	if !ok {
		return s.redirectWithError(ctx, intent, "provider_unavailable")
	}

	// 3+4. Exchange code → token → profile. redirect_uri must match the one
	// sent at OauthStart, recomputed here from the (same) incoming host.
	info, err := prov.Exchange(ctx, req.GetCode(), s.providerRedirectURI(ctx, provider))
	if err != nil {
		s.log.Warn("oauth callback: exchange failed", "err", err)
		return s.redirectWithError(ctx, intent, "token_exchange_failed")
	}

	// 5. Reject if email not verified at provider.
	if info.Email == "" || !info.EmailVerified {
		return s.redirectWithError(ctx, intent, "email_not_verified")
	}

	email := normalizeEmail(info.Email)

	// 6+7. Resolve user: existing oauth account → log in; else create.
	var user *store.User
	existing, err := s.store.GetOAuthAccount(ctx, provider, info.ProviderAccountID)
	if err == nil {
		user, err = s.store.GetUserByIDFull(ctx, existing.UserID)
		if err != nil {
			return s.redirectWithError(ctx, intent, "provider_unavailable")
		}
	} else if !errIsNotFound(err) {
		s.log.Warn("oauth callback: GetOAuthAccount error", "err", err)
		return s.redirectWithError(ctx, intent, "provider_unavailable")
	} else {
		// No oauth account. Email-collision is ALWAYS rejected (no auto-linking).
		if _, e := s.store.GetUserByEmail(ctx, email); e == nil {
			return s.redirectWithError(ctx, intent, "email_in_use")
		} else if !errIsNotFound(e) {
			return s.redirectWithError(ctx, intent, "provider_unavailable")
		}

		// Truly new user — provision tenant + user + oauth_account.
		providedTenant := asString(payload["tenant_name"])
		var tenant *store.Tenant
		if providedTenant != "" {
			tenant, err = s.store.CreateTenant(ctx, providedTenant, providedTenant)
		} else {
			tenant, err = s.store.AutoCreateTenantForUser(ctx, email, info.DisplayName)
		}
		if err != nil {
			if isInvalidTenantName(err) {
				return s.redirectWithError(ctx, "signup", "invalid_tenant_name")
			}
			if errIsConflict(err) {
				return s.redirectWithError(ctx, "signup", "tenant_name_taken")
			}
			return s.redirectWithError(ctx, intent, "provider_unavailable")
		}

		ownerRole := "owner"
		now := nowUTC()
		newUser := &store.User{
			Email:           email,
			DisplayName:     info.DisplayName,
			PasswordHash:    nil, // OAuth-only account
			PlatformRole:    "client",
			TenantID:        &tenant.ID,
			TenantRole:      &ownerRole,
			EmailVerifiedAt: &now, // provider-verified
		}
		user, err = s.store.CreateUser(ctx, newUser)
		if err != nil {
			return s.redirectWithError(ctx, intent, "provider_unavailable")
		}
		if _, err := s.store.CreateOAuthAccount(ctx, user.ID, provider, info.ProviderAccountID, email); err != nil {
			s.log.Warn("oauth callback: CreateOAuthAccount failed", "err", err)
			return s.redirectWithError(ctx, intent, "provider_unavailable")
		}
		// New owner of the freshly created tenant also gets a membership row.
		if err := s.store.CreateMembership(ctx, tenant.ID, user.ID, "owner"); err != nil {
			s.log.Warn("oauth callback: CreateMembership failed", "err", err)
			return s.redirectWithError(ctx, intent, "provider_unavailable")
		}
	}

	// Touch last_login_at, issue session cookie, redirect to /home.
	now := nowUTC()
	if err := s.store.UpdateUser(ctx, user.ID, store.UserUpdate{LastLoginAt: &now}); err != nil {
		s.log.Warn("oauth callback: touch last_login_at failed", "err", err)
	}
	tok, err := s.mintSessionToken(user)
	if err != nil {
		return nil, err
	}
	if err := s.setActiveWithStash(ctx, tok, user.ID, intent == "add"); err != nil {
		return nil, err
	}
	emitSetCookie(ctx, clearCookie(oauthStateCookie, s.cfg.CookieSecure))

	redirectURL := s.frontendBase(ctx) + "/home"
	emitRedirect(ctx, redirectURL)
	return &authv1.OauthRedirect{Location: redirectURL}, nil
}

// cookieFromCtx reads a cookie via the shared interceptor helper.
func cookieFromCtx(ctx context.Context, name string) string {
	return auth.CookieFromMetadata(ctx, name)
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
