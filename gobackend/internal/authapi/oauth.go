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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
	"time"
)

// nowUTC is a thin wrapper so OAuth timestamps are consistent + testable.
func nowUTC() time.Time { return time.Now().UTC() }

// forwardedHost extracts the incoming Host (x-forwarded-host wins over host),
// mirroring the header reads in oauth.py. grpc-gateway forwards permanent
// headers prefixed with "grpcgateway-"; the gateway also explicitly forwards
// the Host as "grpcgateway-host" via a custom matcher (see gateway.go).
func forwardedHost(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	get := func(k string) string {
		if v := md.Get(k); len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if h := get("grpcgateway-x-forwarded-host"); h != "" {
		return h
	}
	if h := get("x-forwarded-host"); h != "" {
		return h
	}
	if h := get("grpcgateway-host"); h != "" {
		return h
	}
	return get("host")
}

// isPublicHost reports whether host is a real public host (not localhost),
// matching the "localhost"/"127.0.0.1" checks in oauth.py.
func isPublicHost(host string) bool {
	return host != "" && !strings.Contains(host, "localhost") && !strings.Contains(host, "127.0.0.1")
}

// providerRedirectURI computes the OAuth callback redirect URI, mirroring
// oauth.py redirect_uri: force https://<incoming-host>/api/auth/oauth/<p>/callback
// for public hosts, else fall back to the configured static URI.
func (s *Service) providerRedirectURI(ctx context.Context, provider string) string {
	host := forwardedHost(ctx)
	if isPublicHost(host) {
		return "https://" + host + "/api/auth/oauth/" + provider + "/callback"
	}
	switch provider {
	case "google":
		return s.cfg.GoogleRedirect
	case "github":
		return s.cfg.GitHubRedirect
	}
	return ""
}

// frontendBase returns the scheme://host prefix for redirecting back to the SPA,
// or "" when the host is local (relative redirect). Mirrors the
// _redirect_with_error / callback host-rewriting.
func frontendBase(ctx context.Context) string {
	host := forwardedHost(ctx)
	if isPublicHost(host) {
		return "https://" + host
	}
	return ""
}

// redirectWithError sends the user back to /signup or /login with ?oauth_error=,
// clearing the state cookie. Mirrors _redirect_with_error.
func (s *Service) redirectWithError(ctx context.Context, intent, code string) (*authv1.OauthRedirect, error) {
	target := "/login"
	if intent == "signup" {
		target = "/signup"
	}
	loc := frontendBase(ctx) + target + "?oauth_error=" + url.QueryEscape(code)
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
		if safeIntent != "signup" && safeIntent != "login" {
			safeIntent = "login"
		}
		return s.redirectWithError(ctx, safeIntent, "provider_unavailable")
	}
	if intent != "signup" && intent != "login" {
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

	_ = ru // redirect_uri is baked into the provider's oauth2.Config; AuthCodeURL uses it.
	authURL := prov.AuthCodeURL(state)
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

	// 3+4. Exchange code → token → profile.
	info, err := prov.Exchange(ctx, req.GetCode())
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
	if err := s.issueSessionCookie(ctx, user); err != nil {
		return nil, err
	}
	emitSetCookie(ctx, clearCookie(oauthStateCookie, s.cfg.CookieSecure))

	redirectURL := frontendBase(ctx) + "/home"
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
