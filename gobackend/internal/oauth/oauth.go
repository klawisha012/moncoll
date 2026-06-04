// Package oauth implements the provider-protocol layer for OAuth2 login via
// Google and GitHub, mirroring backend/src/auth/oauth.py.
//
// It is intentionally narrow: it builds authorize-redirect URLs and exchanges
// authorization codes for provider-verified user profiles. State generation,
// session issuance, cookie management, user find-or-create, and HTTP routing
// are all left to the auth service (task A4).
//
// # Provider configuration
//
// Each provider is enabled when all three env vars are non-empty:
//
//	WAF_OAUTH_GOOGLE_CLIENT_ID   / WAF_OAUTH_GOOGLE_CLIENT_SECRET   / WAF_OAUTH_GOOGLE_REDIRECT_URI
//	WAF_OAUTH_GITHUB_CLIENT_ID   / WAF_OAUTH_GITHUB_CLIENT_SECRET   / WAF_OAUTH_GITHUB_REDIRECT_URI
//
// The names mirror Python's pydantic settings (env_prefix="WAF_", field
// oauth_google_client_id → WAF_OAUTH_GOOGLE_CLIENT_ID).
//
// # Scopes (oauth.py)
//
//	Google: ["openid", "email", "profile"]
//	GitHub: ["read:user", "user:email"]
//
// # UserInfo parsing
//
// Google uses the OpenID Connect userinfo endpoint
// (https://openidconnect.googleapis.com/v1/userinfo).  Fields: sub, email,
// email_verified, name.
//
// GitHub requires two API calls: GET /user (id, name, login) + GET
// /user/emails to find the primary verified email (mirrors
// _fetch_github_profile in routers/oauth.py).  If no primary+verified email
// exists, EmailVerified=false and the caller should reject the login.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// providerURLs holds per-instance URL overrides used in tests to point at
// httptest servers instead of the live Google/GitHub APIs.
type providerURLs struct {
	userinfo string // replaces googleUserinfoURL or githubUserURL
	emails   string // replaces githubEmailsURL (GitHub only)
	token    string // replaces the provider's token endpoint
}

// Provider holds the oauth2.Config for one provider plus auxiliary information
// needed to fetch user profiles after a token exchange.
type Provider struct {
	name  string
	cfg   oauth2.Config
	hc    *http.Client  // injectable for tests; nil → default 5 s client
	urls  *providerURLs // nil in production; set by withEndpoints in tests
}

// UserInfo is the normalized profile returned by Exchange for both providers.
// It mirrors the dict returned by _fetch_google_profile / _fetch_github_profile
// in routers/oauth.py.
//
//   - ProviderAccountID — the stable "sub" (Google) or string(id) (GitHub).
//   - Email             — primary verified email; empty when not verified.
//   - EmailVerified     — true iff the provider has verified the email address.
//   - DisplayName       — "name" field (Google) or name/login (GitHub).
type UserInfo struct {
	ProviderAccountID string
	Email             string
	EmailVerified     bool
	DisplayName       string
}

// NewProvider constructs a Provider from environment variables.
// Returns (nil, false) when any of the three required env vars is missing,
// matching the oauth_google_enabled / oauth_github_enabled logic in config.py.
//
// Supported names: "google", "github".
func NewProvider(name string) (*Provider, bool) {
	return buildProvider(name, os.Getenv)
}

// buildProvider is the testable core of NewProvider.
// getenv is injected so tests can supply fake values without os.Setenv.
func buildProvider(name string, getenv func(string) string) (*Provider, bool) {
	prefix := "WAF_OAUTH_" + upperName(name) + "_"
	clientID := getenv(prefix + "CLIENT_ID")
	clientSecret := getenv(prefix + "CLIENT_SECRET")
	redirectURI := getenv(prefix + "REDIRECT_URI")

	if clientID == "" || clientSecret == "" || redirectURI == "" {
		return nil, false
	}

	cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
	}

	switch name {
	case "google":
		cfg.Endpoint = google.Endpoint
		// GOOGLE_SCOPES = ["openid", "email", "profile"]
		cfg.Scopes = []string{"openid", "email", "profile"}
	case "github":
		cfg.Endpoint = github.Endpoint
		// GITHUB_SCOPES = ["read:user", "user:email"]
		cfg.Scopes = []string{"read:user", "user:email"}
	default:
		return nil, false
	}

	return &Provider{name: name, cfg: cfg}, true
}

// upperName maps "google" → "GOOGLE", "github" → "GITHUB".
func upperName(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		b[i] = c
	}
	return string(b)
}

// Name returns the provider name ("google" or "github").
func (p *Provider) Name() string { return p.name }

// AuthCodeURL returns the provider's authorization redirect URL with the given
// state embedded.  Mirrors client.get_authorization_url(redirect_uri, state,
// scope) from routers/oauth.py.
func (p *Provider) AuthCodeURL(state string) string {
	return p.cfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// Exchange performs the authorization-code → access-token exchange and then
// fetches the user's profile from the provider's userinfo/API endpoint.
//
// For Google: single call to the OpenID Connect userinfo endpoint.
// For GitHub: two calls — GET /user + GET /user/emails — to find the primary
// verified email (faithfully mirrors _fetch_github_profile in routers/oauth.py).
//
// When EmailVerified is false on the returned UserInfo the caller (auth
// service, A4) must reject the login with "email_not_verified", matching step 5
// in routers/oauth.py.
func (p *Provider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	tok, err := p.cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oauth %s: token exchange: %w", p.name, err)
	}

	hc := p.httpClient()
	switch p.name {
	case "google":
		url := googleUserinfoURL
		if p.urls != nil && p.urls.userinfo != "" {
			url = p.urls.userinfo
		}
		return fetchGoogleProfileURL(ctx, hc, tok.AccessToken, url)
	case "github":
		userURL := githubUserURL
		emailsURL := githubEmailsURL
		if p.urls != nil {
			if p.urls.userinfo != "" {
				userURL = p.urls.userinfo
			}
			if p.urls.emails != "" {
				emailsURL = p.urls.emails
			}
		}
		return fetchGitHubProfileURLs(ctx, hc, tok.AccessToken, userURL, emailsURL)
	default:
		return nil, fmt.Errorf("oauth: unknown provider %q", p.name)
	}
}

// httpClient returns the injected test client or a 5 s default client.
// The 5 s timeout mirrors httpx.AsyncClient(timeout=5.0) in oauth.py.
func (p *Provider) httpClient() *http.Client {
	if p.hc != nil {
		return p.hc
	}
	return &http.Client{Timeout: 5 * time.Second}
}

// withHTTPClient returns a shallow copy with the HTTP client replaced (tests).
func (p *Provider) withHTTPClient(c *http.Client) *Provider {
	cp := *p
	cp.hc = c
	return &cp
}

// withEndpoints returns a shallow copy with overridden token endpoint and
// userinfo/emails URLs (tests pointing at httptest servers).
func (p *Provider) withEndpoints(tokenURL, userinfoURL, emailsURL string) *Provider {
	cp := *p
	cp.cfg.Endpoint = oauth2.Endpoint{
		AuthURL:  p.cfg.Endpoint.AuthURL,
		TokenURL: tokenURL,
	}
	cp.urls = &providerURLs{userinfo: userinfoURL, emails: emailsURL}
	return &cp
}

// ---------------------------------------------------------------------------
// Package-level URL constants (vars so tests can see them; not overrideable
// globally — use withEndpoints on a per-Provider basis).
// ---------------------------------------------------------------------------

var (
	// googleUserinfoURL is the OpenID Connect userinfo endpoint.
	// Mirrors: "https://openidconnect.googleapis.com/v1/userinfo" in oauth.py.
	googleUserinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

	// githubUserURL is the GitHub REST API user endpoint.
	githubUserURL = "https://api.github.com/user"

	// githubEmailsURL is the GitHub REST API emails endpoint.
	githubEmailsURL = "https://api.github.com/user/emails"
)

// ---------------------------------------------------------------------------
// Google profile fetch
// ---------------------------------------------------------------------------

// fetchGoogleProfileURL calls the Google OpenID Connect userinfo endpoint.
// Mirrors _fetch_google_profile in routers/oauth.py:
//
//	r = await c.get("https://openidconnect.googleapis.com/v1/userinfo",
//	                headers={"Authorization": f"Bearer {access_token}"})
//	return {"sub": j["sub"], "email": j["email"],
//	        "email_verified": j.get("email_verified", False), "name": j.get("name", "")}
func fetchGoogleProfileURL(ctx context.Context, hc *http.Client, accessToken, url string) (*UserInfo, error) {
	body, err := getJSON(ctx, hc, url, accessToken, "application/json")
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}

	var j struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.Unmarshal(body, &j); err != nil {
		return nil, fmt.Errorf("google userinfo parse: %w", err)
	}

	return &UserInfo{
		ProviderAccountID: j.Sub,
		Email:             j.Email,
		EmailVerified:     j.EmailVerified,
		DisplayName:       j.Name,
	}, nil
}

// ---------------------------------------------------------------------------
// GitHub profile fetch
// ---------------------------------------------------------------------------

// fetchGitHubProfileURLs calls GET /user and GET /user/emails, then picks the
// primary verified email.  Faithfully mirrors _fetch_github_profile:
//
//	u = (await c.get("/user", headers=headers)).json()
//	emails = (await c.get("/user/emails", headers=headers)).json()
//	primary = next((e for e in emails if e["primary"] and e["verified"]), None)
//	if not primary:
//	    return {sub: str(id), email: None, email_verified: False, name: ""}
//	return {sub: str(id), email: primary["email"], email_verified: True,
//	        name: u["name"] or u["login"]}
func fetchGitHubProfileURLs(ctx context.Context, hc *http.Client, accessToken, userURL, emailsURL string) (*UserInfo, error) {
	const ghAccept = "application/vnd.github+json"

	// GET /user
	userBody, err := getJSON(ctx, hc, userURL, accessToken, ghAccept)
	if err != nil {
		return nil, fmt.Errorf("github /user: %w", err)
	}
	var u struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Login string `json:"login"`
	}
	if err := json.Unmarshal(userBody, &u); err != nil {
		return nil, fmt.Errorf("github /user parse: %w", err)
	}

	// GET /user/emails
	emailsBody, err := getJSON(ctx, hc, emailsURL, accessToken, ghAccept)
	if err != nil {
		return nil, fmt.Errorf("github /user/emails: %w", err)
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(emailsBody, &emails); err != nil {
		return nil, fmt.Errorf("github /user/emails parse: %w", err)
	}

	sub := fmt.Sprintf("%d", u.ID)

	// primary = next(e for e in emails if e["primary"] and e["verified"], None)
	for _, e := range emails {
		if e.Primary && e.Verified {
			name := u.Name
			if name == "" {
				name = u.Login // u["name"] or u["login"]
			}
			return &UserInfo{
				ProviderAccountID: sub,
				Email:             e.Email,
				EmailVerified:     true,
				DisplayName:       name,
			}, nil
		}
	}

	// No primary+verified email — mirrors "if not primary: return {...}"
	return &UserInfo{
		ProviderAccountID: sub,
		Email:             "",
		EmailVerified:     false,
		DisplayName:       "",
	}, nil
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

// getJSON performs a GET request with a Bearer token and returns the body bytes.
// The Accept header is sent as-is (JSON for Google, GitHub JSON for GitHub).
func getJSON(ctx context.Context, hc *http.Client, url, accessToken, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", accept)

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
