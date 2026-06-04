package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// NewProvider / buildProvider
// ---------------------------------------------------------------------------

func TestNewProvider_Google_NotConfigured(t *testing.T) {
	_, ok := buildProvider("google", func(string) string { return "" })
	if ok {
		t.Fatal("expected ok=false when env vars are absent")
	}
}

func TestNewProvider_GitHub_NotConfigured(t *testing.T) {
	_, ok := buildProvider("github", func(string) string { return "" })
	if ok {
		t.Fatal("expected ok=false when env vars are absent")
	}
}

func TestNewProvider_UnknownProvider(t *testing.T) {
	_, ok := buildProvider("twitter", func(key string) string {
		// All vars present but provider unknown → should still return false.
		return "value"
	})
	if ok {
		t.Fatal("expected ok=false for unknown provider")
	}
}

func TestNewProvider_Google_Configured(t *testing.T) {
	env := map[string]string{
		"WAF_OAUTH_GOOGLE_CLIENT_ID":     "gid",
		"WAF_OAUTH_GOOGLE_CLIENT_SECRET": "gsecret",
		"WAF_OAUTH_GOOGLE_REDIRECT_URI":  "https://example.com/api/auth/oauth/google/callback",
	}
	p, ok := buildProvider("google", func(k string) string { return env[k] })
	if !ok {
		t.Fatal("expected ok=true when all Google env vars are set")
	}
	if p.Name() != "google" {
		t.Errorf("Name()=%q, want %q", p.Name(), "google")
	}

	// Check scopes — GOOGLE_SCOPES = ["openid", "email", "profile"]
	wantScopes := []string{"openid", "email", "profile"}
	if !equalScopes(p.cfg.Scopes, wantScopes) {
		t.Errorf("scopes=%v, want %v", p.cfg.Scopes, wantScopes)
	}

	// Authorize URL must contain Google's OAuth2 host
	authURL := p.AuthCodeURL("test-state")
	if !strings.Contains(authURL, "accounts.google.com") {
		t.Errorf("AuthCodeURL missing accounts.google.com: %s", authURL)
	}
	if !strings.Contains(authURL, "client_id=gid") {
		t.Errorf("AuthCodeURL missing client_id: %s", authURL)
	}
	if !strings.Contains(authURL, "state=test-state") {
		t.Errorf("AuthCodeURL missing state: %s", authURL)
	}
	if !strings.Contains(authURL, "redirect_uri=") {
		t.Errorf("AuthCodeURL missing redirect_uri: %s", authURL)
	}
	// scope param must contain the three scopes
	for _, sc := range wantScopes {
		if !strings.Contains(authURL, sc) {
			t.Errorf("AuthCodeURL missing scope %q: %s", sc, authURL)
		}
	}
}

func TestNewProvider_GitHub_Configured(t *testing.T) {
	env := map[string]string{
		"WAF_OAUTH_GITHUB_CLIENT_ID":     "ghid",
		"WAF_OAUTH_GITHUB_CLIENT_SECRET": "ghsecret",
		"WAF_OAUTH_GITHUB_REDIRECT_URI":  "https://example.com/api/auth/oauth/github/callback",
	}
	p, ok := buildProvider("github", func(k string) string { return env[k] })
	if !ok {
		t.Fatal("expected ok=true when all GitHub env vars are set")
	}
	if p.Name() != "github" {
		t.Errorf("Name()=%q, want %q", p.Name(), "github")
	}

	// Check scopes — GITHUB_SCOPES = ["read:user", "user:email"]
	wantScopes := []string{"read:user", "user:email"}
	if !equalScopes(p.cfg.Scopes, wantScopes) {
		t.Errorf("scopes=%v, want %v", p.cfg.Scopes, wantScopes)
	}

	authURL := p.AuthCodeURL("gh-state")
	if !strings.Contains(authURL, "github.com") {
		t.Errorf("AuthCodeURL missing github.com: %s", authURL)
	}
	if !strings.Contains(authURL, "client_id=ghid") {
		t.Errorf("AuthCodeURL missing client_id: %s", authURL)
	}
	if !strings.Contains(authURL, "state=gh-state") {
		t.Errorf("AuthCodeURL missing state: %s", authURL)
	}
}

func TestNewProvider_MissingOneVar(t *testing.T) {
	// Only client_id + client_secret, no redirect_uri → not configured
	env := map[string]string{
		"WAF_OAUTH_GOOGLE_CLIENT_ID":     "gid",
		"WAF_OAUTH_GOOGLE_CLIENT_SECRET": "gsecret",
	}
	_, ok := buildProvider("google", func(k string) string { return env[k] })
	if ok {
		t.Fatal("expected ok=false when redirect_uri is missing")
	}
}

// ---------------------------------------------------------------------------
// Exchange — Google
// ---------------------------------------------------------------------------

// fakeTokenServer builds an httptest.Server that returns a minimal OAuth2
// token response (access_token only, bearer type).
func fakeTokenServer(t *testing.T, accessToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"access_token": accessToken,
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	}))
}

// fakeUserinfoServer returns a server that emits a fixed JSON body.
func fakeUserinfoServer(t *testing.T, body map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Bearer header is set.
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "no bearer", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body) //nolint:errcheck
	}))
}

// fakeGitHubServer returns one server that handles both /user and /user/emails
// by path.
func fakeGitHubServer(t *testing.T, userBody map[string]any, emailsBody []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "no bearer", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			json.NewEncoder(w).Encode(userBody) //nolint:errcheck
		case "/user/emails":
			json.NewEncoder(w).Encode(emailsBody) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestExchange_Google_ParsesProfile(t *testing.T) {
	const fakeToken = "goog-access-token"

	tokenSrv := fakeTokenServer(t, fakeToken)
	defer tokenSrv.Close()

	userSrv := fakeUserinfoServer(t, map[string]any{
		"sub":            "12345",
		"email":          "alice@example.com",
		"email_verified": true,
		"name":           "Alice Smith",
	})
	defer userSrv.Close()

	env := map[string]string{
		"WAF_OAUTH_GOOGLE_CLIENT_ID":     "gid",
		"WAF_OAUTH_GOOGLE_CLIENT_SECRET": "gsecret",
		"WAF_OAUTH_GOOGLE_REDIRECT_URI":  "http://localhost/callback",
	}
	p, ok := buildProvider("google", func(k string) string { return env[k] })
	if !ok {
		t.Fatal("buildProvider returned ok=false")
	}

	// Override token + userinfo endpoints to point at test servers.
	p = p.withEndpoints(tokenSrv.URL+"/token", userSrv.URL, "")

	info, err := p.Exchange(context.Background(), "auth-code")
	if err != nil {
		t.Fatalf("Exchange error: %v", err)
	}

	if info.ProviderAccountID != "12345" {
		t.Errorf("ProviderAccountID=%q, want %q", info.ProviderAccountID, "12345")
	}
	if info.Email != "alice@example.com" {
		t.Errorf("Email=%q, want %q", info.Email, "alice@example.com")
	}
	if !info.EmailVerified {
		t.Error("EmailVerified=false, want true")
	}
	if info.DisplayName != "Alice Smith" {
		t.Errorf("DisplayName=%q, want %q", info.DisplayName, "Alice Smith")
	}
}

func TestExchange_Google_UnverifiedEmail(t *testing.T) {
	tokenSrv := fakeTokenServer(t, "tok")
	defer tokenSrv.Close()

	userSrv := fakeUserinfoServer(t, map[string]any{
		"sub":            "99",
		"email":          "unverified@example.com",
		"email_verified": false,
		"name":           "Unknown",
	})
	defer userSrv.Close()

	env := map[string]string{
		"WAF_OAUTH_GOOGLE_CLIENT_ID":     "gid",
		"WAF_OAUTH_GOOGLE_CLIENT_SECRET": "gsecret",
		"WAF_OAUTH_GOOGLE_REDIRECT_URI":  "http://localhost/callback",
	}
	p, _ := buildProvider("google", func(k string) string { return env[k] })
	p = p.withEndpoints(tokenSrv.URL+"/token", userSrv.URL, "")

	info, err := p.Exchange(context.Background(), "code")
	if err != nil {
		t.Fatalf("Exchange error: %v", err)
	}
	if info.EmailVerified {
		t.Error("EmailVerified=true for unverified account, want false")
	}
}

// ---------------------------------------------------------------------------
// Exchange — GitHub (two-call flow)
// ---------------------------------------------------------------------------

func TestExchange_GitHub_PrimaryVerifiedEmail(t *testing.T) {
	const fakeToken = "gh-access-token"

	tokenSrv := fakeTokenServer(t, fakeToken)
	defer tokenSrv.Close()

	ghSrv := fakeGitHubServer(t,
		map[string]any{"id": 42, "name": "Bob Builder", "login": "bobbuilder"},
		[]map[string]any{
			{"email": "other@example.com", "primary": false, "verified": true},
			{"email": "bob@example.com", "primary": true, "verified": true},
		},
	)
	defer ghSrv.Close()

	env := map[string]string{
		"WAF_OAUTH_GITHUB_CLIENT_ID":     "ghid",
		"WAF_OAUTH_GITHUB_CLIENT_SECRET": "ghsecret",
		"WAF_OAUTH_GITHUB_REDIRECT_URI":  "http://localhost/callback",
	}
	p, ok := buildProvider("github", func(k string) string { return env[k] })
	if !ok {
		t.Fatal("buildProvider returned ok=false")
	}

	// /user and /user/emails are served by the same ghSrv.
	p = p.withEndpoints(tokenSrv.URL+"/token", ghSrv.URL+"/user", ghSrv.URL+"/user/emails")

	info, err := p.Exchange(context.Background(), "auth-code")
	if err != nil {
		t.Fatalf("Exchange error: %v", err)
	}

	if info.ProviderAccountID != "42" {
		t.Errorf("ProviderAccountID=%q, want %q", info.ProviderAccountID, "42")
	}
	if info.Email != "bob@example.com" {
		t.Errorf("Email=%q, want %q", info.Email, "bob@example.com")
	}
	if !info.EmailVerified {
		t.Error("EmailVerified=false, want true")
	}
	if info.DisplayName != "Bob Builder" {
		t.Errorf("DisplayName=%q, want %q", info.DisplayName, "Bob Builder")
	}
}

func TestExchange_GitHub_NoPrimaryVerifiedEmail(t *testing.T) {
	tokenSrv := fakeTokenServer(t, "tok")
	defer tokenSrv.Close()

	ghSrv := fakeGitHubServer(t,
		map[string]any{"id": 7, "name": "", "login": "ghostuser"},
		// No primary+verified email — mirrors Python "if not primary: return {email: None, ...}"
		[]map[string]any{
			{"email": "unverified@example.com", "primary": true, "verified": false},
		},
	)
	defer ghSrv.Close()

	env := map[string]string{
		"WAF_OAUTH_GITHUB_CLIENT_ID":     "ghid",
		"WAF_OAUTH_GITHUB_CLIENT_SECRET": "ghsecret",
		"WAF_OAUTH_GITHUB_REDIRECT_URI":  "http://localhost/callback",
	}
	p, _ := buildProvider("github", func(k string) string { return env[k] })
	p = p.withEndpoints(tokenSrv.URL+"/token", ghSrv.URL+"/user", ghSrv.URL+"/user/emails")

	info, err := p.Exchange(context.Background(), "code")
	if err != nil {
		t.Fatalf("Exchange error: %v", err)
	}

	if info.ProviderAccountID != "7" {
		t.Errorf("ProviderAccountID=%q, want %q", info.ProviderAccountID, "7")
	}
	if info.Email != "" {
		t.Errorf("Email=%q, want empty", info.Email)
	}
	if info.EmailVerified {
		t.Error("EmailVerified=true for no-primary-verified-email, want false")
	}
}

func TestExchange_GitHub_FallsBackToLogin_WhenNameEmpty(t *testing.T) {
	// name="" → DisplayName should be the login (u["name"] or u["login"])
	tokenSrv := fakeTokenServer(t, "tok")
	defer tokenSrv.Close()

	ghSrv := fakeGitHubServer(t,
		map[string]any{"id": 99, "name": "", "login": "coollogin"},
		[]map[string]any{
			{"email": "cool@example.com", "primary": true, "verified": true},
		},
	)
	defer ghSrv.Close()

	env := map[string]string{
		"WAF_OAUTH_GITHUB_CLIENT_ID":     "ghid",
		"WAF_OAUTH_GITHUB_CLIENT_SECRET": "ghsecret",
		"WAF_OAUTH_GITHUB_REDIRECT_URI":  "http://localhost/callback",
	}
	p, _ := buildProvider("github", func(k string) string { return env[k] })
	p = p.withEndpoints(tokenSrv.URL+"/token", ghSrv.URL+"/user", ghSrv.URL+"/user/emails")

	info, err := p.Exchange(context.Background(), "code")
	if err != nil {
		t.Fatalf("Exchange error: %v", err)
	}
	if info.DisplayName != "coollogin" {
		t.Errorf("DisplayName=%q, want %q (login fallback)", info.DisplayName, "coollogin")
	}
}

func TestExchange_TokenExchangeFails(t *testing.T) {
	// Token server returns 400.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer tokenSrv.Close()

	env := map[string]string{
		"WAF_OAUTH_GOOGLE_CLIENT_ID":     "gid",
		"WAF_OAUTH_GOOGLE_CLIENT_SECRET": "gsecret",
		"WAF_OAUTH_GOOGLE_REDIRECT_URI":  "http://localhost/callback",
	}
	p, _ := buildProvider("google", func(k string) string { return env[k] })
	p = p.withEndpoints(tokenSrv.URL+"/token", "http://unused", "")

	_, err := p.Exchange(context.Background(), "bad-code")
	if err == nil {
		t.Fatal("expected error when token exchange returns 400")
	}
}

// ---------------------------------------------------------------------------
// AuthCodeURL — endpoint/scope assertions
// ---------------------------------------------------------------------------

func TestAuthCodeURL_Google_Endpoint(t *testing.T) {
	env := map[string]string{
		"WAF_OAUTH_GOOGLE_CLIENT_ID":     "gid",
		"WAF_OAUTH_GOOGLE_CLIENT_SECRET": "gsecret",
		"WAF_OAUTH_GOOGLE_REDIRECT_URI":  "https://app.example.com/api/auth/oauth/google/callback",
	}
	p, _ := buildProvider("google", func(k string) string { return env[k] })
	url := p.AuthCodeURL("mystate")

	checks := []struct{ label, want string }{
		{"host", "accounts.google.com"},
		{"client_id", "client_id=gid"},
		{"state", "state=mystate"},
		{"scope:openid", "openid"},
		{"scope:email", "email"},
		{"scope:profile", "profile"},
	}
	for _, c := range checks {
		if !strings.Contains(url, c.want) {
			t.Errorf("AuthCodeURL missing %s (%q): %s", c.label, c.want, url)
		}
	}
}

func TestAuthCodeURL_GitHub_Endpoint(t *testing.T) {
	env := map[string]string{
		"WAF_OAUTH_GITHUB_CLIENT_ID":     "ghid",
		"WAF_OAUTH_GITHUB_CLIENT_SECRET": "ghsecret",
		"WAF_OAUTH_GITHUB_REDIRECT_URI":  "https://app.example.com/api/auth/oauth/github/callback",
	}
	p, _ := buildProvider("github", func(k string) string { return env[k] })
	url := p.AuthCodeURL("ghstate")

	checks := []struct{ label, want string }{
		{"host", "github.com"},
		{"client_id", "client_id=ghid"},
		{"state", "state=ghstate"},
		{"scope:read:user", "read%3Auser"}, // URL-encoded colon
		{"scope:user:email", "user%3Aemail"},
	}
	for _, c := range checks {
		if !strings.Contains(url, c.want) {
			t.Errorf("AuthCodeURL missing %s (%q): %s", c.label, c.want, url)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func equalScopes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Ensure the fmt import is used (it is — in fakeGitHubServer via fmt.Sprintf
// inside fetchGitHubProfileURLs). This blank reference suppresses any
// "imported and not used" if the compiler is picky about the test file.
var _ = fmt.Sprintf
