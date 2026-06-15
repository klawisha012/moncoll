// Package captcha provides Cloudflare Turnstile verification,
// mirroring backend/src/auth/captcha.py.
//
// Unconfigured behaviour (WAF_TURNSTILE_SECRET_KEY empty) → returns true,
// matching captcha.py's "if not settings.turnstile_secret_key: return True".
// When a secret IS configured there is no bypass: every token is verified
// against Cloudflare. (The legacy "e2e-test-bypass" short-circuit was removed —
// it was a production CAPTCHA backdoor; e2e tests run with an empty secret.)
package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const siteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// Verifier holds Turnstile configuration and an HTTP client.
type Verifier struct {
	secret     string
	httpClient *http.Client
}

// NewVerifier reads WAF_TURNSTILE_SECRET_KEY from the environment.
// When the secret is empty, Verify always returns true (dev pass-through).
func NewVerifier() *Verifier {
	return &Verifier{
		secret: os.Getenv("WAF_TURNSTILE_SECRET_KEY"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// newVerifierWithClient is used in tests to inject a fake HTTP client.
func newVerifierWithClient(secret string, client *http.Client) *Verifier {
	return &Verifier{secret: secret, httpClient: client}
}

// isPrivateIP returns true for private/loopback/link-local addresses,
// matching captcha.py's _is_private_ip.  On parse error returns true (safe).
func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true // unparseable → treat as private (safe)
	}
	return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast()
}

// Verify verifies a Turnstile token against Cloudflare's siteverify API.
//
// Behaviour:
//   - secret not configured → true (dev no-op)
//   - token empty → false
//   - remoteIP non-empty and not private → forwarded to Cloudflare
//   - HTTP error → false (logged)
func (v *Verifier) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	// Unconfigured → pass (dev no-op). When a secret IS set, every token is
	// verified against Cloudflare — there is no bypass token.
	if v.secret == "" {
		return true, nil
	}
	// Mirror captcha.py: empty token → fail
	if token == "" {
		return false, nil
	}

	form := url.Values{
		"secret":   {v.secret},
		"response": {token},
	}
	// Only forward remoteIP when it's a real public address — sending a Docker
	// internal IP makes Cloudflare reject the token (matches captcha.py comment).
	if remoteIP != "" && !isPrivateIP(remoteIP) {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, siteverifyURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("captcha: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		slog.Warn("turnstile siteverify HTTP error", "err", err)
		return false, nil // mirror captcha.py: return False on HTTPError
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Warn("turnstile siteverify read body error", "err", err)
		return false, nil
	}

	var result struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		slog.Warn("turnstile siteverify JSON parse error", "err", err)
		return false, nil
	}

	if !result.Success {
		slog.Warn("turnstile siteverify failed",
			"error_codes", result.ErrorCodes,
			"remoteip_sent", form.Get("remoteip") != "",
		)
	}
	return result.Success, nil
}
