package config

import (
	"fmt"
	"os"
	"strings"
)

// ValidateSecrets fails fast when security-critical secrets are missing, so the
// service refuses to start in an insecure state instead of silently booting
// without a password (the behaviour PASETO/Postgres already enforce in Load).
//
// Two classes of secret:
//
//   - Always-required: must be non-empty regardless of configuration.
//     CLICKHOUSE_PASSWORD — the analytics DB must never run unauthenticated.
//     (PASETO key and Postgres DSN are validated in Load and are not repeated
//     here.)
//
//   - Feature-gated: required only when the feature is switched on, detected by
//     its public/gate variable. A fully-disabled feature (gate empty) is a
//     legitimate configuration and is skipped; a partially-enabled feature
//     (gate set, secret empty) is rejected.
//
// All problems are collected and reported together so an operator fixes the
// configuration in one pass rather than one restart at a time.
func ValidateSecrets() error {
	var missing []string

	// Always-required.
	if os.Getenv("CLICKHOUSE_PASSWORD") == "" {
		missing = append(missing,
			"CLICKHOUSE_PASSWORD (analytics DB must not run without a password)")
	}

	// Feature-gated: gate variable → required secret.
	gated := []struct {
		gate, gateName, secret, secretName, feature string
	}{
		{"WAF_SMTP_HOST", "WAF_SMTP_HOST", "WAF_SMTP_PASSWORD", "WAF_SMTP_PASSWORD", "SMTP"},
		{"WAF_OAUTH_GOOGLE_CLIENT_ID", "WAF_OAUTH_GOOGLE_CLIENT_ID", "WAF_OAUTH_GOOGLE_CLIENT_SECRET", "WAF_OAUTH_GOOGLE_CLIENT_SECRET", "Google OAuth"},
		{"WAF_OAUTH_GITHUB_CLIENT_ID", "WAF_OAUTH_GITHUB_CLIENT_ID", "WAF_OAUTH_GITHUB_CLIENT_SECRET", "WAF_OAUTH_GITHUB_CLIENT_SECRET", "GitHub OAuth"},
		{"WAF_TURNSTILE_SITE_KEY", "WAF_TURNSTILE_SITE_KEY", "WAF_TURNSTILE_SECRET_KEY", "WAF_TURNSTILE_SECRET_KEY", "Turnstile"},
	}
	for _, g := range gated {
		if os.Getenv(g.gate) != "" && os.Getenv(g.secret) == "" {
			missing = append(missing, fmt.Sprintf(
				"%s (%s enabled via %s but secret is empty)",
				g.secretName, g.feature, g.gateName))
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf(
			"insecure configuration; refusing to start. Set the following secrets:\n  - %s",
			strings.Join(missing, "\n  - "))
	}
	return nil
}
