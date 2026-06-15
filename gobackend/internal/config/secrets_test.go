package config

import (
	"strings"
	"testing"
)

// setSecretEnv resets every variable the validator inspects to a known-good
// baseline (ClickHouse password present, every feature OFF), then applies the
// per-test overrides. This isolates each case from the ambient environment.
func setSecretEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	base := map[string]string{
		"CLICKHOUSE_PASSWORD":            "ch-secret",
		"WAF_SMTP_HOST":                  "",
		"WAF_SMTP_PASSWORD":              "",
		"WAF_OAUTH_GOOGLE_CLIENT_ID":     "",
		"WAF_OAUTH_GOOGLE_CLIENT_SECRET": "",
		"WAF_OAUTH_GITHUB_CLIENT_ID":     "",
		"WAF_OAUTH_GITHUB_CLIENT_SECRET": "",
		"WAF_TURNSTILE_SITE_KEY":         "",
		"WAF_TURNSTILE_SECRET_KEY":       "",
	}
	for k, v := range base {
		if ov, ok := overrides[k]; ok {
			t.Setenv(k, ov)
		} else {
			t.Setenv(k, v)
		}
	}
}

func TestValidateSecrets_OKWhenRequiredPresentAndFeaturesOff(t *testing.T) {
	setSecretEnv(t, nil)
	if err := ValidateSecrets(); err != nil {
		t.Fatalf("expected no error with ClickHouse password set and all features off, got %v", err)
	}
}

func TestValidateSecrets_FailsWhenClickHousePasswordEmpty(t *testing.T) {
	setSecretEnv(t, map[string]string{"CLICKHOUSE_PASSWORD": ""})
	err := ValidateSecrets()
	if err == nil {
		t.Fatal("expected error for empty CLICKHOUSE_PASSWORD")
	}
	if !strings.Contains(err.Error(), "CLICKHOUSE_PASSWORD") {
		t.Errorf("error should name CLICKHOUSE_PASSWORD: %v", err)
	}
}

func TestValidateSecrets_SMTPPartialFails(t *testing.T) {
	// Host set (feature on) but password empty → partially-enabled → fail.
	setSecretEnv(t, map[string]string{"WAF_SMTP_HOST": "smtp.example.com"})
	err := ValidateSecrets()
	if err == nil || !strings.Contains(err.Error(), "WAF_SMTP_PASSWORD") {
		t.Fatalf("expected SMTP password error, got %v", err)
	}
}

func TestValidateSecrets_SMTPFullyConfiguredOK(t *testing.T) {
	setSecretEnv(t, map[string]string{
		"WAF_SMTP_HOST":     "smtp.example.com",
		"WAF_SMTP_PASSWORD": "pw",
	})
	if err := ValidateSecrets(); err != nil {
		t.Fatalf("expected ok for fully-configured SMTP, got %v", err)
	}
}

func TestValidateSecrets_OAuthGooglePartialFails(t *testing.T) {
	setSecretEnv(t, map[string]string{"WAF_OAUTH_GOOGLE_CLIENT_ID": "gid"})
	err := ValidateSecrets()
	if err == nil || !strings.Contains(err.Error(), "WAF_OAUTH_GOOGLE_CLIENT_SECRET") {
		t.Fatalf("expected Google OAuth secret error, got %v", err)
	}
}

func TestValidateSecrets_OAuthGitHubPartialFails(t *testing.T) {
	setSecretEnv(t, map[string]string{"WAF_OAUTH_GITHUB_CLIENT_ID": "ghid"})
	err := ValidateSecrets()
	if err == nil || !strings.Contains(err.Error(), "WAF_OAUTH_GITHUB_CLIENT_SECRET") {
		t.Fatalf("expected GitHub OAuth secret error, got %v", err)
	}
}

func TestValidateSecrets_TurnstilePartialFails(t *testing.T) {
	// Public site key configured (operator intends Turnstile on) but backend
	// secret empty → verification would silently pass-through → fail.
	setSecretEnv(t, map[string]string{"WAF_TURNSTILE_SITE_KEY": "site"})
	err := ValidateSecrets()
	if err == nil || !strings.Contains(err.Error(), "WAF_TURNSTILE_SECRET_KEY") {
		t.Fatalf("expected Turnstile secret error, got %v", err)
	}
}

func TestValidateSecrets_AllFeaturesConfiguredOK(t *testing.T) {
	setSecretEnv(t, map[string]string{
		"WAF_SMTP_HOST": "smtp", "WAF_SMTP_PASSWORD": "pw",
		"WAF_OAUTH_GOOGLE_CLIENT_ID": "gid", "WAF_OAUTH_GOOGLE_CLIENT_SECRET": "gsec",
		"WAF_OAUTH_GITHUB_CLIENT_ID": "ghid", "WAF_OAUTH_GITHUB_CLIENT_SECRET": "ghsec",
		"WAF_TURNSTILE_SITE_KEY": "site", "WAF_TURNSTILE_SECRET_KEY": "tsec",
	})
	if err := ValidateSecrets(); err != nil {
		t.Fatalf("expected ok with every feature fully configured, got %v", err)
	}
}

// TestValidateSecrets_MultipleMissingReported ensures all problems surface at
// once rather than one-at-a-time across restarts.
func TestValidateSecrets_MultipleMissingReported(t *testing.T) {
	setSecretEnv(t, map[string]string{
		"CLICKHOUSE_PASSWORD":        "",
		"WAF_OAUTH_GOOGLE_CLIENT_ID": "gid",
	})
	err := ValidateSecrets()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "CLICKHOUSE_PASSWORD") ||
		!strings.Contains(err.Error(), "WAF_OAUTH_GOOGLE_CLIENT_SECRET") {
		t.Errorf("expected both missing secrets reported, got %v", err)
	}
}
