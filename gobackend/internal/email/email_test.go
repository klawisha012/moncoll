package email

import (
	"context"
	"strings"
	"testing"
)

func TestVerifyEmailTemplate(t *testing.T) {
	s := newSenderFromConfig(smtpConfig{}) // unconfigured — no-op
	// We test template rendering by calling SendVerificationEmail and verifying
	// it returns nil (no-op path) — we can inspect the rendered body by
	// rendering the template directly.
	if err := s.SendVerificationEmail(context.Background(), "test@example.com", "Alice", "https://example.com/verify/token123"); err != nil {
		t.Fatalf("SendVerificationEmail returned error: %v", err)
	}
}

func TestVerifyEmailTemplateContent(t *testing.T) {
	var buf strings.Builder
	err := verifyEmailTmpl.Execute(&buf, VerifyEmailData{
		DisplayName: "Alice",
		VerifyURL:   "https://example.com/verify/abc",
	})
	if err != nil {
		t.Fatalf("template execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Alice") {
		t.Error("expected display_name 'Alice' in output")
	}
	if !strings.Contains(out, "https://example.com/verify/abc") {
		t.Error("expected verify_url in output")
	}
	if !strings.Contains(out, "24 hours") {
		t.Error("expected expiry hint in verify email")
	}
}

func TestResetPasswordTemplateContent(t *testing.T) {
	var buf strings.Builder
	err := resetPasswordTmpl.Execute(&buf, ResetPasswordData{
		DisplayName: "Bob",
		ResetURL:    "https://example.com/reset/xyz",
	})
	if err != nil {
		t.Fatalf("template execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Bob") {
		t.Error("expected display_name 'Bob' in output")
	}
	if !strings.Contains(out, "https://example.com/reset/xyz") {
		t.Error("expected reset_url in output")
	}
	if !strings.Contains(out, "1 hour") {
		t.Error("expected expiry hint in reset email")
	}
}

func TestNewSenderUnconfigured_ReturnsNoop(t *testing.T) {
	// No WAF_SMTP_HOST → configured=false
	s := newSenderFromConfig(smtpConfig{})
	if s.configured {
		t.Fatal("expected sender to be unconfigured (no-op)")
	}
	// Both send helpers must return nil on unconfigured sender (dev no-op)
	if err := s.SendVerificationEmail(context.Background(), "x@x.com", "User", "http://link"); err != nil {
		t.Errorf("SendVerificationEmail no-op: expected nil, got %v", err)
	}
	if err := s.SendPasswordResetEmail(context.Background(), "x@x.com", "User", "http://link"); err != nil {
		t.Errorf("SendPasswordResetEmail no-op: expected nil, got %v", err)
	}
}

func TestBuildMIMEMessage(t *testing.T) {
	msg := buildMIMEMessage("WAF <noreply@example.com>", "user@example.com", "Test Subject", "<p>Hello</p>")
	s := string(msg)
	if !strings.Contains(s, "Subject: Test Subject") {
		t.Error("missing Subject header")
	}
	if !strings.Contains(s, "multipart/alternative") {
		t.Error("missing multipart/alternative content-type")
	}
	if !strings.Contains(s, "<p>Hello</p>") {
		t.Error("missing HTML body")
	}
	if !strings.Contains(s, "This message requires an HTML-capable client.") {
		t.Error("missing plain-text fallback (mirrors email.py set_content)")
	}
}

func TestDefaultSMTPConfig(t *testing.T) {
	// Ensure defaults match config.py: port=587, starttls=true
	cfg := loadConfig()
	if cfg.port != "587" {
		t.Errorf("default SMTP port should be 587, got %s", cfg.port)
	}
	if !cfg.starttls {
		t.Error("default SMTP starttls should be true")
	}
	if cfg.fromEmail != "noreply@localhost" {
		t.Errorf("default from_email should be noreply@localhost, got %s", cfg.fromEmail)
	}
	if cfg.fromName != "WAF" {
		t.Errorf("default from_name should be WAF, got %s", cfg.fromName)
	}
}
