package email

import (
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

// TestMIMEMessageParses guards deliverability: a structurally-invalid message,
// or one missing Date/Message-ID, gets dropped or spam-filed regardless of the
// SMTP result. Parse a built invite message the way a receiving MTA would.
func TestMIMEMessageParses(t *testing.T) {
	raw := buildMIMEMessage("WAF <noreply@example.com>", "user@gmail.com", "Subj",
		"<p>hi <a href=\"https://x/accept?token=a&b=c\">link</a></p>",
		"hi\nhttps://x/accept?token=a&b=c\n")
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("message does not parse: %v", err)
	}
	if msg.Header.Get("Date") == "" {
		t.Error("missing Date header")
	}
	if msg.Header.Get("Message-ID") == "" {
		t.Error("missing Message-ID header")
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" {
		t.Fatalf("content-type = %q (%v)", mediaType, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var types []string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("part read: %v", err)
		}
		body, _ := io.ReadAll(p)
		mt, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		types = append(types, mt)
		// The plain part must keep the URL intact (no &amp; escaping).
		if mt == "text/plain" && !strings.Contains(string(body), "token=a&b=c") {
			t.Errorf("plain part escaped the URL: %q", string(body))
		}
	}
	if len(types) != 2 || types[0] != "text/plain" || types[1] != "text/html" {
		t.Errorf("parts = %v, want [text/plain text/html]", types)
	}
}

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
	msg := buildMIMEMessage("WAF <noreply@example.com>", "user@example.com", "Test Subject", "<p>Hello</p>", "Hello in plain text")
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
	if !strings.Contains(s, "Hello in plain text") {
		t.Error("missing real plain-text alternative")
	}
	// Date + Message-ID are required for deliverability (Gmail drops mail without them).
	if !strings.Contains(s, "\r\nDate: ") {
		t.Error("missing Date header")
	}
	if !strings.Contains(s, "\r\nMessage-ID: <") || !strings.Contains(s, "@example.com>") {
		t.Error("missing or malformed Message-ID header (should be anchored to sender domain)")
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
