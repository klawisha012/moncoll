// Package email provides SMTP email sending, mirroring backend/src/auth/email.py.
//
// Config is read from WAF_SMTP_* env vars (same as Python config.py).
// When WAF_SMTP_HOST is empty the Sender is a logged no-op — matching
// email.py's "_send: if not s.smtp_host: log + return" behaviour so that
// the stack works in dev without an SMTP server.
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"strings"
)

// -----------------------------------------------------------------------
// Templates — ported from email_templates/*.html (Jinja2 → html/template)
// -----------------------------------------------------------------------

var verifyEmailTmpl = template.Must(template.New("verify_email").Parse(`<p>Hi {{.DisplayName}},</p>
<p>Confirm your email to activate your WAF account:</p>
<p><a href="{{.VerifyURL}}">{{.VerifyURL}}</a></p>
<p>This link expires in 24 hours.</p>`))

var resetPasswordTmpl = template.Must(template.New("reset_password").Parse(`<p>Hi {{.DisplayName}},</p>
<p>Reset your password:</p>
<p><a href="{{.ResetURL}}">{{.ResetURL}}</a></p>
<p>This link expires in 1 hour. Ignore if you didn't request it.</p>`))

var inviteTmpl = template.Must(template.New("team_invite").Parse(`<p>Hi,</p>
<p>You've been invited to join the team <strong>{{.TeamName}}</strong> on WAF.</p>
<p><a href="{{.InviteURL}}">{{.InviteURL}}</a></p>
<p>This invitation expires in 7 days. Ignore this email if you didn't expect it.</p>`))

// -----------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------

type smtpConfig struct {
	host      string
	port      string
	username  string
	password  string
	fromEmail string
	fromName  string
	starttls  bool
}

func loadConfig() smtpConfig {
	port := os.Getenv("WAF_SMTP_PORT")
	if port == "" {
		port = "587"
	}
	startTLS := true
	if v := os.Getenv("WAF_SMTP_STARTTLS"); v != "" {
		startTLS = !(v == "false" || v == "0" || strings.EqualFold(v, "no"))
	}
	fromEmail := os.Getenv("WAF_SMTP_FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "noreply@localhost"
	}
	fromName := os.Getenv("WAF_SMTP_FROM_NAME")
	if fromName == "" {
		fromName = "WAF"
	}
	return smtpConfig{
		host:      os.Getenv("WAF_SMTP_HOST"),
		port:      port,
		username:  os.Getenv("WAF_SMTP_USERNAME"),
		password:  os.Getenv("WAF_SMTP_PASSWORD"),
		fromEmail: fromEmail,
		fromName:  fromName,
		starttls:  startTLS,
	}
}

// -----------------------------------------------------------------------
// Sender
// -----------------------------------------------------------------------

// Sender wraps SMTP configuration and exposes typed send helpers.
type Sender struct {
	cfg       smtpConfig
	configured bool
}

// NewSender reads WAF_SMTP_* from the environment.  If WAF_SMTP_HOST is
// empty the Sender is a no-op logger, matching email.py's behaviour.
func NewSender() *Sender {
	cfg := loadConfig()
	return &Sender{
		cfg:        cfg,
		configured: cfg.host != "",
	}
}

// newSenderFromConfig is used in tests to inject config without touching env.
func newSenderFromConfig(cfg smtpConfig) *Sender {
	return &Sender{cfg: cfg, configured: cfg.host != ""}
}

// VerifyEmailData holds template variables for SendVerificationEmail.
type VerifyEmailData struct {
	DisplayName string
	VerifyURL   string
}

// ResetPasswordData holds template variables for SendPasswordResetEmail.
type ResetPasswordData struct {
	DisplayName string
	ResetURL    string
}

// SendVerificationEmail sends "Verify your WAF email" to the given address.
// Mirror of email.py send_verify_email.
func (s *Sender) SendVerificationEmail(ctx context.Context, to, displayName, verifyURL string) error {
	var buf bytes.Buffer
	if err := verifyEmailTmpl.Execute(&buf, VerifyEmailData{
		DisplayName: displayName,
		VerifyURL:   verifyURL,
	}); err != nil {
		return fmt.Errorf("email: render verify_email template: %w", err)
	}
	return s.send(ctx, to, "Verify your WAF email", buf.String())
}

// InviteData holds template variables for SendInvitationEmail.
type InviteData struct {
	TeamName  string
	InviteURL string
}

// SendInvitationEmail sends a team invitation with a tokenized accept link.
func (s *Sender) SendInvitationEmail(ctx context.Context, to, teamName, inviteURL string) error {
	var buf bytes.Buffer
	if err := inviteTmpl.Execute(&buf, InviteData{TeamName: teamName, InviteURL: inviteURL}); err != nil {
		return fmt.Errorf("email: render team_invite template: %w", err)
	}
	return s.send(ctx, to, "You've been invited to a WAF team", buf.String())
}

// SendPasswordResetEmail sends "Reset your WAF password" to the given address.
// Mirror of email.py send_password_reset.
func (s *Sender) SendPasswordResetEmail(ctx context.Context, to, displayName, resetURL string) error {
	var buf bytes.Buffer
	if err := resetPasswordTmpl.Execute(&buf, ResetPasswordData{
		DisplayName: displayName,
		ResetURL:    resetURL,
	}); err != nil {
		return fmt.Errorf("email: render reset_password template: %w", err)
	}
	return s.send(ctx, to, "Reset your WAF password", buf.String())
}

// send is the internal dispatcher — mirrors email.py _send.
// When not configured: logs a warning + the body, returns nil (dev no-op).
func (s *Sender) send(_ context.Context, toEmail, subject, htmlBody string) error {
	if !s.configured {
		slog.Warn("SMTP not configured — would send email",
			"to", toEmail,
			"subject", subject,
		)
		slog.Info("EMAIL BODY (dev):\n" + htmlBody)
		return nil
	}
	return s.sendSMTP(toEmail, subject, htmlBody)
}

// sendSMTP delivers the message via net/smtp.
// email.py uses aiosmtplib with start_tls=s.smtp_starttls:
//   - starttls=true  → STARTTLS upgrade on the plain port (Python default, port 587)
//   - starttls=false → implicit TLS / SMTPS (port 465)
func (s *Sender) sendSMTP(to, subject, htmlBody string) error {
	from := fmt.Sprintf("%s <%s>", s.cfg.fromName, s.cfg.fromEmail)
	msg := buildMIMEMessage(from, to, subject, htmlBody)
	addr := net.JoinHostPort(s.cfg.host, s.cfg.port)

	if s.cfg.starttls {
		// STARTTLS: connect plaintext, upgrade with STARTTLS
		auth := smtp.PlainAuth("", s.cfg.username, s.cfg.password, s.cfg.host)
		if err := smtp.SendMail(addr, auth, s.cfg.fromEmail, []string{to}, msg); err != nil {
			return fmt.Errorf("email: smtp.SendMail STARTTLS: %w", err)
		}
		return nil
	}

	// Implicit TLS (SMTPS, typically port 465)
	tlsCfg := &tls.Config{ServerName: s.cfg.host} //nolint:gosec
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("email: tls.Dial: %w", err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, s.cfg.host)
	if err != nil {
		return fmt.Errorf("email: smtp.NewClient: %w", err)
	}
	defer c.Quit() //nolint:errcheck

	if s.cfg.username != "" {
		auth := smtp.PlainAuth("", s.cfg.username, s.cfg.password, s.cfg.host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("email: smtp Auth: %w", err)
		}
	}
	if err := c.Mail(s.cfg.fromEmail); err != nil {
		return fmt.Errorf("email: smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("email: smtp RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("email: smtp DATA: %w", err)
	}
	if _, err = w.Write(msg); err != nil {
		return fmt.Errorf("email: smtp DATA write: %w", err)
	}
	return w.Close()
}

// buildMIMEMessage constructs a minimal multipart/alternative MIME message
// with a text/plain fallback and the HTML body, matching email.py's
// EmailMessage.set_content / add_alternative pattern.
func buildMIMEMessage(from, to, subject, htmlBody string) []byte {
	boundary := "waf_mime_boundary_001"
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString(`Content-Type: multipart/alternative; boundary="` + boundary + `"` + "\r\n")
	b.WriteString("\r\n")

	// Plain-text fallback (mirrors email.py set_content)
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString("This message requires an HTML-capable client.\r\n")

	// HTML part (mirrors email.py add_alternative(html_body, subtype="html"))
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(htmlBody + "\r\n")

	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}
