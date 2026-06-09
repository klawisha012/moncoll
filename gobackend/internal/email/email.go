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
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"strings"
	texttemplate "text/template"
	"time"
)

// smtpTimeout bounds both the TCP connect and the whole SMTP conversation, so
// an unreachable or stalled mail server (e.g. egress to the provider is blocked)
// fails fast instead of hanging the caller's request for the OS TCP timeout.
const smtpTimeout = 10 * time.Second

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

// Plain-text alternatives. A multipart/alternative message whose text/plain part
// is a junk placeholder ("requires an HTML-capable client") is a strong spam
// signal — Gmail files such mail under Spam. Each plain part below mirrors the
// HTML content (same wording + the same link) so the two alternatives agree,
// which is what spam filters expect from legitimate transactional mail.
var verifyEmailTextTmpl = texttemplate.Must(texttemplate.New("verify_email_txt").Parse(`Hi {{.DisplayName}},

Confirm your email to activate your WAF account:
{{.VerifyURL}}

This link expires in 24 hours.`))

var resetPasswordTextTmpl = texttemplate.Must(texttemplate.New("reset_password_txt").Parse(`Hi {{.DisplayName}},

Reset your password:
{{.ResetURL}}

This link expires in 1 hour. Ignore this email if you didn't request it.`))

var inviteTextTmpl = texttemplate.Must(texttemplate.New("team_invite_txt").Parse(`Hi,

You've been invited to join the team "{{.TeamName}}" on WAF.

Open this link to accept the invitation:
{{.InviteURL}}

This invitation expires in 7 days. Ignore this email if you didn't expect it.`))

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

// Configured reports whether a real SMTP host is set. When false, send is a
// dev no-op (logs the body, delivers nothing) — callers use this to avoid
// reporting "email sent" when nothing actually left the process.
func (s *Sender) Configured() bool { return s.configured }

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
	data := VerifyEmailData{DisplayName: displayName, VerifyURL: verifyURL}
	html, text, err := render(verifyEmailTmpl, verifyEmailTextTmpl, data)
	if err != nil {
		return fmt.Errorf("email: render verify_email: %w", err)
	}
	return s.send(ctx, to, "Verify your WAF email", html, text)
}

// InviteData holds template variables for SendInvitationEmail.
type InviteData struct {
	TeamName  string
	InviteURL string
}

// SendInvitationEmail sends a team invitation with a tokenized accept link.
func (s *Sender) SendInvitationEmail(ctx context.Context, to, teamName, inviteURL string) error {
	data := InviteData{TeamName: teamName, InviteURL: inviteURL}
	html, text, err := render(inviteTmpl, inviteTextTmpl, data)
	if err != nil {
		return fmt.Errorf("email: render team_invite: %w", err)
	}
	return s.send(ctx, to, "You've been invited to a WAF team", html, text)
}

// SendPasswordResetEmail sends "Reset your WAF password" to the given address.
// Mirror of email.py send_password_reset.
func (s *Sender) SendPasswordResetEmail(ctx context.Context, to, displayName, resetURL string) error {
	data := ResetPasswordData{DisplayName: displayName, ResetURL: resetURL}
	html, text, err := render(resetPasswordTmpl, resetPasswordTextTmpl, data)
	if err != nil {
		return fmt.Errorf("email: render reset_password: %w", err)
	}
	return s.send(ctx, to, "Reset your WAF password", html, text)
}

// executer is satisfied by both html/template and text/template *Template.
type executer interface {
	Execute(wr io.Writer, data any) error
}

// render executes the HTML and plain-text templates for one message against the
// same data, returning (html, text). Both alternatives must agree in content for
// good spam scoring. The text template must be a text/template (not html/template)
// so URLs aren't entity-escaped (e.g. & → &amp;) in the plain part.
func render(htmlTmpl, textTmpl executer, data any) (string, string, error) {
	var htmlBuf, textBuf bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBuf, data); err != nil {
		return "", "", fmt.Errorf("html template: %w", err)
	}
	if err := textTmpl.Execute(&textBuf, data); err != nil {
		return "", "", fmt.Errorf("text template: %w", err)
	}
	return htmlBuf.String(), textBuf.String(), nil
}

// send is the internal dispatcher — mirrors email.py _send.
// When not configured: logs a warning + the body, returns nil (dev no-op).
func (s *Sender) send(_ context.Context, toEmail, subject, htmlBody, textBody string) error {
	if !s.configured {
		slog.Warn("SMTP not configured — would send email",
			"to", toEmail,
			"subject", subject,
		)
		slog.Info("EMAIL BODY (dev):\n" + textBody)
		return nil
	}
	return s.sendSMTP(toEmail, subject, htmlBody, textBody)
}

// sendSMTP delivers the message via net/smtp, mirroring email.py's aiosmtplib
// behaviour but with bounded timeouts:
//   - starttls=true  → connect plaintext, upgrade with STARTTLS (port 587)
//   - starttls=false → implicit TLS / SMTPS (port 465)
//
// Every network step is bounded by smtpTimeout (connect) plus a conversation
// deadline on the connection, so a blocked or stalled provider can't hang the
// caller — it fails fast and the invitation is shared via its accept_url.
func (s *Sender) sendSMTP(to, subject, htmlBody, textBody string) error {
	from := fmt.Sprintf("%s <%s>", s.cfg.fromName, s.cfg.fromEmail)
	msg := buildMIMEMessage(from, to, subject, htmlBody, textBody)
	addr := net.JoinHostPort(s.cfg.host, s.cfg.port)
	tlsCfg := &tls.Config{ServerName: s.cfg.host} //nolint:gosec
	dialer := &net.Dialer{Timeout: smtpTimeout}

	var conn net.Conn
	var err error
	if s.cfg.starttls {
		conn, err = dialer.Dial("tcp", addr)
	} else {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	}
	if err != nil {
		return fmt.Errorf("email: dial %s: %w", addr, err)
	}
	defer conn.Close()
	// Bound the whole conversation: a server that accepts the TCP connection but
	// then stalls (no banner / hangs mid-DATA) must not block past this deadline.
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))

	c, err := smtp.NewClient(conn, s.cfg.host)
	if err != nil {
		return fmt.Errorf("email: smtp.NewClient: %w", err)
	}
	defer c.Quit() //nolint:errcheck

	if s.cfg.starttls {
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("email: smtp StartTLS: %w", err)
		}
	}
	if s.cfg.username != "" {
		// PlainAuth refuses to transmit credentials over a cleartext link; by
		// this point the connection is TLS (implicit, or upgraded via STARTTLS).
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

// buildMIMEMessage constructs a multipart/alternative MIME message with a real
// text/plain alternative followed by the HTML body. The plain part mirrors the
// HTML content (not a junk placeholder) — a content-matching text alternative is
// what spam filters expect from legitimate transactional mail.
func buildMIMEMessage(from, to, subject, htmlBody, textBody string) []byte {
	boundary := "waf_mime_boundary_001"
	if textBody == "" {
		textBody = "Open this email in an HTML-capable client to view it."
	}
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	// Date and Message-ID are mandatory per RFC 5322. Python's smtplib.send_message
	// injected them automatically; the raw net/smtp port did not, so messages went
	// out without them — Gmail and others silently drop or spam-file such mail even
	// after the upstream server returns 250. Add them explicitly.
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: " + newMessageID(from) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString(`Content-Type: multipart/alternative; boundary="` + boundary + `"` + "\r\n")
	b.WriteString("\r\n")

	// Plain-text alternative — mirrors the HTML content (same link + wording).
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(textBody + "\r\n")

	// HTML part (mirrors email.py add_alternative(html_body, subtype="html"))
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(htmlBody + "\r\n")

	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

// newMessageID builds an RFC 5322 Message-ID of the form <random@domain>, where
// domain is taken from the sender address so the identifier is anchored to the
// sending domain (a deliverability nicety). Falls back to "localhost" if no
// domain can be parsed.
func newMessageID(from string) string {
	domain := "localhost"
	if at := strings.LastIndex(from, "@"); at >= 0 {
		if d := strings.Trim(from[at+1:], " <>"); d != "" {
			domain = d
		}
	}
	var rb [16]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return fmt.Sprintf("<waf.%d@%s>", time.Now().UnixNano(), domain)
	}
	return fmt.Sprintf("<%s@%s>", hex.EncodeToString(rb[:]), domain)
}
