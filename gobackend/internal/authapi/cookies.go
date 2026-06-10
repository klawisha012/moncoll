package authapi

// cookies.go — Set-Cookie string builders + response-metadata emission.
//
// gRPC handlers can't set HTTP headers directly. We emit a "x-set-cookie"
// (and/or "x-redirect") metadata pair via grpc.SetHeader; the gateway's
// WithForwardResponseOption (internal/server/gateway.go) translates these into
// real Set-Cookie / Location:302 on the HTTP response.
//
// Cookie attributes keep the legacy Python shape (set_cookie calls in
// routers/{password,totp,oauth}.py + dependencies.py):
//   name=waf_session, HttpOnly, Secure=cookie_secure, SameSite=Lax, Path=/.
// Max-Age intentionally diverges from Python's fixed 28800s: it now follows
// auth.SessionTTL (WAF_SESSION_TTL_HOURS, default 7d). Logout / state clears
// use Max-Age=0.

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/zwarder/waf/gobackend/internal/auth"
)

// Cookie names — mirror dependencies.py + routers.
const (
	sessionCookie     = "waf_session"
	totpEnrolCookie   = "waf_totp_enrol"
	totpPendingCookie = "waf_totp_pending"
	oauthStateCookie  = "waf_oauth_state"
)

// sessionMaxAge is the cookie Max-Age in seconds, derived from
// auth.SessionTTL at call time (single source of truth — no init-order
// dependent cached copy) so the cookie lives exactly as long as the PASETO
// token inside it stays valid.
func sessionMaxAge() int { return int(auth.SessionTTL().Seconds()) }

// Metadata keys read by the gateway ForwardResponseOption.
const (
	mdSetCookie = "x-set-cookie"
	mdRedirect  = "x-redirect"
)

// buildCookie constructs a Set-Cookie header value. secure toggles the Secure
// attribute (driven by WAF_COOKIE_SECURE). SameSite=Lax + HttpOnly + Path=/
// match every Python set_cookie call.
func buildCookie(name, value string, maxAge int, secure bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s=%s", name, value)
	b.WriteString("; Path=/")
	fmt.Fprintf(&b, "; Max-Age=%d", maxAge)
	b.WriteString("; HttpOnly")
	b.WriteString("; SameSite=Lax")
	if secure {
		b.WriteString("; Secure")
	}
	return b.String()
}

// clearCookie builds a Set-Cookie value that deletes the named cookie
// (Max-Age=0), mirroring Response.delete_cookie(name, path="/").
func clearCookie(name string, secure bool) string {
	return buildCookie(name, "", 0, secure)
}

// emitSetCookie appends a Set-Cookie value to the response metadata. Multiple
// calls accumulate (grpc metadata.Pairs values are appended), so a handler can
// set + clear several cookies in one response.
func emitSetCookie(ctx context.Context, cookie string) {
	_ = grpc.SetHeader(ctx, metadata.Pairs(mdSetCookie, cookie))
}

// emitRedirect sets the 302 Location target via response metadata.
func emitRedirect(ctx context.Context, location string) {
	_ = grpc.SetHeader(ctx, metadata.Pairs(mdRedirect, location))
}
