package authapi

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zwarder/waf/gobackend/internal/auth"
)

// TestSessionMaxAgeMatchesTokenTTL pins the cookie-lifetime ↔ token-lifetime
// contract and its units (seconds): the browser must drop the waf_session
// cookie exactly when the PASETO token inside it expires.
func TestSessionMaxAgeMatchesTokenTTL(t *testing.T) {
	assert.Equal(t, int(auth.SessionTTL().Seconds()), sessionMaxAge())
	assert.Positive(t, sessionMaxAge())
}

// TestBuildCookie_SessionMaxAge asserts the issued session cookie carries the
// configured positive Max-Age (clears are covered by Max-Age=0 tests in
// service_test.go / accounts_test.go).
func TestBuildCookie_SessionMaxAge(t *testing.T) {
	c := buildCookie(sessionCookie, "tok", sessionMaxAge(), false)
	assert.Contains(t, c, fmt.Sprintf("Max-Age=%d", sessionMaxAge()))
	assert.Contains(t, c, "HttpOnly")
	assert.Contains(t, c, "SameSite=Lax")
}
