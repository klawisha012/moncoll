package authapi

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// extractCookieVal pulls the value of the named cookie out of the emitted
// x-set-cookie metadata (parsing "<name>=<value>; ...").
func extractCookieVal(md metadata.MD, name string) string {
	for _, c := range md.Get(mdSetCookie) {
		for _, part := range strings.Split(c, ";") {
			n, v, found := strings.Cut(strings.TrimSpace(part), "=")
			if found && n == name {
				return v
			}
		}
	}
	return ""
}

// genCode produces a valid current TOTP code for the given base32 secret.
func genCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	return code
}
