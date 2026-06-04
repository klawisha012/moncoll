package auth

import (
	"strconv"
	"testing"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/require"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// mintLocal encrypts arbitrary claim bytes as a v4.local token the way pyseto
// does (raw JSON payload, no registered-claim coercion).
//
// We use NewTokenFromClaimsJSON to load the raw JSON directly into the Token's
// internal claim map (preserving float exp as a JSON number), then call
// V4Encrypt to produce a real v4.local ciphertext.
func mintLocal(t *testing.T, key []byte, claimsJSON string) string {
	t.Helper()
	k, err := paseto.V4SymmetricKeyFromBytes(key)
	require.NoError(t, err)

	tok, err := paseto.NewTokenFromClaimsJSON([]byte(claimsJSON), nil)
	require.NoError(t, err)

	// V4Encrypt returns the token string; implicit = nil (same as pyseto default)
	return tok.V4Encrypt(k, nil)
}
