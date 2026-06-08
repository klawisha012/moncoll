package auth

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/require"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i) // 0x00..0x1f — matches the optional pyseto fixture
	}
	return k
}

func TestDecodeRoundTrip(t *testing.T) {
	tok := mintLocal(t, testKey(),
		`{"sub":"7","pr":"admin","tn":null,"tr":null,"iat":1.0,"exp":`+
			itoa(time.Now().Add(time.Hour).Unix())+`.0}`)
	dec := NewDecoder(testKey())
	claims, err := dec.Decode(tok)
	require.NoError(t, err)
	require.Equal(t, "7", claims.Sub)
	require.Equal(t, "admin", claims.PlatformRole)
}

func TestDecodeExpiredFails(t *testing.T) {
	dec := NewDecoder(testKey())
	expired := mintLocal(t, testKey(), `{"sub":"7","pr":"admin","exp":`+
		itoa(time.Now().Add(-time.Hour).Unix())+`.0}`)
	_, err := dec.Decode(expired)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestDecodeWrongKeyFails(t *testing.T) {
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0xAA
	}
	good := mintLocal(t, testKey(), `{"sub":"7","pr":"admin","exp":`+
		itoa(time.Now().Add(time.Hour).Unix())+`.0}`)
	dec := NewDecoder(other)
	_, err := dec.Decode(good)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestDecodeFixtureToken(t *testing.T) {
	raw, err := os.ReadFile("testdata/py_token.txt")
	if err != nil {
		t.Skip("optional: generate testdata/py_token.txt from pyseto to cross-verify")
	}
	dec := NewDecoder(testKey())
	parser := paseto.NewParserWithoutExpiryCheck()
	parsed, err := parser.ParseV4Local(dec.key, strings.TrimSpace(string(raw)), nil)
	require.NoError(t, err)

	var claims Claims
	err = json.Unmarshal(parsed.ClaimsJSON(), &claims)
	require.NoError(t, err)
	require.Equal(t, "7", claims.Sub)
	require.Equal(t, "admin", claims.PlatformRole)
}
