package centrifugo

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMintConnectionToken_ValidHS256JWT(t *testing.T) {
	secret := "test-hmac-secret-key"
	t.Setenv("CENTRIFUGO_TOKEN_HMAC_SECRET", secret)

	ttl := time.Hour
	userID := "42"

	before := time.Now().Unix()
	tokenStr, err := MintConnectionToken(userID, ttl)
	after := time.Now().Unix()
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)

	// Parse and verify with the same secret.
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	// sub must equal userID.
	sub, err := claims.GetSubject()
	require.NoError(t, err)
	assert.Equal(t, userID, sub)

	// exp must be in [now+ttl-1s, now+ttl+1s] (generous for CI timing).
	expTime, err := claims.GetExpirationTime()
	require.NoError(t, err)
	expUnix := expTime.Unix()
	assert.GreaterOrEqual(t, expUnix, before+int64(ttl.Seconds())-1)
	assert.LessOrEqual(t, expUnix, after+int64(ttl.Seconds())+1)

	// Algorithm header must be HS256.
	assert.Equal(t, "HS256", token.Method.Alg())
}

func TestMintConnectionToken_EmptySecret(t *testing.T) {
	t.Setenv("CENTRIFUGO_TOKEN_HMAC_SECRET", "")
	_, err := MintConnectionToken("99", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CENTRIFUGO_TOKEN_HMAC_SECRET is empty")
}

func TestMintConnectionToken_DifferentUserIDs(t *testing.T) {
	t.Setenv("CENTRIFUGO_TOKEN_HMAC_SECRET", "another-secret")

	tok1, err := MintConnectionToken("1", time.Hour)
	require.NoError(t, err)
	tok2, err := MintConnectionToken("2", time.Hour)
	require.NoError(t, err)

	// Tokens for different users must differ.
	assert.NotEqual(t, tok1, tok2)
}
