package authapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
)

func TestStashCodecRoundTrip(t *testing.T) {
	toks := []string{"v4.local.aaa", "v4.local.bbb"}
	enc := encodeStash(toks)
	assert.NotEmpty(t, enc)
	assert.NotContains(t, enc, ",")
	assert.NotContains(t, enc, ";")
	assert.Equal(t, toks, decodeStash(enc))
	assert.Nil(t, decodeStash(""))
	assert.Nil(t, decodeStash("@@bad@@"))
}

func TestPruneStashDropsInvalidDedupesExcludes(t *testing.T) {
	iss := auth.NewIssuer(testKey())
	svc := &Service{decoder: auth.NewDecoder(testKey())}
	t1, _ := iss.CreateSessionToken(1, "client", nil, nil)
	t2, _ := iss.CreateSessionToken(2, "client", nil, nil)
	t2dup, _ := iss.CreateSessionToken(2, "client", nil, nil)

	out := svc.pruneStash([]string{t1, "garbage", t2, t2dup}, 1)
	assert.Len(t, out, 1)
	uid, ok := svc.tokenUID(out[0])
	assert.True(t, ok)
	assert.Equal(t, int64(2), uid)
}

func TestSwitchAccountToAlreadyActiveIsNoop(t *testing.T) {
	h := newHarness(t, Config{})

	// Seed uid 101 into the fake store so GetUserByIDFull resolves.
	u := &store.User{ID: 101, Email: "alice@example.com", DisplayName: "Alice", PlatformRole: "client"}
	h.st.usersByID[101] = u

	// Mint a session token for uid 101 and set it as the active cookie.
	tok, err := auth.NewIssuer(testKey()).CreateSessionToken(101, "client", nil, nil)
	require.NoError(t, err)
	ctx := ctxWithCookie(sessionCookie + "=" + tok)

	// SwitchAccount to uid 101 (the already-active account) — should be a no-op.
	resp, err := h.svc.SwitchAccount(ctx, &authv1.SwitchAccountRequest{UserId: 101})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, int64(101), resp.Id)
}
