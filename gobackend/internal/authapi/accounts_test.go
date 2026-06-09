package authapi

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

func TestLoginKeepCurrentStashesPrevious(t *testing.T) {
	h := newHarness(t, Config{})

	// Seed a verified client user that a normal Login would succeed for.
	seedVerifiedClient(t, h, "b@x.test", "hunter2")

	// Mint a token for a DIFFERENT uid (101) — this represents an existing active
	// session already in the browser cookie.
	activeTok, err := auth.NewIssuer(testKey()).CreateSessionToken(101, "client", nil, nil)
	require.NoError(t, err)

	// Attach the existing active session as the incoming cookie.
	ctx := ctxWithCookie(sessionCookie + "=" + activeTok)

	// Run Login with keep_current=true.
	md, err := runWithMD(ctx, func(c context.Context) error {
		_, e := h.svc.Login(c, &authv1.LoginRequest{
			Email:        "b@x.test",
			Password:     "hunter2",
			CaptchaToken: "t",
			KeepCurrent:  true,
		})
		return e
	})
	require.NoError(t, err)

	// The new waf_session cookie must be non-empty (the freshly-logged-in token).
	newSess := extractCookieVal(md, sessionCookie)
	require.NotEmpty(t, newSess, "waf_session cookie must be set after keep_current login")

	// The waf_accounts cookie must encode exactly the previous active token.
	stashRaw := extractCookieVal(md, stashCookie)
	require.NotEmpty(t, stashRaw, "waf_accounts stash cookie must be set")
	stashed := decodeStash(stashRaw)
	require.Equal(t, []string{activeTok}, stashed, "stash must contain exactly the previous active token")
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

func TestListAccountsActiveFirstThenStash(t *testing.T) {
	h := newHarness(t, Config{})

	// Seed both users so GetUserByIDFull resolves.
	h.st.usersByID[101] = &store.User{ID: 101, Email: "admin@example.com", DisplayName: "Admin", PlatformRole: "admin"}
	h.st.usersByID[102] = &store.User{ID: 102, Email: "client@example.com", DisplayName: "Client", PlatformRole: "client"}

	iss := auth.NewIssuer(testKey())
	activeTok, err := iss.CreateSessionToken(101, "admin", nil, nil)
	require.NoError(t, err)
	stashedTok, err := iss.CreateSessionToken(102, "client", nil, nil)
	require.NoError(t, err)

	stashVal := encodeStash([]string{stashedTok})
	ctx := ctxWithCookie(sessionCookie + "=" + activeTok + "; " + stashCookie + "=" + stashVal)

	resp, err := h.svc.ListAccounts(ctx, &authv1.ListAccountsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Accounts, 2)
	assert.Equal(t, int64(101), resp.Accounts[0].UserId)
	assert.True(t, resp.Accounts[0].Active)
	assert.Equal(t, int64(102), resp.Accounts[1].UserId)
	assert.False(t, resp.Accounts[1].Active)
}

func TestSwitchAccountSwapsActiveAndStash(t *testing.T) {
	h := newHarness(t, Config{})

	// Seed both users so GetUserByIDFull resolves.
	h.st.usersByID[101] = &store.User{ID: 101, Email: "admin@example.com", DisplayName: "Admin", PlatformRole: "admin"}
	h.st.usersByID[102] = &store.User{ID: 102, Email: "client@example.com", DisplayName: "Client", PlatformRole: "client"}

	iss := auth.NewIssuer(testKey())
	activeTok, err := iss.CreateSessionToken(101, "admin", nil, nil)
	require.NoError(t, err)
	stashedTok, err := iss.CreateSessionToken(102, "client", nil, nil)
	require.NoError(t, err)

	stashVal := encodeStash([]string{stashedTok})
	ctx := ctxWithCookie(sessionCookie + "=" + activeTok + "; " + stashCookie + "=" + stashVal)

	md, err := runWithMD(ctx, func(c context.Context) error {
		_, e := h.svc.SwitchAccount(c, &authv1.SwitchAccountRequest{UserId: 102})
		return e
	})
	require.NoError(t, err)

	// The emitted waf_session must belong to uid 102.
	newSession := extractCookieVal(md, sessionCookie)
	require.NotEmpty(t, newSession)
	uid, ok := h.svc.tokenUID(newSession)
	assert.True(t, ok)
	assert.Equal(t, int64(102), uid)

	// The emitted waf_accounts stash must contain exactly the original 101 token.
	newStashRaw := extractCookieVal(md, stashCookie)
	require.NotEmpty(t, newStashRaw)
	newStash := decodeStash(newStashRaw)
	require.Len(t, newStash, 1)
	stashedUID, ok := h.svc.tokenUID(newStash[0])
	assert.True(t, ok)
	assert.Equal(t, int64(101), stashedUID)
}

func TestSwitchAccountUnknownUID(t *testing.T) {
	h := newHarness(t, Config{})

	// Seed uid 101 only — uid 999 is unknown/not stashed.
	h.st.usersByID[101] = &store.User{ID: 101, Email: "admin@example.com", DisplayName: "Admin", PlatformRole: "admin"}

	iss := auth.NewIssuer(testKey())
	activeTok, err := iss.CreateSessionToken(101, "admin", nil, nil)
	require.NoError(t, err)

	ctx := ctxWithCookie(sessionCookie + "=" + activeTok)

	_, err = h.svc.SwitchAccount(ctx, &authv1.SwitchAccountRequest{UserId: 999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestLogoutOnePromotesStash(t *testing.T) {
	h := newHarness(t, Config{})

	// Seed both users so tokenUID resolves.
	h.st.usersByID[101] = &store.User{ID: 101, Email: "admin@example.com", DisplayName: "Admin", PlatformRole: "admin"}
	h.st.usersByID[102] = &store.User{ID: 102, Email: "client@example.com", DisplayName: "Client", PlatformRole: "client"}

	iss := auth.NewIssuer(testKey())
	activeTok, err := iss.CreateSessionToken(101, "admin", nil, nil)
	require.NoError(t, err)
	stashedTok, err := iss.CreateSessionToken(102, "client", nil, nil)
	require.NoError(t, err)

	cookieHdr := sessionCookie + "=" + activeTok + "; " + stashCookie + "=" + encodeStash([]string{stashedTok})
	ctx := ctxWithCookie(cookieHdr)

	md, err := runWithMD(ctx, func(c context.Context) error {
		_, e := h.svc.Logout(c, &authv1.LogoutRequest{All: false})
		return e
	})
	require.NoError(t, err)

	// The emitted waf_session must decode to uid 102 (the promoted stashed account).
	newSession := extractCookieVal(md, sessionCookie)
	require.NotEmpty(t, newSession, "waf_session cookie must be emitted after single logout")
	uid, ok := h.svc.tokenUID(newSession)
	assert.True(t, ok)
	assert.Equal(t, int64(102), uid)

	// The emitted waf_accounts stash must be empty (cleared — one item was promoted).
	newStashRaw := extractCookieVal(md, stashCookie)
	stash := decodeStash(newStashRaw)
	assert.Len(t, stash, 0, "stash must be empty after the only stashed account is promoted")
}

func TestLogoutAllClearsBoth(t *testing.T) {
	h := newHarness(t, Config{})

	// Seed both users.
	h.st.usersByID[101] = &store.User{ID: 101, Email: "admin@example.com", DisplayName: "Admin", PlatformRole: "admin"}
	h.st.usersByID[102] = &store.User{ID: 102, Email: "client@example.com", DisplayName: "Client", PlatformRole: "client"}

	iss := auth.NewIssuer(testKey())
	activeTok, err := iss.CreateSessionToken(101, "admin", nil, nil)
	require.NoError(t, err)
	stashedTok, err := iss.CreateSessionToken(102, "client", nil, nil)
	require.NoError(t, err)

	cookieHdr := sessionCookie + "=" + activeTok + "; " + stashCookie + "=" + encodeStash([]string{stashedTok})
	ctx := ctxWithCookie(cookieHdr)

	md, err := runWithMD(ctx, func(c context.Context) error {
		_, e := h.svc.Logout(c, &authv1.LogoutRequest{All: true})
		return e
	})
	require.NoError(t, err)

	// clearCookie produces e.g. "waf_session=; Path=/; Max-Age=0; ..."
	// so the substring "waf_session=;" is present in a cleared waf_session cookie.
	assert.True(t, hasCookie(md, sessionCookie+"=;"), "waf_session must be cleared (empty value)")
	assert.True(t, hasCookie(md, "Max-Age=0"), "cleared cookie must carry Max-Age=0")
	assert.True(t, hasCookie(md, stashCookie+"=;"), "waf_accounts must be cleared (empty value)")
}
