package authapi

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
)

// stashCookie holds the non-active signed-in sessions (httpOnly, same flags as
// waf_session). maxAccounts caps active + stashed to bound cookie size and the
// number of full credentials kept in one browser.
const (
	stashCookie = "waf_accounts"
	maxAccounts = 3 // active + (maxAccounts-1) stashed
)

// encodeStash serialises tokens to a cookie-safe value: base64url(JSON([]token)).
func encodeStash(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}
	b, err := json.Marshal(tokens)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeStash reverses encodeStash. Any malformed input yields nil (self-heals).
func decodeStash(raw string) []string {
	if raw == "" {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil
	}
	var toks []string
	if err := json.Unmarshal(b, &toks); err != nil {
		return nil
	}
	return toks
}

// tokenUID decodes a session token and returns its user id when valid+unexpired.
func (s *Service) tokenUID(token string) (int64, bool) {
	if token == "" {
		return 0, false
	}
	c, err := s.decoder.Decode(token)
	if err != nil {
		return 0, false
	}
	return parseUserID(c.Sub)
}

// pruneStash keeps only valid, unexpired, non-excludeUID, uid-deduped tokens
// (order preserved, first wins). No cap here — callers enforce maxAccounts.
func (s *Service) pruneStash(tokens []string, excludeUID int64) []string {
	seen := map[int64]bool{}
	out := []string{}
	for _, t := range tokens {
		uid, ok := s.tokenUID(t)
		if !ok || uid == excludeUID || seen[uid] {
			continue
		}
		seen[uid] = true
		out = append(out, t)
	}
	return out
}

// emitStash writes (or clears) the stash cookie.
func (s *Service) emitStash(ctx context.Context, tokens []string) {
	if len(tokens) == 0 {
		emitSetCookie(ctx, clearCookie(stashCookie, s.cfg.CookieSecure))
		return
	}
	emitSetCookie(ctx, buildCookie(stashCookie, encodeStash(tokens), sessionMaxAge, s.cfg.CookieSecure))
}

// setActiveWithStash makes newToken (for newUID) active. keepCurrent=false is a
// fresh login: clears the stash. keepCurrent=true preserves the outgoing active
// session and the existing stash, erroring if that would exceed maxAccounts;
// expired/invalid stash entries are pruned before the cap is evaluated, so the
// effective cap is "active + (maxAccounts-1) valid stashed".
func (s *Service) setActiveWithStash(ctx context.Context, newToken string, newUID int64, keepCurrent bool) error {
	if !keepCurrent {
		emitSetCookie(ctx, buildCookie(sessionCookie, newToken, sessionMaxAge, s.cfg.CookieSecure))
		emitSetCookie(ctx, clearCookie(stashCookie, s.cfg.CookieSecure))
		return nil
	}
	current := auth.CookieFromMetadata(ctx, sessionCookie)
	stash := decodeStash(auth.CookieFromMetadata(ctx, stashCookie))
	if cur, ok := s.tokenUID(current); ok && cur != newUID {
		stash = append([]string{current}, stash...)
	}
	pruned := s.pruneStash(stash, newUID)
	if len(pruned) > maxAccounts-1 {
		return status.Error(codes.FailedPrecondition, "too many signed-in accounts")
	}
	emitSetCookie(ctx, buildCookie(sessionCookie, newToken, sessionMaxAge, s.cfg.CookieSecure))
	s.emitStash(ctx, pruned)
	return nil
}

// ListAccounts returns the active account first, then stashed ones (uid-deduped),
// skipping any whose token is invalid/expired or whose user no longer exists.
func (s *Service) ListAccounts(ctx context.Context, _ *authv1.ListAccountsRequest) (*authv1.ListAccountsResponse, error) {
	active := auth.CookieFromMetadata(ctx, sessionCookie)
	stash := decodeStash(auth.CookieFromMetadata(ctx, stashCookie))
	resp := &authv1.ListAccountsResponse{}
	seen := map[int64]bool{}
	add := func(token string, isActive bool) {
		uid, ok := s.tokenUID(token)
		if !ok || seen[uid] {
			return
		}
		u, err := s.store.GetUserByIDFull(ctx, uid)
		if err != nil || u == nil {
			return
		}
		seen[uid] = true
		resp.Accounts = append(resp.Accounts, &authv1.Account{
			UserId:       u.ID,
			Email:        u.Email,
			DisplayName:  u.DisplayName,
			PlatformRole: u.PlatformRole,
			Active:       isActive,
		})
	}
	add(active, true)
	for _, t := range stash {
		add(t, false)
	}
	return resp, nil
}

// SwitchAccount promotes a stashed account to active, demoting the current one
// back into the stash.
func (s *Service) SwitchAccount(ctx context.Context, req *authv1.SwitchAccountRequest) (*authv1.UserPublic, error) {
	active := auth.CookieFromMetadata(ctx, sessionCookie)
	if uid, ok := s.tokenUID(active); ok && uid == req.GetUserId() {
		u, err := s.store.GetUserByIDFull(ctx, uid)
		if err != nil || u == nil {
			return nil, status.Error(codes.Internal, "user lookup failed")
		}
		return userPublic(u), nil // already active — no-op
	}
	stash := decodeStash(auth.CookieFromMetadata(ctx, stashCookie))
	var target string
	rest := []string{}
	for _, t := range stash {
		uid, ok := s.tokenUID(t)
		if target == "" && ok && uid == req.GetUserId() {
			target = t
			continue
		}
		rest = append(rest, t)
	}
	if target == "" {
		return nil, status.Error(codes.NotFound, "account not signed in")
	}
	if _, ok := s.tokenUID(active); ok {
		rest = append([]string{active}, rest...)
	}
	emitSetCookie(ctx, buildCookie(sessionCookie, target, sessionMaxAge, s.cfg.CookieSecure))
	s.emitStash(ctx, s.pruneStash(rest, req.GetUserId()))

	u, err := s.store.GetUserByIDFull(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "user lookup failed")
	}
	return userPublic(u), nil
}
