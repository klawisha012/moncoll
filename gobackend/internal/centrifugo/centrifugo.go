// Package centrifugo provides an HTTP client for the Centrifugo v6 server API
// and a JWT minter for centrifuge-js client connection tokens.
//
// Publisher failure mode: if Centrifugo is down or returns a 5xx, Publish
// returns false and logs the error. It never panics — callers in the hot-path
// aggregator loop drop the delta and continue.
//
// Token: MintConnectionToken mints a standard HS256 JWT with claims
//
//	sub = userID, exp = now+ttl, subs = server-side dashboard subscriptions
//
// using CENTRIFUGO_TOKEN_HMAC_SECRET. Centrifugo v6 verifies this with
// client_token_hmac_secret_key from its config.json (or the env override
// CENTRIFUGO_CLIENT_TOKEN_HMAC_SECRET_KEY).
package centrifugo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Publisher is an HTTP client for the Centrifugo server-side publish API.
// Construct with NewPublisher; zero value is not valid.
type Publisher struct {
	apiURL string
	apiKey string
	http   *http.Client
}

// NewPublisher constructs a Publisher from env vars:
//
//	CENTRIFUGO_API_URL  (default: http://centrifugo:8000/api)
//	CENTRIFUGO_API_KEY
func NewPublisher() *Publisher {
	apiURL := os.Getenv("CENTRIFUGO_API_URL")
	if apiURL == "" {
		apiURL = "http://centrifugo:8000/api"
	}
	return &Publisher{
		apiURL: apiURL,
		apiKey: os.Getenv("CENTRIFUGO_API_KEY"),
		http: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// publishPayload is the JSON body for POST /publish.
type publishPayload struct {
	Channel string `json:"channel"`
	Data    any    `json:"data"`
}

// centrifugoResponse is the partial shape Centrifugo returns on both success
// and validation error. An "error" key signals a Centrifugo-level error even
// when the HTTP status is 200.
type centrifugoResponse struct {
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Publish sends data to a Centrifugo channel via POST <CENTRIFUGO_API_URL>/publish
// with the Authorization: apikey <KEY> header.
// Returns true if delivered, false on any error (transport, 5xx, or
// Centrifugo-level validation error). Errors are logged, never propagated —
// these updates are ephemeral; the next batch overwrites the loss.
func (p *Publisher) Publish(ctx context.Context, channel string, data any) (bool, error) {
	if p.apiKey == "" {
		slog.WarnContext(ctx, "centrifugo: CENTRIFUGO_API_KEY empty — skipping publish", "channel", channel)
		return false, nil
	}

	body, err := json.Marshal(publishPayload{Channel: channel, Data: data})
	if err != nil {
		slog.WarnContext(ctx, "centrifugo: marshal failed", "channel", channel, "err", err)
		return false, nil
	}

	url := p.apiURL + "/publish"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.WarnContext(ctx, "centrifugo: build request failed", "channel", channel, "err", err)
		return false, nil
	}
	req.Header.Set("Authorization", "apikey "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		slog.WarnContext(ctx, "centrifugo: publish transport error", "channel", channel, "err", err)
		return false, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		slog.WarnContext(ctx, "centrifugo: publish returned non-200",
			"channel", channel, "status", resp.StatusCode, "body", string(preview))
		return false, nil
	}

	var cr centrifugoResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		// Non-fatal: if we can't decode the response body, assume success
		// (Centrifugo returned 200 which is the strong signal).
		return true, nil
	}
	if cr.Error != nil {
		slog.WarnContext(ctx, "centrifugo: publish error in response",
			"channel", channel, "code", cr.Error.Code, "message", cr.Error.Message)
		return false, nil
	}
	return true, nil
}

// ─── Connection token ─────────────────────────────────────────────────────────

// MintConnectionToken mints a Centrifugo client connection JWT.
//
// Centrifugo v6 accepts a standard JWT with:
//
//	sub — user identifier (string)
//	exp — Unix timestamp of expiry
//
// Signed with HS256 using CENTRIFUGO_TOKEN_HMAC_SECRET. This must match
// client_token_hmac_secret_key in docker/centrifugo/config.json (or its env
// override CENTRIFUGO_CLIENT_TOKEN_HMAC_SECRET_KEY).
//
// Mirrors publisher.py make_connection_token exactly — same header/payload
// claim set, same algorithm.
func MintConnectionToken(userID string, ttl time.Duration) (string, error) {
	secret := os.Getenv("CENTRIFUGO_TOKEN_HMAC_SECRET")
	if secret == "" {
		return "", fmt.Errorf("centrifugo: CENTRIFUGO_TOKEN_HMAC_SECRET is empty — cannot mint connection tokens")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": now.Add(ttl).Unix(),
		"subs": map[string]map[string]any{
			"dashboard:map": map[string]any{},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("centrifugo: sign JWT: %w", err)
	}
	return signed, nil
}
