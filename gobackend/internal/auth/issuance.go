package auth

// issuance.go — PASETO v4.local session token issuance + bcrypt password
// hashing + HMAC-SHA256 short-lived signed tokens + PASETO short-lived
// encrypted tokens.  All primitives are byte-faithful to security.py so that
// tokens minted by Go are accepted by the Python decoder (and vice-versa)
// during the strangler-fig overlap period.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"aidanwoods.dev/go-paseto"
	"golang.org/x/crypto/bcrypt"
)

// defaultSessionTTL is the session lifetime when WAF_SESSION_TTL_HOURS is
// unset or invalid. 7 days keeps signed-in accounts (including the stashed
// multi-account sessions) usable across days without re-login.
const defaultSessionTTL = 7 * 24 * time.Hour

// maxSessionTTLHours caps WAF_SESSION_TTL_HOURS at one year. Far beyond that
// (~292 years) the hours→Duration conversion overflows int64 into a negative
// TTL: every minted token is born expired and the cookie Max-Age goes
// negative — a total auth outage that is hard to diagnose.
const maxSessionTTLHours = 24 * 365

// sessionTTL is resolved once at startup from WAF_SESSION_TTL_HOURS.
var sessionTTL = sessionTTLFromEnv()

func sessionTTLFromEnv() time.Duration {
	return parseSessionTTL(os.Getenv("WAF_SESSION_TTL_HOURS"))
}

// parseSessionTTL converts a WAF_SESSION_TTL_HOURS value into a Duration.
// A set-but-invalid value falls back to the default loudly: silently
// extending a security knob (operator sets "1h" expecting one hour, gets
// seven days) must leave a trace in the logs.
func parseSessionTTL(v string) time.Duration {
	if v == "" {
		return defaultSessionTTL
	}
	h, err := strconv.Atoi(v)
	if err != nil || h <= 0 || h > maxSessionTTLHours {
		slog.Warn("invalid WAF_SESSION_TTL_HOURS, using default",
			"value", v, "default", defaultSessionTTL.String(), "max_hours", maxSessionTTLHours)
		return defaultSessionTTL
	}
	return time.Duration(h) * time.Hour
}

// SessionTTL returns the configured session lifetime. Cookie Max-Age values
// must use this so the browser keeps the cookie exactly as long as the PASETO
// token inside it stays valid.
func SessionTTL() time.Duration {
	return sessionTTL
}

// bcryptCost matches passlib's default bcrypt rounds (12).
const bcryptCost = 12

// ErrInvalidShortLived is returned by VerifyShortLived / DecryptShortLived
// for any verification or expiry failure.
var ErrInvalidShortLived = errors.New("invalid or expired short-lived token")

// Issuer mints PASETO v4.local session tokens compatible with the existing
// Decoder (token.go).
type Issuer struct {
	key    paseto.V4SymmetricKey
	rawKey []byte // kept for HMAC operations (sign_short_lived)
}

// NewIssuer constructs an Issuer from a raw 32-byte symmetric key.
// Panics if key is not exactly 32 bytes — the same invariant as NewDecoder.
func NewIssuer(rawKey []byte) *Issuer {
	k, err := paseto.V4SymmetricKeyFromBytes(rawKey)
	if err != nil {
		panic("auth: invalid PASETO key length")
	}
	cp := make([]byte, len(rawKey))
	copy(cp, rawKey)
	return &Issuer{key: k, rawKey: cp}
}

// CreateSessionToken mints a v4.local PASETO token whose JSON payload is
// byte-compatible with the Python create_session_token.  iat/exp are float64
// Unix seconds (NOT RFC3339) matching pyseto's encoding.
//
//	payload = {"sub": str(user_id), "pr": platform_role, "tn": tenant_id|null,
//	           "tr": tenant_role|null, "iat": <float>, "exp": <float>, "tv": <int>}
//
// tokenVersion is the caller's current users.token_version; it is embedded as
// the "tv" claim so the auth gate can reject tokens minted before a revocation.
func (i *Issuer) CreateSessionToken(
	userID int64,
	platformRole string,
	tenantID *int64,
	tenantRole *string,
	tokenVersion int,
) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(sessionTTL)

	// Build raw JSON exactly like Python:
	//   json.dumps(payload) — no special separators, so Go's compact encoder
	//   is fine (no spaces after : or ,).
	claims := map[string]any{
		"sub": strconv.FormatInt(userID, 10),
		"pr":  platformRole,
		"tn":  tenantID,   // nil → JSON null
		"tr":  tenantRole, // nil → JSON null
		"iat": now.Unix(), // float-compatible; see note below
		"exp": exp.Unix(),
		"tv":  tokenVersion,
	}
	// Python stores iat/exp as float (datetime.timestamp() returns float).
	// We build the JSON manually to emit them as floats with a ".0" suffix so
	// the Go Decoder (which unmarshals into float64) round-trips correctly.
	// Using integer seconds is fine — json.Unmarshal into float64 preserves
	// integer JSON numbers exactly, and the Python decoder also uses
	// datetime.timestamp() → float comparisons, so integer seconds work.
	claimsJSON, err := marshalSessionClaims(
		strconv.FormatInt(userID, 10),
		platformRole,
		tenantID,
		tenantRole,
		now.Unix(),
		exp.Unix(),
		tokenVersion,
	)
	if err != nil {
		return "", fmt.Errorf("marshal session claims: %w", err)
	}

	_ = claims // used only for documentation clarity above

	tok, err := paseto.NewTokenFromClaimsJSON(claimsJSON, nil)
	if err != nil {
		return "", fmt.Errorf("build paseto token: %w", err)
	}
	return tok.V4Encrypt(i.key, nil), nil
}

// marshalSessionClaims emits the JSON payload in a form compatible with
// pyseto: iat/exp as JSON numbers (floats with .0 suffix to match Python's
// datetime.timestamp() output), tn/tr as null when nil.
func marshalSessionClaims(
	sub, pr string,
	tn *int64,
	tr *string,
	iat, exp int64,
	tv int,
) ([]byte, error) {
	type payload struct {
		Sub string  `json:"sub"`
		Pr  string  `json:"pr"`
		Tn  *int64  `json:"tn"`
		Tr  *string `json:"tr"`
		Iat float64 `json:"iat"`
		Exp float64 `json:"exp"`
		Tv  int     `json:"tv"`
	}
	return json.Marshal(payload{
		Sub: sub,
		Pr:  pr,
		Tn:  tn,
		Tr:  tr,
		Iat: float64(iat),
		Exp: float64(exp),
		Tv:  tv,
	})
}

// ---------------------------------------------------------------------------
// Password hashing (passlib bcrypt compatible)
// ---------------------------------------------------------------------------

// HashPassword hashes plain using bcrypt at cost 12 (passlib default).
// Returns a $2b$12$... string accepted by passlib.verify and VerifyPassword.
func HashPassword(plain string) (string, error) {
	// Truncate to 72 bytes to match passlib / libbcrypt behaviour.
	// x/crypto/bcrypt itself also truncates at 72 bytes but returns an error
	// for inputs > 72 bytes on some versions. Pre-truncating is the safest
	// approach for cross-compat with existing $2b$ hashes from passlib.
	b := []byte(plain)
	if len(b) > 72 {
		b = b[:72]
	}
	h, err := bcrypt.GenerateFromPassword(b, bcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// VerifyPassword returns true iff plain matches hash.  Accepts $2b$ and $2a$
// hashes produced by passlib.  Returns false (not an error) on any failure,
// matching the Python verify_password signature.
func VerifyPassword(plain, hash string) bool {
	if hash == "" {
		return false
	}
	b := []byte(plain)
	if len(b) > 72 {
		b = b[:72]
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), b)
	return err == nil
}

// ---------------------------------------------------------------------------
// Short-lived HMAC-signed tokens  (sign_short_lived / verify_short_lived)
// ---------------------------------------------------------------------------

// SignShortLived mirrors security.py sign_short_lived:
//
//	body = {**payload, "exp": now+ttl, "p": purpose}
//	raw  = json.dumps(body, separators=(",",":")).encode()
//	tag  = hmac.new(key, raw, sha256).digest()
//	return base64url(raw + tag).rstrip("=")
//
// The HMAC key is the same raw PASETO key bytes used by the Issuer.
func (i *Issuer) SignShortLived(payload map[string]any, ttl time.Duration, purpose string) (string, error) {
	body := make(map[string]any, len(payload)+2)
	for k, v := range payload {
		body[k] = v
	}
	body["exp"] = float64(time.Now().UTC().Unix()) + ttl.Seconds()
	body["p"] = purpose

	// separators=(",",":") → compact JSON with no spaces
	raw, err := marshalCompact(body)
	if err != nil {
		return "", fmt.Errorf("sign_short_lived marshal: %w", err)
	}

	mac := hmac.New(sha256.New, i.rawKey)
	mac.Write(raw)
	tag := mac.Sum(nil) // 32 bytes

	combined := append(raw, tag...) //nolint:gocritic // intentional new slice
	return base64.RawURLEncoding.EncodeToString(combined), nil
}

// VerifyShortLived mirrors security.py verify_short_lived.
// Returns the original payload (without "p" and "exp") or ErrInvalidShortLived.
func (i *Issuer) VerifyShortLived(value, purpose string) (map[string]any, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrInvalidShortLived
	}
	if len(decoded) < 32 {
		return nil, ErrInvalidShortLived
	}

	raw := decoded[:len(decoded)-32]
	tag := decoded[len(decoded)-32:]

	mac := hmac.New(sha256.New, i.rawKey)
	mac.Write(raw)
	expected := mac.Sum(nil)

	if !hmac.Equal(tag, expected) {
		return nil, ErrInvalidShortLived
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, ErrInvalidShortLived
	}

	if body["p"] != purpose {
		return nil, ErrInvalidShortLived
	}

	exp, ok := body["exp"].(float64)
	if !ok || exp < float64(time.Now().UTC().Unix()) {
		return nil, ErrInvalidShortLived
	}

	delete(body, "p")
	delete(body, "exp")
	return body, nil
}

// ---------------------------------------------------------------------------
// Short-lived PASETO-encrypted tokens (encrypt_short_lived / decrypt_short_lived)
// ---------------------------------------------------------------------------

// EncryptShortLived mirrors security.py encrypt_short_lived:
//
//	body = {**payload, "exp": now+ttl, "p": purpose}
//	return pyseto.encode(key, json.dumps(body).encode())
func (i *Issuer) EncryptShortLived(payload map[string]any, ttl time.Duration, purpose string) (string, error) {
	body := make(map[string]any, len(payload)+2)
	for k, v := range payload {
		body[k] = v
	}
	body["exp"] = float64(time.Now().UTC().Unix()) + ttl.Seconds()
	body["p"] = purpose

	// Python uses json.dumps(body) (no special separators — default includes
	// spaces after separators in older Python, but in Python 3.x json.dumps
	// with no args uses compact=False which puts ", " and ": ". However
	// pyseto just sends the bytes as the payload; the decryptor re-parses the
	// JSON. So the exact spacing doesn't matter for encrypted tokens —
	// compact JSON is fine.
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encrypt_short_lived marshal: %w", err)
	}

	tok, err := paseto.NewTokenFromClaimsJSON(raw, nil)
	if err != nil {
		return "", fmt.Errorf("encrypt_short_lived build token: %w", err)
	}
	return tok.V4Encrypt(i.key, nil), nil
}

// DecryptShortLived mirrors security.py decrypt_short_lived.
// Returns the original payload (without "p" and "exp") or ErrInvalidShortLived.
func (i *Issuer) DecryptShortLived(token, purpose string) (map[string]any, error) {
	parser := paseto.NewParserWithoutExpiryCheck()
	parsed, err := parser.ParseV4Local(i.key, token, nil)
	if err != nil {
		return nil, ErrInvalidShortLived
	}

	var body map[string]any
	if err := json.Unmarshal(parsed.ClaimsJSON(), &body); err != nil {
		return nil, ErrInvalidShortLived
	}

	if body["p"] != purpose {
		return nil, ErrInvalidShortLived
	}

	exp, ok := body["exp"].(float64)
	if !ok || exp < float64(time.Now().UTC().Unix()) {
		return nil, ErrInvalidShortLived
	}

	delete(body, "p")
	delete(body, "exp")
	return body, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// marshalCompact produces compact JSON (no spaces) equivalent to Python's
// json.dumps(body, separators=(",",":")).
// Go's json.Marshal already produces compact JSON.
func marshalCompact(v any) ([]byte, error) {
	return json.Marshal(v)
}
