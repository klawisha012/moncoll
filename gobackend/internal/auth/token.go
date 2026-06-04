package auth

import (
	"encoding/json"
	"errors"
	"time"

	"aidanwoods.dev/go-paseto"
)

// ErrInvalidToken is returned for any decrypt/parse/expiry failure, matching
// decode_session_token returning None for all failure modes.
var ErrInvalidToken = errors.New("invalid or expired session")

// Claims mirrors the payload minted by create_session_token. exp/iat are float
// Unix seconds (NOT RFC3339).
type Claims struct {
	Sub          string  `json:"sub"`
	PlatformRole string  `json:"pr"`
	TenantID     *int64  `json:"tn"`
	TenantRole   *string `json:"tr"`
	Iat          float64 `json:"iat"`
	Exp          float64 `json:"exp"`
}

// Decoder decrypts PASETO v4.local tokens minted by the Python backend.
type Decoder struct {
	key paseto.V4SymmetricKey
}

// NewDecoder constructs a Decoder from a raw 32-byte symmetric key.
// Panics if key is not exactly 32 bytes — length is validated in config.Load.
func NewDecoder(rawKey []byte) *Decoder {
	k, err := paseto.V4SymmetricKeyFromBytes(rawKey)
	if err != nil {
		panic("auth: invalid PASETO key length")
	}
	return &Decoder{key: k}
}

// Decode decrypts a v4.local token and returns its claims. We do NOT use the
// rule engine (it expects RFC3339 exp); we read raw claim bytes and check exp
// as a float, exactly like the Python path.
func (d *Decoder) Decode(token string) (*Claims, error) {
	// NewParserWithoutExpiryCheck returns a Parser with no rules — critical
	// because go-paseto's NotExpired rule expects RFC3339 strings, but the
	// Python backend stores exp as a float Unix timestamp.
	parser := paseto.NewParserWithoutExpiryCheck()
	parsed, err := parser.ParseV4Local(d.key, token, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// ClaimsJSON re-marshals the internal map[string]json.RawMessage; float
	// values survive the round-trip as JSON numbers.
	var c Claims
	if err := json.Unmarshal(parsed.ClaimsJSON(), &c); err != nil {
		return nil, ErrInvalidToken
	}

	if c.Exp <= float64(time.Now().Unix()) {
		return nil, ErrInvalidToken
	}

	return &c, nil
}
