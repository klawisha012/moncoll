package auth

// fernet.go — Fernet symmetric encryption of the TOTP secret, byte-faithful to
// backend/src/auth/totp.py:
//
//	def _get_fernet() -> Fernet:
//	    key_bytes = _load_or_create_paseto_key()          # 32 raw bytes
//	    fernet_key = base64.urlsafe_b64encode(key_bytes)  # 44-char b64url string
//	    return Fernet(fernet_key)
//
// Python's cryptography.Fernet takes a base64url-encoded 32-byte key and splits
// it internally into a 16-byte signing key + 16-byte encryption key. The
// fernet-go library models the same: a fernet.Key is the raw 32 bytes, and
// DecodeKey() base64url-decodes the key string. Constructing the Key directly
// from the 32-byte PASETO key is therefore equivalent to Python's
// Fernet(urlsafe_b64encode(paseto_key)).
//
// A secret Fernet-encrypted by Python decrypts here and vice-versa as long as
// both processes share the same PASETO key file / WAF_PASETO_KEY.

import (
	"errors"
	"time"

	"github.com/fernet/fernet-go"
)

// fernetNoExpiry mirrors Python Fernet.decrypt() with no ttl argument, which
// performs NO timestamp expiry check. fernet-go always checks the TTL, so we
// pass an effectively-infinite window. (100 years.)
const fernetNoExpiry = 100 * 365 * 24 * time.Hour

// ErrFernetDecrypt is returned when a Fernet token fails authentication/decrypt.
var ErrFernetDecrypt = errors.New("fernet: decrypt failed")

// fernetKeyFromPaseto builds a *fernet.Key from the raw 32-byte PASETO key.
// Equivalent to Python's Fernet(base64.urlsafe_b64encode(paseto_key)): the
// fernet.Key is exactly those 32 bytes (16 signing + 16 encryption).
func fernetKeyFromPaseto(rawKey []byte) (*fernet.Key, error) {
	if len(rawKey) != 32 {
		return nil, errors.New("fernet: PASETO key must be 32 bytes")
	}
	var k fernet.Key
	copy(k[:], rawKey)
	return &k, nil
}

// FernetEncrypt encrypts plaintext with the Fernet key derived from the 32-byte
// PASETO key. Returns the URL-safe base64 Fernet token as a string, matching
// totp.py encrypt_secret (f.encrypt(plain.encode()).decode()).
func FernetEncrypt(pasetoKey []byte, plaintext string) (string, error) {
	k, err := fernetKeyFromPaseto(pasetoKey)
	if err != nil {
		return "", err
	}
	tok, err := fernet.EncryptAndSign([]byte(plaintext), k)
	if err != nil {
		return "", err
	}
	return string(tok), nil
}

// FernetDecrypt decrypts a Fernet token produced by FernetEncrypt or Python's
// encrypt_secret. Returns ErrFernetDecrypt on any authentication/format error,
// matching the try/except in totp.py decrypt_secret (which falls back to the
// raw value — that fallback is the caller's responsibility, see service.go).
func FernetDecrypt(pasetoKey []byte, token string) (string, error) {
	k, err := fernetKeyFromPaseto(pasetoKey)
	if err != nil {
		return "", err
	}
	msg := fernet.VerifyAndDecrypt([]byte(token), fernetNoExpiry, []*fernet.Key{k})
	if msg == nil {
		return "", ErrFernetDecrypt
	}
	return string(msg), nil
}
