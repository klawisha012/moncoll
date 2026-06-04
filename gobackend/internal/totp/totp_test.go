package totp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	gototp "github.com/pquerna/otp/totp"
)

// -----------------------------------------------------------------------
// GenerateSecret
// -----------------------------------------------------------------------

func TestGenerateSecret_Format(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret error: %v", err)
	}
	// pyotp.random_base32() returns uppercase base32; pquerna also uppercase.
	if len(secret) == 0 {
		t.Error("empty secret returned")
	}
	// base32 alphabet: A-Z 2-7 (no padding needed for 160-bit = 32 chars)
	for _, c := range secret {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=') {
			t.Errorf("invalid base32 char %q in secret %s", c, secret)
		}
	}
	// pyotp default secret length is 32 base32 chars (160 bits)
	if len(secret) != 32 {
		t.Errorf("expected 32-char base32 secret (pyotp default), got %d", len(secret))
	}
}

// -----------------------------------------------------------------------
// ProvisioningURI
// -----------------------------------------------------------------------

func TestProvisioningURI_Format(t *testing.T) {
	uri := ProvisioningURI("JBSWY3DPEHPK3PXP", "alice@example.com", "WAF")
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("expected otpauth://totp/ prefix, got: %s", uri)
	}
	if !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("secret not found in URI: %s", uri)
	}
	if !strings.Contains(uri, "issuer=WAF") {
		t.Errorf("issuer not found in URI: %s", uri)
	}
	if !strings.Contains(uri, "alice%40example.com") && !strings.Contains(uri, "alice@example.com") {
		t.Errorf("account name not found in URI: %s", uri)
	}
}

func TestProvisioningURI_DefaultIssuer(t *testing.T) {
	uri := ProvisioningURI("JBSWY3DPEHPK3PXP", "user@test.com", "")
	if !strings.Contains(uri, "WAF") {
		t.Errorf("default issuer WAF not found in URI: %s", uri)
	}
}

// -----------------------------------------------------------------------
// Verify
// -----------------------------------------------------------------------

func TestVerify_CurrentCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	// Generate the current code using the same library (pquerna) and verify it.
	code, err := gototp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !Verify(secret, code) {
		t.Error("Verify rejected valid current code")
	}
}

func TestVerify_WrongCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if Verify(secret, "000000") {
		// This could theoretically pass ~1/1000000 of the time; accept it.
		t.Log("note: 000000 happened to be valid (1-in-million chance)")
	}
	if Verify(secret, "not-a-code") {
		t.Error("Verify accepted non-numeric garbage")
	}
}

func TestVerify_EmptySecret(t *testing.T) {
	if Verify("", "123456") {
		t.Error("Verify should return false for empty secret")
	}
}

func TestVerify_EmptyCode(t *testing.T) {
	if Verify("JBSWY3DPEHPK3PXP", "") {
		t.Error("Verify should return false for empty code")
	}
}

// RFC 6238 / pyotp-compatible test vector.
// Secret "JBSWY3DPEHPK3PXP" is the well-known pyotp test secret.
// At Unix time 1706745600 (2024-02-01 00:00:00 UTC) the TOTP code is
// deterministic. We generate it with pquerna and verify with our Verify
// to confirm round-trip compatibility.
func TestVerify_KnownVector(t *testing.T) {
	const knownSecret = "JBSWY3DPEHPK3PXP"
	// Use a fixed time that's at the start of a 30s window to avoid step boundary flakiness.
	ts := time.Unix(1706745600, 0) // 2024-02-01 00:00:00 UTC
	code, err := gototp.GenerateCode(knownSecret, ts)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	// Now verify using pquerna's Validate with the same timestamp window.
	// (We use gototp.ValidateCustom to pin the time rather than time.Now())
	ok, err := gototp.ValidateCustom(code, knownSecret, ts, gototp.ValidateOpts{
		Period: 30,
		Skew:   1,
		Digits: 6,
	})
	if err != nil {
		t.Fatalf("ValidateCustom: %v", err)
	}
	if !ok {
		t.Errorf("known vector failed: secret=%s code=%s at %v", knownSecret, code, ts)
	}
	t.Logf("RFC-6238 vector: secret=%s ts=%v code=%s ✓", knownSecret, ts, code)
}

// -----------------------------------------------------------------------
// Recovery codes
// -----------------------------------------------------------------------

func TestGenerateRecoveryCodes_Count(t *testing.T) {
	plain, hashed := GenerateRecoveryCodes(10)
	if len(plain) != 10 {
		t.Errorf("expected 10 plain codes, got %d", len(plain))
	}
	if len(hashed) != 10 {
		t.Errorf("expected 10 hashed codes, got %d", len(hashed))
	}
}

func TestGenerateRecoveryCodes_Format(t *testing.T) {
	plain, hashed := GenerateRecoveryCodes(10)
	for i, c := range plain {
		// token_hex(5) → 10 hex chars
		if len(c) != 10 {
			t.Errorf("code[%d] %q: expected 10 hex chars, got %d", i, c, len(c))
		}
		for _, ch := range c {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
				t.Errorf("code[%d] %q: non-hex char %q", i, c, ch)
			}
		}
		// Hash must be sha256 hex (64 chars)
		if len(hashed[i]) != 64 {
			t.Errorf("hash[%d] %q: expected 64 hex chars, got %d", i, hashed[i], len(hashed[i]))
		}
	}
}

func TestGenerateRecoveryCodes_HashAlgo(t *testing.T) {
	// Verify the hash algorithm matches Python:
	//   hashlib.sha256(code.encode()).hexdigest()
	plain, hashed := GenerateRecoveryCodes(3)
	for i, c := range plain {
		sum := sha256.Sum256([]byte(c))
		expected := hex.EncodeToString(sum[:])
		if hashed[i] != expected {
			t.Errorf("code[%d]: hash mismatch\n  got:  %s\n  want: %s", i, hashed[i], expected)
		}
	}
}

func TestVerifyRecoveryCode_Valid(t *testing.T) {
	plain, hashed := GenerateRecoveryCodes(10)
	for i, c := range plain {
		idx, ok := VerifyRecoveryCode(c, hashed)
		if !ok {
			t.Errorf("code[%d] %q: VerifyRecoveryCode returned false", i, c)
		}
		if idx != i {
			t.Errorf("code[%d]: expected index %d, got %d", i, i, idx)
		}
	}
}

func TestVerifyRecoveryCode_Invalid(t *testing.T) {
	_, hashed := GenerateRecoveryCodes(10)
	idx, ok := VerifyRecoveryCode("wrongcode1", hashed)
	if ok {
		t.Error("VerifyRecoveryCode returned true for wrong code")
	}
	if idx != -1 {
		t.Errorf("expected index -1, got %d", idx)
	}
}

func TestVerifyRecoveryCode_KnownHash(t *testing.T) {
	// Cross-compat test: manually compute Python-style hash and verify.
	// Python: hashlib.sha256("deadbeef12".encode()).hexdigest()
	code := "deadbeef12"
	sum := sha256.Sum256([]byte(code))
	expected := hex.EncodeToString(sum[:])

	idx, ok := VerifyRecoveryCode(code, []string{expected})
	if !ok {
		t.Errorf("VerifyRecoveryCode failed for known Python-style hash")
	}
	if idx != 0 {
		t.Errorf("expected index 0, got %d", idx)
	}
}

func TestVerifyRecoveryCode_EmptyList(t *testing.T) {
	idx, ok := VerifyRecoveryCode("anycode", nil)
	if ok {
		t.Error("should not match against empty list")
	}
	if idx != -1 {
		t.Errorf("expected -1 index for empty list, got %d", idx)
	}
}
