package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasetoKeyFromEnvHex(t *testing.T) {
	hexKey := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	t.Setenv("WAF_PASETO_KEY", hexKey)
	t.Setenv("WAF_POSTGRES_DSN", "postgres://x")

	cfg, err := Load()
	require.NoError(t, err)
	require.Len(t, cfg.PasetoKey, 32)
	require.Equal(t, byte(0x00), cfg.PasetoKey[0])
	require.Equal(t, byte(0xff), cfg.PasetoKey[31])
}

func TestPasetoKeyBadHexFails(t *testing.T) {
	t.Setenv("WAF_PASETO_KEY", "nothex")
	t.Setenv("WAF_POSTGRES_DSN", "postgres://x")
	_, err := Load()
	require.Error(t, err)
}

func TestPasetoKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, ".paseto_key")
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	require.NoError(t, os.WriteFile(keyPath, raw, 0o600))

	os.Unsetenv("WAF_PASETO_KEY")
	t.Setenv("WAF_PASETO_KEY_FILE", keyPath)
	t.Setenv("WAF_POSTGRES_DSN", "postgres://x")

	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, raw, cfg.PasetoKey)
}
