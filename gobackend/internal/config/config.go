// Package config loads runtime settings from WAF_* environment variables,
// mirroring backend/src/config.py + auth/security.py for the Go service.
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

// defaultKeyFile matches PASETO_KEY_FILE in backend/src/auth/security.py.
const defaultKeyFile = "/var/lib/angie/data/.paseto_key"

type Config struct {
	PasetoKey   []byte // 32 raw bytes
	PostgresDSN string
	GRPCAddr    string // host:port for the gateway/REST listener
	MetricsAddr string // host:port for /metrics
	Timeouts    Timeouts
	Storage     StorageConfig
}

// StorageConfig selects the source-of-truth backend (FR-001). Default "local"
// preserves single-node behaviour byte-for-byte; "s3" enables the shared store
// for horizontal scaling. See specs/001-horizontal-scaling/.
type StorageConfig struct {
	Backend          string // "local" (default) | "s3"
	S3Endpoint       string
	S3Bucket         string
	S3AccessKey      string
	S3SecretKey      string
	S3Region         string
	S3UseTLS         bool
	EdgeSyncInterval int // seconds; edge sidecar poll (default 10) → ≤30s converge (FR-003)
}

func loadStorage() StorageConfig {
	return StorageConfig{
		Backend:          getenv("WAF_STORAGE_BACKEND", "local"),
		S3Endpoint:       os.Getenv("WAF_S3_ENDPOINT"),
		S3Bucket:         getenv("WAF_S3_BUCKET", "waf-state"),
		S3AccessKey:      os.Getenv("WAF_S3_ACCESS_KEY"),
		S3SecretKey:      os.Getenv("WAF_S3_SECRET_KEY"),
		S3Region:         os.Getenv("WAF_S3_REGION"),
		S3UseTLS:         getenv("WAF_S3_USE_TLS", "false") == "true",
		EdgeSyncInterval: getenvInt("WAF_EDGE_SYNC_INTERVAL", 10),
	}
}

func Load() (*Config, error) {
	key, err := loadPasetoKey()
	if err != nil {
		return nil, err
	}
	dsn := os.Getenv("WAF_POSTGRES_DSN")
	if dsn == "" {
		return nil, fmt.Errorf("WAF_POSTGRES_DSN is required")
	}
	cfg := &Config{
		PasetoKey:   key,
		PostgresDSN: dsn,
		GRPCAddr:    getenv("WAF_GO_HTTP_ADDR", ":8080"),
		MetricsAddr: getenv("WAF_GO_METRICS_ADDR", ":9100"),
		Timeouts:    LoadTimeouts(),
		Storage:     loadStorage(),
	}
	return cfg, nil
}

// loadPasetoKey reproduces _load_or_create_paseto_key: WAF_PASETO_KEY (64 hex)
// wins; otherwise read the key file. The Go service NEVER generates a key —
// Python owns key creation. We fail if neither source yields 32 bytes.
func loadPasetoKey() ([]byte, error) {
	if env := os.Getenv("WAF_PASETO_KEY"); env != "" {
		if len(env) != 64 {
			return nil, fmt.Errorf("WAF_PASETO_KEY must be 64 hex chars, got %d", len(env))
		}
		raw, err := hex.DecodeString(env)
		if err != nil {
			return nil, fmt.Errorf("WAF_PASETO_KEY is not valid hex: %w", err)
		}
		return raw, nil
	}
	path := getenv("WAF_PASETO_KEY_FILE", defaultKeyFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot read PASETO key file %s (%w); set WAF_PASETO_KEY (64 hex chars) in the environment to share the Python backend's session key",
			path, err,
		)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("PASETO key file %s must contain 32 bytes, got %d", path, len(raw))
	}
	return raw, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
