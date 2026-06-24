package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// contentETag is the localFS version hash (s3 uses the S3 ETag instead).
func contentETag(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func marshalManifest(m Manifest) ([]byte, error) {
	if m.Entries == nil {
		m.Entries = map[string]Entry{}
	}
	return json.MarshalIndent(m, "", "  ")
}

func unmarshalManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, err
	}
	if m.Entries == nil {
		m.Entries = map[string]Entry{}
	}
	return m, nil
}

func defaultMode(sensitive bool) uint32 {
	if sensitive {
		return 0o600
	}
	return 0o644
}

// NewManifest returns an empty manifest for a scope (cold start).
func NewManifest(scope string) Manifest {
	return Manifest{Entries: map[string]Entry{}, Scope: scope}
}
