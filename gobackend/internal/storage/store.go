// Package storage is the shared source-of-truth seam for WAF file state
// (per-tenant Angie config, TLS material, ban/registry artefacts). It has two
// backends — localFS (single-node, default, current behaviour) and s3 (shared,
// enables horizontal scaling). See specs/001-horizontal-scaling/contracts/.
package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

// ManifestKey is the object key of the generation manifest — the single atomic
// commit point for a change set (FR-004).
const ManifestKey = "state/manifest.json"

var (
	// ErrNotFound is returned by Get/Stat when the object is absent.
	ErrNotFound = errors.New("storage: object not found")
	// ErrConflict is returned by PublishManifest when ifMatchETag no longer
	// matches the current manifest (a concurrent publisher won the race).
	ErrConflict = errors.New("storage: manifest etag mismatch (concurrent publish)")
)

// ObjectInfo carries metadata about a stored object.
type ObjectInfo struct {
	Key       string
	ETag      string // version hash; set by the backend
	Size      int64
	Mode      uint32 // perms for edge materialisation (0644 config, 0600 key)
	Sensitive bool   // TLS key / credential: SSE at rest + 0600 locally (FR-010)
	ModTime   time.Time
}

// PutOptions controls a write.
type PutOptions struct {
	Mode      uint32 // 0 → derived from Sensitive
	Sensitive bool
}

// Entry is a manifest record for one object.
type Entry struct {
	ETag      string `json:"etag"`
	Size      int64  `json:"size"`
	Mode      uint32 `json:"mode"`
	Sensitive bool   `json:"sensitive"`
}

// Manifest is the atomic snapshot of active state. Published LAST in a change
// set; the edge sidecar only commits a fully-downloaded generation (FR-004).
type Manifest struct {
	Generation       int64            `json:"generation"`
	PublishedAt      time.Time        `json:"published_at"`
	Entries          map[string]Entry `json:"entries"` // key → meta
	SuspendedTenants []int64          `json:"suspended_tenants"`
	Scope            string           `json:"scope"` // single-region "default" in v1
}

// Store is the source of truth for file state. Implementations: localFS, s3.
type Store interface {
	Put(ctx context.Context, key string, r io.Reader, opts PutOptions) (ObjectInfo, error)
	Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)
	Stat(ctx context.Context, key string) (ObjectInfo, error)

	// ReadManifest returns the current manifest plus its etag (for CAS). A
	// missing manifest yields an empty manifest and "" etag (cold start).
	ReadManifest(ctx context.Context) (Manifest, string, error)
	// PublishManifest atomically swaps the manifest. ifMatchETag must equal the
	// etag from the ReadManifest the caller built on; otherwise ErrConflict.
	PublishManifest(ctx context.Context, m Manifest, ifMatchETag string) (newETag string, err error)
}
