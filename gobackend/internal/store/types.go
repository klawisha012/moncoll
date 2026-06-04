// Package store provides access to the Postgres tables owned by the Python
// backend. The Go service reads and writes rows; alembic owns schema migrations.
package store

import (
	"context"
	"time"
)

// User mirrors the columns of the users table that the auth gate needs.
type User struct {
	ID              int64
	PlatformRole    string
	EmailVerifiedAt *time.Time
	TotpEnabledAt   *time.Time
	TenantID        *int64
}

// Tenant mirrors the columns of the tenants table the auth gate needs.
type Tenant struct {
	ID          int64
	Name        string
	SuspendedAt *time.Time
}

// Reader is the read-only surface the auth policy depends on. Implemented by
// the pgx store and by fakes in tests.
type Reader interface {
	GetUserByID(ctx context.Context, id int64) (*User, error)
	GetTenantByID(ctx context.Context, id int64) (*Tenant, error)
}

// Connection mirrors all columns of the connections table.
//
// The struct is shared across the crowdsec sync (needs ID/TenantID/Name/Domain/
// Enabled/Status), the connections service (needs the full set), and the
// background poller (needs all columns). All fields are populated by the full
// SELECT helpers; the lean ListConnections query populates only the six fields
// the crowdsec sync actually reads.
//
// OriginHosts is stored as a JSON array in Postgres and decoded into []string.
// GeoipDeniedCountries is likewise a JSON array decoded into []string.
type Connection struct {
	// Core identity — used by crowdsec sync, dashboard, certs.
	ID       int64
	TenantID int64
	Name     string
	Domain   string // lowercase IDNA-normalised, UNIQUE across table
	Enabled  bool
	Status   string

	// Full column set (populated by GetConnectionFull / GetConnectionInternal /
	// ListConnectionsForPoll and the create/update returning queries).
	OriginHosts          []string   // JSON array: list of origin IP/host strings
	OriginPort           int        // default 443
	OriginTLSMode        string     // "strict" | "lenient"
	VerifyToken          string     // random URL-safe token, 32 chars
	VerifiedAt           *time.Time // set when TXT record confirmed
	StatusDetail         *string    // human-readable note, nullable
	AcmeRetryCount       int
	AcmeNextRetryAt      *time.Time
	NextPollAt           *time.Time
	DNSTTLSeconds        int    // default 60
	LastCheckedAt        *time.Time
	HTTPVersions         string // default "h1,h2"
	CompressionAlgo      string // default "auto"
	ModsecState          string // "off" | "detection_only" | "blocking"
	GeoipDeniedCountries []string   // JSON array: ISO 3166-1 alpha-2 country codes
	CrowdsecActive       bool
	SSLCertPath          *string // populated once status=active
	SSLKeyPath           *string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// ConnectionUpdate carries the mutable fields that update_connection in
// service.py may patch. All fields are pointers so callers can set only those
// they want changed (partial-update pattern).
type ConnectionUpdate struct {
	Name            *string
	OriginHosts     []string // nil = leave unchanged; non-nil (including empty) = overwrite
	OriginPort      *int
	OriginTLSMode   *string
	HTTPVersions    *string
	CompressionAlgo *string
	Enabled         *bool
}

// NotFoundError is returned when a row does not exist or is owned by a
// different tenant (the caller cannot distinguish the two cases by design —
// leaking existence to another tenant is a security issue).
type NotFoundError struct{ Entity string }

func (e *NotFoundError) Error() string { return e.Entity + " not found" }

// ConflictError is returned when an INSERT violates a UNIQUE constraint (e.g.
// duplicate domain). The caller maps it to HTTP 409.
type ConflictError struct{ Detail string }

func (e *ConflictError) Error() string { return "conflict: " + e.Detail }
