// Package store provides read-only access to the Postgres tables owned by the
// Python backend. The Go service never writes or migrates; alembic owns schema.
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
	SuspendedAt *time.Time
}

// Reader is the read-only surface the auth policy depends on. Implemented by
// the pgx store and by fakes in tests.
type Reader interface {
	GetUserByID(ctx context.Context, id int64) (*User, error)
	GetTenantByID(ctx context.Context, id int64) (*Tenant, error)
}

// NotFoundError is returned when a row does not exist.
type NotFoundError struct{ Entity string }

func (e *NotFoundError) Error() string { return e.Entity + " not found" }
