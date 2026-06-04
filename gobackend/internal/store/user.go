package store

// user.go — CreateUser, GetUserByEmail, UpdateUser
// Mirrors the Python auth service (service.py) faithfully.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// userFullColumns is the column list shared by CreateUser (RETURNING) and
// GetUserByEmail.  Order must match userFullScan.
//
// NOTE: GetUserByID intentionally selects only 5 columns; adding columns
// here does NOT break it.
const userFullColumns = `
	id, email, display_name, password_hash, platform_role,
	tenant_id, tenant_role, email_verified_at,
	totp_secret, totp_enabled_at, recovery_codes_hash,
	last_login_at, created_at, updated_at`

// userFullScan scans a full user row into *User.
func userFullScan(row pgx.Row, u *User) error {
	return row.Scan(
		&u.ID,
		&u.Email,
		&u.DisplayName,
		&u.PasswordHash,
		&u.PlatformRole,
		&u.TenantID,
		&u.TenantRole,
		&u.EmailVerifiedAt,
		&u.TotpSecret,
		&u.TotpEnabledAt,
		&u.RecoveryCodesHash,
		&u.LastLoginAt,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
}

// CreateUser inserts a new user row and returns the full row (all columns).
// The Email field is expected to already be lowercase (mirror of service.py
// which calls email.lower() before passing to the ORM).
// Returns *ConflictError if the email is already taken (unique constraint).
func (s *Store) CreateUser(ctx context.Context, u *User) (*User, error) {
	const q = `
		INSERT INTO users (
			email, display_name, password_hash, platform_role,
			tenant_id, tenant_role, email_verified_at,
			totp_secret, totp_enabled_at, recovery_codes_hash,
			last_login_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING ` + userFullColumns

	out := &User{}
	err := userFullScan(
		s.pool.QueryRow(ctx, q,
			u.Email,
			u.DisplayName,
			u.PasswordHash,
			u.PlatformRole,
			u.TenantID,
			u.TenantRole,
			u.EmailVerifiedAt,
			u.TotpSecret,
			u.TotpEnabledAt,
			u.RecoveryCodesHash,
			u.LastLoginAt,
		),
		out,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, &ConflictError{Detail: "email already taken"}
		}
		return nil, fmt.Errorf("CreateUser: %w", err)
	}
	return out, nil
}

// GetUserByEmail returns the full user row for the given email (lowercased
// before the query, matching Python's get_by_email).
// Returns *NotFoundError when no row exists.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	const q = `SELECT ` + userFullColumns + ` FROM users WHERE email = $1`

	u := &User{}
	err := userFullScan(s.pool.QueryRow(ctx, q, strings.ToLower(email)), u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "user"}
	}
	if err != nil {
		return nil, fmt.Errorf("GetUserByEmail: %w", err)
	}
	return u, nil
}

// GetUserByIDFull returns the full user row (all columns) for the given id.
// Unlike GetUserByID (which selects only the 5 auth-gate columns), this
// populates Email/DisplayName/TenantRole/TotpSecret/RecoveryCodesHash so the
// auth service can build a UserPublic or read the TOTP secret. Returns
// *NotFoundError when no row exists.
func (s *Store) GetUserByIDFull(ctx context.Context, id int64) (*User, error) {
	const q = `SELECT ` + userFullColumns + ` FROM users WHERE id = $1`
	u := &User{}
	err := userFullScan(s.pool.QueryRow(ctx, q, id), u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "user"}
	}
	if err != nil {
		return nil, fmt.Errorf("GetUserByIDFull: %w", err)
	}
	return u, nil
}

// UpdateUser applies a partial patch to the user with the given id.
// Only non-nil fields in patch are written. At least one field must be
// non-nil; passing an empty patch is a no-op that returns nil.
func (s *Store) UpdateUser(ctx context.Context, id int64, patch UserUpdate) error {
	setClauses := []string{}
	args := []any{}
	idx := 1

	add := func(col string, val any) {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", col, idx))
		args = append(args, val)
		idx++
	}

	if patch.PasswordHash != nil {
		add("password_hash", *patch.PasswordHash)
	}
	if patch.EmailVerifiedAt != nil {
		add("email_verified_at", *patch.EmailVerifiedAt)
	}
	if patch.TotpSecret != nil {
		add("totp_secret", *patch.TotpSecret)
	}
	if patch.TotpEnabledAt != nil {
		add("totp_enabled_at", *patch.TotpEnabledAt)
	}
	if patch.RecoveryCodesHash != nil {
		add("recovery_codes_hash", patch.RecoveryCodesHash)
	}
	if patch.LastLoginAt != nil {
		add("last_login_at", *patch.LastLoginAt)
	}
	if patch.DisplayName != nil {
		add("display_name", *patch.DisplayName)
	}
	if patch.TenantID != nil {
		add("tenant_id", *patch.TenantID)
	}
	if patch.TenantRole != nil {
		add("tenant_role", *patch.TenantRole)
	}
	if patch.PlatformRole != nil {
		add("platform_role", *patch.PlatformRole)
	}

	if len(setClauses) == 0 {
		return nil // nothing to do
	}

	// Always bump updated_at.
	add("updated_at", time.Now().UTC())

	args = append(args, id)
	q := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d",
		strings.Join(setClauses, ", "), idx)

	ct, err := s.pool.Exec(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("UpdateUser: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return &NotFoundError{Entity: "user"}
	}
	return nil
}
