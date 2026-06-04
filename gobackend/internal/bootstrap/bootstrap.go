// Package bootstrap provides the create-admin one-shot command that provisions
// a platform admin user. It mirrors backend/src/cli/create_admin.py faithfully:
//
//   - email is lowercased before lookup/insert (Python's email.lower())
//   - display_name = email.split("@")[0]  (Python's default)
//   - platform_role = "admin"
//   - email_verified_at = now()
//   - tenant_id = NULL, tenant_role = NULL
//   - if the email already exists the command exits with an error (no upsert)
//   - password is hashed with bcrypt cost 12 via auth.HashPassword (passlib-compatible)
//
// TOTP: no TOTP is enrolled here. The freshly created admin has totp_enabled_at=NULL
// so the auth login flow's totp_enrol path will prompt the admin to set up TOTP
// on first login (require_admin checks totp_enabled_at in the policy validator).
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// ErrEmailTaken is returned by CreateAdmin when the email already exists.
// Mirrors Python's auth.EmailTaken.
var ErrEmailTaken = errors.New("email already in use")

// Result holds the created user's ID and email for the caller to display.
type Result struct {
	ID    int64
	Email string
}

// CreateAdmin provisions a platform admin user. It is idempotent in the sense
// that it returns ErrEmailTaken (instead of creating a duplicate) if the email
// already exists — matching Python's create_admin behaviour exactly (no upsert).
//
// Parameters:
//
//	st       — an open *store.Store (schema must already be present)
//	email    — admin email address (will be lowercased)
//	password — plaintext password (will be bcrypt-hashed)
func CreateAdmin(ctx context.Context, st *store.Store, email, password string) (*Result, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, fmt.Errorf("email must not be empty")
	}
	if password == "" {
		return nil, fmt.Errorf("password must not be empty")
	}

	// Check if email is already taken (mirrors Python's get_by_email check
	// before raising EmailTaken).
	_, err := st.GetUserByEmail(ctx, email)
	if err == nil {
		// User found — email already exists.
		return nil, ErrEmailTaken
	}
	var nf *store.NotFoundError
	if !errors.As(err, &nf) {
		return nil, fmt.Errorf("lookup user by email: %w", err)
	}
	// ErrNoRows → proceed with creation.

	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// display_name = email.split("@")[0]  (Python's default)
	displayName := email
	if at := strings.Index(email, "@"); at > 0 {
		displayName = email[:at]
	}

	now := time.Now().UTC()

	u := &store.User{
		Email:           email,
		DisplayName:     displayName,
		PasswordHash:    &hash,
		PlatformRole:    "admin",
		TenantID:        nil, // admins have no tenant
		TenantRole:      nil,
		EmailVerifiedAt: &now,
		// TotpSecret/TotpEnabledAt intentionally nil — admin enrolls on first login.
	}

	created, err := st.CreateUser(ctx, u)
	if err != nil {
		var ce *store.ConflictError
		if errors.As(err, &ce) {
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	return &Result{ID: created.ID, Email: created.Email}, nil
}
