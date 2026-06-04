//go:build integration

package bootstrap_test

// bootstrap_test.go — integration tests for CreateAdmin.
//
// Uses dockertest + the real Go migrator so the schema matches production.
// Run: go test -tags integration ./internal/bootstrap/ -v

import (
	"context"
	"fmt"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/bootstrap"
	"github.com/zwarder/waf/gobackend/internal/migrate"
	"github.com/zwarder/waf/gobackend/internal/store"
	"log/slog"
)

// newTestStore spins up a fresh Postgres container, runs the Go migrator, and
// returns a connected *store.Store + cleanup.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err, "connect to Docker")

	res, err := pool.Run("postgres", "16", []string{
		"POSTGRES_PASSWORD=pw",
		"POSTGRES_DB=waf",
	})
	require.NoError(t, err, "start postgres container")
	t.Cleanup(func() { _ = pool.Purge(res) })

	dsn := fmt.Sprintf("postgres://postgres:pw@localhost:%s/waf?sslmode=disable",
		res.GetPort("5432/tcp"))

	var st *store.Store
	require.NoError(t, pool.Retry(func() error {
		s, e := store.New(context.Background(), dsn)
		if e != nil {
			return e
		}
		if e = s.Ping(context.Background()); e != nil {
			return e
		}
		st = s
		return nil
	}), "wait for postgres")
	t.Cleanup(st.Close)

	logger := slog.Default()
	require.NoError(t, migrate.Run(dsn, logger), "run migrations")

	return st
}

// TestCreateAdmin_NewEmail verifies the happy path:
//   - user row created with platform_role="admin", email_verified_at set,
//     tenant_id/tenant_role nil, password verifiable.
func TestCreateAdmin_NewEmail(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	res, err := bootstrap.CreateAdmin(ctx, st, "admin@example.com", "s3cr3tP@ss")
	require.NoError(t, err)
	assert.Greater(t, res.ID, int64(0))
	assert.Equal(t, "admin@example.com", res.Email)

	// Verify the DB row.
	u, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	assert.Equal(t, "admin", u.PlatformRole)
	assert.NotNil(t, u.EmailVerifiedAt, "email_verified_at must be set")
	assert.Nil(t, u.TenantID, "admins have no tenant_id")
	assert.Nil(t, u.TenantRole, "admins have no tenant_role")
	assert.Nil(t, u.TotpEnabledAt, "TOTP not enrolled at creation")
	assert.Equal(t, "admin", u.DisplayName, "display_name = email.split('@')[0]")

	require.NotNil(t, u.PasswordHash, "password_hash must be set")
	assert.True(t, auth.VerifyPassword("s3cr3tP@ss", *u.PasswordHash),
		"VerifyPassword must succeed with the original plaintext")
}

// TestCreateAdmin_EmailCasing verifies that emails are lowercased (Python compat).
func TestCreateAdmin_EmailCasing(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	_, err := bootstrap.CreateAdmin(ctx, st, "Admin@EXAMPLE.COM", "pw1234")
	require.NoError(t, err)

	u, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	assert.Equal(t, "admin@example.com", u.Email)
}

// TestCreateAdmin_DuplicateEmail verifies that a second call for the same email
// returns ErrEmailTaken (no upsert — faithful to Python's EmailTaken behaviour).
func TestCreateAdmin_DuplicateEmail(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	_, err := bootstrap.CreateAdmin(ctx, st, "dup@example.com", "firstPassword")
	require.NoError(t, err)

	_, err = bootstrap.CreateAdmin(ctx, st, "dup@example.com", "differentPassword")
	require.ErrorIs(t, err, bootstrap.ErrEmailTaken,
		"second call for the same email must return ErrEmailTaken")

	// The original password must still be valid (no update occurred).
	u, err := st.GetUserByEmail(ctx, "dup@example.com")
	require.NoError(t, err)
	require.NotNil(t, u.PasswordHash)
	assert.True(t, auth.VerifyPassword("firstPassword", *u.PasswordHash),
		"original password must still be valid after failed second call")
	assert.False(t, auth.VerifyPassword("differentPassword", *u.PasswordHash),
		"new password must NOT have been stored")
}
