//go:build integration

package store

// auth_store_test.go — integration tests for the auth-related store methods:
// CreateUser, GetUserByEmail, UpdateUser, email verification CRUD, OAuth CRUD.
//
// Uses dockertest + the Go migrator (migrate.Run) for schema creation.
// Run: go test -tags integration ./internal/store/ -run 'TestUser|TestEmailVerification|TestOAuth' -v

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zwarder/waf/gobackend/internal/migrate"
)

// authTestStore spins up a fresh Postgres container, runs the real Go
// migrator, and returns a connected Store + cleanup func.
func authTestStore(t *testing.T) *Store {
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

	var st *Store
	require.NoError(t, pool.Retry(func() error {
		s, e := New(context.Background(), dsn)
		if e != nil {
			return e
		}
		if e = s.pool.Ping(context.Background()); e != nil {
			return e
		}
		st = s
		return nil
	}), "wait for postgres")
	t.Cleanup(st.Close)

	// Use the real migrator so the test schema exactly matches production.
	logger := slog.Default()
	require.NoError(t, migrate.Run(dsn, logger), "run migrations")

	return st
}

// seedTenant inserts a minimal tenant row required by the users FK and returns
// its id.
func seedTenant(t *testing.T, st *Store) int64 {
	t.Helper()
	var id int64
	err := st.pool.QueryRow(context.Background(),
		`INSERT INTO tenants (name, display_name) VALUES ($1, $2) RETURNING id`,
		"acme", "Acme Corp",
	).Scan(&id)
	require.NoError(t, err)
	return id
}

// ---------------------------------------------------------------------------
// User tests
// ---------------------------------------------------------------------------

func TestUserCreateAndGetByEmail(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	tid := seedTenant(t, st)
	role := "owner"
	hash := "$2b$12$fakehashfakehashfakehashfakehashfakehashfakehashfakehash12"
	displayName := "alice"

	in := &User{
		Email:        "alice@example.com",
		DisplayName:  displayName,
		PasswordHash: &hash,
		PlatformRole: "client",
		TenantID:     &tid,
		TenantRole:   &role,
	}
	created, err := st.CreateUser(ctx, in)
	require.NoError(t, err)
	assert.Greater(t, created.ID, int64(0))
	assert.Equal(t, "alice@example.com", created.Email)
	assert.Equal(t, displayName, created.DisplayName)
	assert.Equal(t, "client", created.PlatformRole)
	assert.Equal(t, tid, *created.TenantID)
	assert.Equal(t, "owner", *created.TenantRole)
	assert.Equal(t, hash, *created.PasswordHash)
	assert.Nil(t, created.TotpSecret)
	assert.Nil(t, created.TotpEnabledAt)
	assert.Nil(t, created.RecoveryCodesHash)

	// GetUserByEmail
	got, err := st.GetUserByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, hash, *got.PasswordHash)
	assert.Nil(t, got.TotpSecret)

	// Case-insensitive lookup (mirror of service.py email.lower())
	got2, err := st.GetUserByEmail(ctx, "ALICE@EXAMPLE.COM")
	require.NoError(t, err)
	assert.Equal(t, created.ID, got2.ID)
}

func TestUserCreateDuplicateEmailIsConflict(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	tid := seedTenant(t, st)
	role := "owner"

	u := &User{
		Email:        "dup@example.com",
		DisplayName:  "dup",
		PlatformRole: "client",
		TenantID:     &tid,
		TenantRole:   &role,
	}
	_, err := st.CreateUser(ctx, u)
	require.NoError(t, err)

	_, err = st.CreateUser(ctx, u)
	var ce *ConflictError
	require.ErrorAs(t, err, &ce)
}

func TestUserGetByEmail_NotFound(t *testing.T) {
	st := authTestStore(t)
	_, err := st.GetUserByEmail(context.Background(), "nobody@example.com")
	var nf *NotFoundError
	require.ErrorAs(t, err, &nf)
}

func TestUserCreateAdmin(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	u := &User{
		Email:           "admin@example.com",
		DisplayName:     "Admin",
		PlatformRole:    "admin",
		EmailVerifiedAt: &now,
	}
	created, err := st.CreateUser(ctx, u)
	require.NoError(t, err)
	assert.Equal(t, "admin", created.PlatformRole)
	assert.Nil(t, created.TenantID)
	assert.Nil(t, created.TenantRole)
	require.NotNil(t, created.EmailVerifiedAt)
}

// ---------------------------------------------------------------------------
// UpdateUser
// ---------------------------------------------------------------------------

func TestUpdateUser_EmailVerifiedAndTotp(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	tid := seedTenant(t, st)
	role := "owner"
	u, err := st.CreateUser(ctx, &User{
		Email:        "upd@example.com",
		DisplayName:  "upd",
		PlatformRole: "client",
		TenantID:     &tid,
		TenantRole:   &role,
	})
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	secret := "JBSWY3DPEHPK3PXP"
	lastLogin := now.Add(-time.Hour)

	err = st.UpdateUser(ctx, u.ID, UserUpdate{
		EmailVerifiedAt: &now,
		TotpSecret:      &secret,
		TotpEnabledAt:   &now,
		LastLoginAt:     &lastLogin,
	})
	require.NoError(t, err)

	got, err := st.GetUserByEmail(ctx, "upd@example.com")
	require.NoError(t, err)

	require.NotNil(t, got.EmailVerifiedAt)
	assert.WithinDuration(t, now, *got.EmailVerifiedAt, time.Second)
	require.NotNil(t, got.TotpSecret)
	assert.Equal(t, secret, *got.TotpSecret)
	require.NotNil(t, got.TotpEnabledAt)
	require.NotNil(t, got.LastLoginAt)

	// GetUserByID also returns the auth-gate subset — make sure it still works.
	authUser, err := st.GetUserByID(ctx, u.ID)
	require.NoError(t, err)
	require.NotNil(t, authUser.EmailVerifiedAt)
	require.NotNil(t, authUser.TotpEnabledAt)
}

func TestUpdateUser_RecoveryCodes(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	tid := seedTenant(t, st)
	role := "member"
	u, err := st.CreateUser(ctx, &User{
		Email:        "rcodes@example.com",
		DisplayName:  "rc",
		PlatformRole: "client",
		TenantID:     &tid,
		TenantRole:   &role,
	})
	require.NoError(t, err)

	codes := []string{"hash1", "hash2", "hash3"}
	err = st.UpdateUser(ctx, u.ID, UserUpdate{RecoveryCodesHash: codes})
	require.NoError(t, err)

	got, err := st.GetUserByEmail(ctx, "rcodes@example.com")
	require.NoError(t, err)
	assert.Equal(t, codes, got.RecoveryCodesHash)
}

func TestUpdateUser_NotFound(t *testing.T) {
	st := authTestStore(t)
	displayName := "ghost"
	err := st.UpdateUser(context.Background(), 999999, UserUpdate{DisplayName: &displayName})
	var nf *NotFoundError
	require.ErrorAs(t, err, &nf)
}

// ---------------------------------------------------------------------------
// EmailVerification tests
// ---------------------------------------------------------------------------

func TestEmailVerification_CreateGetMarkUsed(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	tid := seedTenant(t, st)
	role := "owner"
	u, err := st.CreateUser(ctx, &User{
		Email: "evuser@example.com", DisplayName: "ev",
		PlatformRole: "client", TenantID: &tid, TenantRole: &role,
	})
	require.NoError(t, err)

	hash := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	expires := time.Now().UTC().Add(time.Hour)

	require.NoError(t, st.CreateEmailVerification(ctx, u.ID, hash, "verify_email", expires))

	v, err := st.GetEmailVerification(ctx, hash, "verify_email")
	require.NoError(t, err)
	assert.Equal(t, u.ID, v.UserID)
	assert.Equal(t, "verify_email", v.Purpose)
	assert.Equal(t, hash, v.TokenHash)
	assert.Nil(t, v.UsedAt)

	// Mark used.
	require.NoError(t, st.MarkEmailVerificationUsed(ctx, v.ID))

	// Should no longer be returned by GetEmailVerification.
	_, err = st.GetEmailVerification(ctx, hash, "verify_email")
	var nf *NotFoundError
	require.ErrorAs(t, err, &nf)
}

func TestEmailVerification_ExpiredNotReturned(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	tid := seedTenant(t, st)
	role := "owner"
	u, err := st.CreateUser(ctx, &User{
		Email: "expireduser@example.com", DisplayName: "exp",
		PlatformRole: "client", TenantID: &tid, TenantRole: &role,
	})
	require.NoError(t, err)

	hash := "expired00000000000000000000000000000000000000000000000000000000"
	// expires_at in the past
	expires := time.Now().UTC().Add(-time.Second)
	require.NoError(t, st.CreateEmailVerification(ctx, u.ID, hash, "reset_password", expires))

	_, err = st.GetEmailVerification(ctx, hash, "reset_password")
	var nf *NotFoundError
	require.ErrorAs(t, err, &nf)
}

func TestEmailVerification_WrongPurposeNotReturned(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	tid := seedTenant(t, st)
	role := "owner"
	u, err := st.CreateUser(ctx, &User{
		Email: "purposeuser@example.com", DisplayName: "pu",
		PlatformRole: "client", TenantID: &tid, TenantRole: &role,
	})
	require.NoError(t, err)

	hash := "purposehash000000000000000000000000000000000000000000000000000"
	expires := time.Now().UTC().Add(time.Hour)
	require.NoError(t, st.CreateEmailVerification(ctx, u.ID, hash, "verify_email", expires))

	// Query with wrong purpose.
	_, err = st.GetEmailVerification(ctx, hash, "reset_password")
	var nf *NotFoundError
	require.ErrorAs(t, err, &nf)
}

// ---------------------------------------------------------------------------
// OAuthAccount tests
// ---------------------------------------------------------------------------

func TestOAuthAccount_CreateAndGet(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	tid := seedTenant(t, st)
	role := "owner"
	u, err := st.CreateUser(ctx, &User{
		Email: "oauthuser@example.com", DisplayName: "oauth",
		PlatformRole: "client", TenantID: &tid, TenantRole: &role,
	})
	require.NoError(t, err)

	oa, err := st.CreateOAuthAccount(ctx, u.ID, "google", "g-12345", "oauthuser@gmail.com")
	require.NoError(t, err)
	assert.Equal(t, u.ID, oa.UserID)
	assert.Equal(t, "google", oa.Provider)
	assert.Equal(t, "g-12345", oa.ProviderAccountID)
	assert.Equal(t, "oauthuser@gmail.com", oa.EmailAtProvider)

	got, err := st.GetOAuthAccount(ctx, "google", "g-12345")
	require.NoError(t, err)
	assert.Equal(t, oa.ID, got.ID)
	assert.Equal(t, u.ID, got.UserID)
}

func TestOAuthAccount_DuplicateIsConflict(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()

	tid := seedTenant(t, st)
	role := "owner"
	u, err := st.CreateUser(ctx, &User{
		Email: "oauth2@example.com", DisplayName: "o2",
		PlatformRole: "client", TenantID: &tid, TenantRole: &role,
	})
	require.NoError(t, err)

	_, err = st.CreateOAuthAccount(ctx, u.ID, "github", "gh-999", "oauth2@github.com")
	require.NoError(t, err)

	_, err = st.CreateOAuthAccount(ctx, u.ID, "github", "gh-999", "oauth2@github.com")
	var ce *ConflictError
	require.ErrorAs(t, err, &ce)
}

func TestOAuthAccount_NotFound(t *testing.T) {
	st := authTestStore(t)
	_, err := st.GetOAuthAccount(context.Background(), "google", "nonexistent")
	var nf *NotFoundError
	require.ErrorAs(t, err, &nf)
}
