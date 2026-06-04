//go:build integration

package migrate_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zwarder/waf/gobackend/internal/migrate"
	"github.com/zwarder/waf/gobackend/internal/store"
)

func TestMigrate_FreshDB(t *testing.T) {
	ctx := context.Background()
	dsn := spinUpPostgres(t)

	// First run: apply baseline on a fresh DB.
	require.NoError(t, migrate.Run(dsn, slog.Default()), "first Run must succeed")

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Assert key tables exist.
	for _, table := range []string{"users", "tenants", "connections", "oauth_accounts", "email_verifications"} {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`, table).Scan(&exists)
		require.NoError(t, err, "checking table %s", table)
		assert.True(t, exists, "table %s must exist", table)
	}

	// Spot-check representative columns that are critical for the Go store.
	type colCheck struct{ table, column string }
	checks := []colCheck{
		{"users", "totp_secret"},
		{"users", "recovery_codes_hash"},
		{"users", "email_verified_at"},
		{"connections", "origin_hosts"},
		{"connections", "geoip_denied_countries"},
		{"connections", "crowdsec_active"},
		{"connections", "modsec_state"},
		{"connections", "acme_retry_count"},
	}
	for _, c := range checks {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
			)`, c.table, c.column).Scan(&exists)
		require.NoError(t, err, "checking %s.%s", c.table, c.column)
		assert.True(t, exists, "column %s.%s must exist", c.table, c.column)
	}

	// Verify store queries don't error on the freshly-migrated schema.
	st, err := store.New(ctx, dsn)
	require.NoError(t, err)
	defer st.Close()

	_, err = st.GetUserByID(ctx, 999)
	// Should be NotFoundError, NOT a schema/scan error.
	var nfe *store.NotFoundError
	require.ErrorAs(t, err, &nfe, "GetUserByID on empty DB should return NotFoundError")

	conns, err := st.ListConnections(ctx)
	require.NoError(t, err, "ListConnections on empty DB must not error")
	assert.Empty(t, conns)
}

func TestMigrate_Idempotent(t *testing.T) {
	dsn := spinUpPostgres(t)

	// First run.
	require.NoError(t, migrate.Run(dsn, slog.Default()))

	// Second run: must succeed (ErrNoChange treated as success).
	require.NoError(t, migrate.Run(dsn, slog.Default()), "second Run (idempotent) must not error")
}

// spinUpPostgres starts a throwaway postgres:16 container via dockertest and
// returns its DSN. The container is terminated when t finishes.
func spinUpPostgres(t *testing.T) string {
	t.Helper()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err, "dockertest.NewPool")

	resource, err := pool.RunWithOptions(
		&dockertest.RunOptions{
			Repository: "postgres",
			Tag:        "16",
			Env: []string{
				"POSTGRES_USER=waf",
				"POSTGRES_PASSWORD=waf",
				"POSTGRES_DB=waf",
			},
		},
		func(hc *docker.HostConfig) {
			hc.AutoRemove = true
			hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
		},
	)
	require.NoError(t, err, "pool.RunWithOptions")
	t.Cleanup(func() { _ = pool.Purge(resource) })

	dsn := fmt.Sprintf(
		"postgres://waf:waf@localhost:%s/waf?sslmode=disable",
		resource.GetPort("5432/tcp"),
	)

	// Wait until Postgres is ready to accept connections.
	ctx := context.Background()
	require.NoError(t, pool.Retry(func() error {
		p, err := pgxpool.New(ctx, dsn)
		if err != nil {
			return err
		}
		defer p.Close()
		return p.Ping(ctx)
	}), "postgres did not become ready")

	return dsn
}
