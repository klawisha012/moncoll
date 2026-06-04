//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

func TestGetConnectionForTenant(t *testing.T) {
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	res, err := pool.Run("postgres", "16", []string{"POSTGRES_PASSWORD=pw", "POSTGRES_DB=waf"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Purge(res) })

	dsn := fmt.Sprintf("postgres://postgres:pw@localhost:%s/waf?sslmode=disable", res.GetPort("5432/tcp"))

	var st *Store
	require.NoError(t, pool.Retry(func() error {
		s, e := New(context.Background(), dsn)
		if e != nil {
			return e
		}
		st = s
		return st.pool.Ping(context.Background())
	}))
	t.Cleanup(st.Close)

	ctx := context.Background()

	_, err = st.pool.Exec(ctx, `
		CREATE TABLE tenants (
			id BIGINT PRIMARY KEY,
			name TEXT NOT NULL,
			display_name TEXT NOT NULL DEFAULT '',
			suspended_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE TABLE connections (
			id BIGINT PRIMARY KEY,
			tenant_id BIGINT NOT NULL,
			name TEXT NOT NULL,
			domain TEXT NOT NULL UNIQUE,
			enabled BOOLEAN NOT NULL DEFAULT true,
			status TEXT NOT NULL DEFAULT 'active'
		);
		INSERT INTO tenants (id, name) VALUES (1, 'acme'), (2, 'beta');
		INSERT INTO connections (id, tenant_id, name, domain, enabled, status) VALUES
			(10, 1, 'main', 'acme.example.com', true, 'active'),
			(20, 2, 'web', 'beta.example.com', true, 'active');
	`)
	require.NoError(t, err)

	t.Run("OwnerMatch", func(t *testing.T) {
		conn, err := st.GetConnectionForTenant(ctx, 10, 1)
		require.NoError(t, err)
		require.NotNil(t, conn)
		require.Equal(t, int64(10), conn.ID)
		require.Equal(t, int64(1), conn.TenantID)
		require.Equal(t, "acme.example.com", conn.Domain)
	})

	t.Run("WrongTenant_ReturnsNotFound", func(t *testing.T) {
		// Connection 10 belongs to tenant 1, not tenant 2 — must return NotFoundError.
		conn, err := st.GetConnectionForTenant(ctx, 10, 2)
		require.Nil(t, conn)
		var nf *NotFoundError
		require.ErrorAs(t, err, &nf, "expected *NotFoundError for wrong-tenant lookup, got %v", err)
	})

	t.Run("NonExistentConnection_ReturnsNotFound", func(t *testing.T) {
		conn, err := st.GetConnectionForTenant(ctx, 999, 1)
		require.Nil(t, conn)
		var nf *NotFoundError
		require.ErrorAs(t, err, &nf)
	})
}
