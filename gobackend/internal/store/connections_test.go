//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

func TestListConnections(t *testing.T) {
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

	// Minimal schema — only the columns ListConnections queries.
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
		INSERT INTO tenants (id, name, display_name) VALUES (1, 'acme', 'Acme'), (2, 'beta', 'Beta');
		INSERT INTO connections (id, tenant_id, name, domain, enabled, status) VALUES
			(10, 1, 'main', 'acme.example.com', true, 'active'),
			(11, 1, 'staging', 'staging.acme.example.com', false, 'pending_verification'),
			(12, 2, 'web', 'beta.example.com', true, 'active');
	`)
	require.NoError(t, err)

	conns, err := st.ListConnections(ctx)
	require.NoError(t, err)
	require.Len(t, conns, 3)

	// Results are ordered by id.
	require.Equal(t, int64(10), conns[0].ID)
	require.Equal(t, int64(1), conns[0].TenantID)
	require.Equal(t, "main", conns[0].Name)
	require.Equal(t, "acme.example.com", conns[0].Domain)
	require.True(t, conns[0].Enabled)
	require.Equal(t, "active", conns[0].Status)

	require.Equal(t, int64(11), conns[1].ID)
	require.False(t, conns[1].Enabled)
	require.Equal(t, "pending_verification", conns[1].Status)

	require.Equal(t, int64(12), conns[2].ID)
	require.Equal(t, int64(2), conns[2].TenantID)
	require.Equal(t, "beta.example.com", conns[2].Domain)

	// Empty DB variant: zero rows should return nil slice, no error.
	_, err = st.pool.Exec(ctx, `DELETE FROM connections`)
	require.NoError(t, err)
	conns2, err := st.ListConnections(ctx)
	require.NoError(t, err)
	require.Empty(t, conns2)
}
