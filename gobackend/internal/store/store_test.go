//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

func TestStoreReadsUsersAndTenants(t *testing.T) {
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
		CREATE TABLE tenants (id BIGINT PRIMARY KEY, suspended_at TIMESTAMPTZ);
		CREATE TABLE users (id BIGINT PRIMARY KEY, platform_role TEXT NOT NULL,
			email_verified_at TIMESTAMPTZ, totp_enabled_at TIMESTAMPTZ, tenant_id BIGINT);
		INSERT INTO tenants VALUES (3, NULL), (4, now());
		INSERT INTO users VALUES (7, 'admin', now(), now(), NULL),
		                         (8, 'client', NULL, NULL, 3);`)
	require.NoError(t, err)

	u, err := st.GetUserByID(ctx, 7)
	require.NoError(t, err)
	require.Equal(t, "admin", u.PlatformRole)
	require.NotNil(t, u.EmailVerifiedAt)
	require.NotNil(t, u.TotpEnabledAt)
	require.Nil(t, u.TenantID)

	u8, err := st.GetUserByID(ctx, 8)
	require.NoError(t, err)
	require.Nil(t, u8.EmailVerifiedAt)
	require.Equal(t, int64(3), *u8.TenantID)

	_, err = st.GetUserByID(ctx, 999)
	var nf *NotFoundError
	require.ErrorAs(t, err, &nf)

	ten, err := st.GetTenantByID(ctx, 4)
	require.NoError(t, err)
	require.NotNil(t, ten.SuspendedAt)

	_ = time.Now
}
