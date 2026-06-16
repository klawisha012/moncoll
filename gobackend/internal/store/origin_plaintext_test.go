//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOriginTLSModeOffAccepted verifies migration 0009 added 'off' to the
// origin_tls_mode enum so a connection can proxy to a plain-HTTP origin. Runs
// against the REAL migrator (authTestStore) so the actual enum is exercised —
// before 0009 this INSERT fails with
// `invalid input value for enum origin_tls_mode: "off"`.
func TestOriginTLSModeOffAccepted(t *testing.T) {
	st := authTestStore(t)
	ctx := context.Background()
	tid := seedTenant(t, st)

	_, err := st.pool.Exec(ctx,
		`INSERT INTO connections (tenant_id, name, domain, status, origin_hosts, origin_port,
			origin_tls_mode, verify_token, http_versions, compression_algo, modsec_state, geoip_denied_countries)
		 VALUES ($1, 'WAF site', 'app.example.com', 'pending_dns', '["frontend"]'::json, 3000,
			'off', 'tok', 'h1,h2', 'auto', 'detection_only', '[]'::json)`, tid)
	require.NoError(t, err, "origin_tls_mode 'off' must be accepted after migration 0009")

	var mode string
	require.NoError(t, st.pool.QueryRow(ctx,
		`SELECT origin_tls_mode FROM connections WHERE tenant_id=$1 AND domain='app.example.com'`, tid).Scan(&mode))
	require.Equal(t, "off", mode)
}
