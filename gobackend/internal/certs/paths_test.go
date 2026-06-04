package certs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func tid(n int64) *int64 { return &n }

// TestBackendSSLPaths_NoTenant mirrors the non-tenant branch.
func TestBackendSSLPaths_NoTenant(t *testing.T) {
	cert, key := BackendSSLPaths(7, nil)
	assert.Equal(t, "/var/lib/angie/http.d/conn_7/7.crt", cert)
	assert.Equal(t, "/var/lib/angie/http.d/conn_7/7.key", key)
}

// TestBackendSSLPaths_WithTenant mirrors the tenant branch.
func TestBackendSSLPaths_WithTenant(t *testing.T) {
	cert, key := BackendSSLPaths(42, tid(3))
	assert.Equal(t, "/var/lib/waf/tenants/3/compose/conn_42/42.crt", cert)
	assert.Equal(t, "/var/lib/waf/tenants/3/compose/conn_42/42.key", key)
}

// TestAngieSSLPaths_NoTenant uses ANGIE_HTTPD_DIR constant.
func TestAngieSSLPaths_NoTenant(t *testing.T) {
	cert, key := AngieSSLPaths(7, nil)
	assert.Equal(t, "/etc/angie/http.d/conn_7/7.crt", cert)
	assert.Equal(t, "/etc/angie/http.d/conn_7/7.key", key)
}

// TestAngieSSLPaths_WithTenant verifies exact tenant path.
func TestAngieSSLPaths_WithTenant(t *testing.T) {
	cert, key := AngieSSLPaths(42, tid(3))
	assert.Equal(t, "/etc/angie/tenants/3/compose/conn_42/42.crt", cert)
	assert.Equal(t, "/etc/angie/tenants/3/compose/conn_42/42.key", key)
}

// TestConnectionSSLPaths_BackwardCompat checks alias equals non-tenant backend paths.
func TestConnectionSSLPaths_BackwardCompat(t *testing.T) {
	c1, k1 := ConnectionSSLPaths(99)
	c2, k2 := BackendSSLPaths(99, nil)
	assert.Equal(t, c2, c1)
	assert.Equal(t, k2, k1)
}

// TestBackendSSLPaths_LargeIDs checks large connection/tenant IDs produce correct format.
func TestBackendSSLPaths_LargeIDs(t *testing.T) {
	cert, key := BackendSSLPaths(1000, tid(999))
	assert.Equal(t, "/var/lib/waf/tenants/999/compose/conn_1000/1000.crt", cert)
	assert.Equal(t, "/var/lib/waf/tenants/999/compose/conn_1000/1000.key", key)
}
