// Package certs ports backend/src/certificates/service.py to Go.
// Path helpers are pure functions — no I/O — and are unit-tested.
package certs

import "fmt"

// Backend-container paths (for file operations — /var/lib/angie/http.d)
const backendHTTPDDir = "/var/lib/angie/http.d"

// Angie-container paths (for nginx config directives — /etc/angie/http.d)
const angieHTTPDDir = "/etc/angie/http.d"

// BackendSSLPaths returns the cert and key paths for backend file operations.
// Mirrors get_backend_ssl_paths in service.py.
func BackendSSLPaths(connectionID int64, tenantID *int64) (certPath, keyPath string) {
	if tenantID != nil {
		certPath = fmt.Sprintf("/var/lib/waf/tenants/%d/compose/conn_%d/%d.crt", *tenantID, connectionID, connectionID)
		keyPath = fmt.Sprintf("/var/lib/waf/tenants/%d/compose/conn_%d/%d.key", *tenantID, connectionID, connectionID)
	} else {
		certPath = fmt.Sprintf("%s/conn_%d/%d.crt", backendHTTPDDir, connectionID, connectionID)
		keyPath = fmt.Sprintf("%s/conn_%d/%d.key", backendHTTPDDir, connectionID, connectionID)
	}
	return
}

// AngieSSLPaths returns the cert and key paths as seen from inside the Angie container.
// Mirrors get_angie_ssl_paths in service.py.
func AngieSSLPaths(connectionID int64, tenantID *int64) (certPath, keyPath string) {
	if tenantID != nil {
		certPath = fmt.Sprintf("/etc/angie/tenants/%d/compose/conn_%d/%d.crt", *tenantID, connectionID, connectionID)
		keyPath = fmt.Sprintf("/etc/angie/tenants/%d/compose/conn_%d/%d.key", *tenantID, connectionID, connectionID)
	} else {
		certPath = fmt.Sprintf("%s/conn_%d/%d.crt", angieHTTPDDir, connectionID, connectionID)
		keyPath = fmt.Sprintf("%s/conn_%d/%d.key", angieHTTPDDir, connectionID, connectionID)
	}
	return
}

// ConnectionSSLPaths is the backward-compat alias for BackendSSLPaths with no tenant.
// Mirrors get_connection_ssl_paths in service.py.
func ConnectionSSLPaths(connectionID int64) (certPath, keyPath string) {
	return BackendSSLPaths(connectionID, nil)
}

// sslKeys returns the canonical store object keys for a connection's cert/key
// (object-layout.md). The key object is sensitive (SSE-encrypted, FR-010).
func sslKeys(connectionID int64, tenantID *int64) (certKey, keyKey string) {
	if tenantID != nil {
		certKey = fmt.Sprintf("tenants/%d/conn_%d/%d.crt", *tenantID, connectionID, connectionID)
		keyKey = fmt.Sprintf("tenants/%d/conn_%d/%d.key", *tenantID, connectionID, connectionID)
	} else {
		certKey = fmt.Sprintf("certs/conn_%d/%d.crt", connectionID, connectionID)
		keyKey = fmt.Sprintf("certs/conn_%d/%d.key", connectionID, connectionID)
	}
	return
}
