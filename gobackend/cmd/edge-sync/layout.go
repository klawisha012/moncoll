package main

import (
	"os"

	"github.com/zwarder/waf/gobackend/internal/storage"
)

// edgeLayout maps canonical object keys to the live local paths this edge node's
// Angie reads (contracts/object-layout.md). It reuses storage.LocalLayout — the
// same key→path mapper the backend's local mode uses — with edge-container roots.
// Every root is env-overridable so one binary fits docker-compose and k8s.
//
//	tenants/<tid>/conn_<id>/… → <WAF_TENANTS_DIR>/<tid>/compose/conn_<id>/…
//	certs/conn_<id>/…         → <WAF_HTTPD_DIR>/conn_<id>/…
//	state/…                   → <WAF_STATE_DIR>/…
//	modsec/…                  → <WAF_MODSEC_DIR>/…
func edgeLayout() storage.LocalLayout {
	return storage.LocalLayout{
		Tenants: getenv("WAF_TENANTS_DIR", "/var/lib/waf/tenants"),
		HTTPD:   getenv("WAF_HTTPD_DIR", "/var/lib/angie/http.d"),
		State:   getenv("WAF_STATE_DIR", "/var/lib/angie/data"),
		Modsec:  getenv("WAF_MODSEC_DIR", "/var/lib/angie/modsecurity"),
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
