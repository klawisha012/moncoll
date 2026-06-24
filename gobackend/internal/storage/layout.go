package storage

import (
	"path"
	"strings"
)

// LocalLayout maps canonical object keys to the live local filesystem paths
// that Angie already reads. It preserves the existing single-node volume layout
// (backward compatibility) and is shared by:
//   - the local-mode Store (backend writes land at current paths), and
//   - the edge-sync sidecar (materialises S3 objects to the same paths).
//
// Key → path (see specs/001-horizontal-scaling/contracts/object-layout.md):
//
//	tenants/<tid>/conn_<id>/<rest> → <Tenants>/<tid>/compose/conn_<id>/<rest>
//	certs/conn_<id>/<rest>         → <HTTPD>/conn_<id>/<rest>
//	state/<rest>                   → <State>/<rest>   (also the manifest)
//	modsec/<rest>                  → <Modsec>/<rest>
type LocalLayout struct {
	Tenants string // default /var/lib/waf/tenants (WAF_TENANTS_DIR)
	HTTPD   string // default /var/lib/angie/http.d
	State   string // default /var/lib/angie/data   (WAF_STATE_DIR)
	Modsec  string // default /app/etc/angie/modsecurity (WAF_MODSEC_DIR)
}

// DefaultLayout returns the production container paths.
func DefaultLayout() LocalLayout {
	return LocalLayout{
		Tenants: "/var/lib/waf/tenants",
		HTTPD:   "/var/lib/angie/http.d",
		State:   "/var/lib/angie/data",
		Modsec:  "/app/etc/angie/modsecurity",
	}
}

// Path resolves a canonical key to its live local path.
func (l LocalLayout) Path(key string) string {
	cls, rest, ok := strings.Cut(key, "/")
	if !ok {
		return path.Join(l.State, key) // bare top-level key (defensive)
	}
	switch cls {
	case "tenants":
		// <tid>/conn_<id>/<rest> → <tid>/compose/conn_<id>/<rest>
		if tid, sub, ok := strings.Cut(rest, "/"); ok {
			return path.Join(l.Tenants, tid, "compose", sub)
		}
		return path.Join(l.Tenants, rest)
	case "certs":
		return path.Join(l.HTTPD, rest)
	case "modsec":
		return path.Join(l.Modsec, rest)
	case "state":
		return path.Join(l.State, rest)
	default:
		return path.Join(l.State, key)
	}
}
