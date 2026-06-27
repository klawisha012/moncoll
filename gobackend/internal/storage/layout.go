package storage

import (
	"fmt"
	"path"
	"regexp"
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

var (
	decimalSegmentRe = regexp.MustCompile(`^[0-9]+$`)
	connSegmentRe    = regexp.MustCompile(`^conn_[0-9]+$`)
)

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
func (l LocalLayout) Path(key string) (string, error) {
	key = strings.TrimSuffix(key, "/")
	parts, err := canonicalKeyParts(key)
	if err != nil {
		return "", err
	}
	cls := parts[0]
	rest := strings.Join(parts[1:], "/")
	switch cls {
	case "tenants":
		// <tid>/conn_<id>/<rest> → <tid>/compose/conn_<id>/<rest>
		if len(parts) < 3 || !decimalSegmentRe.MatchString(parts[1]) || !connSegmentRe.MatchString(parts[2]) {
			return "", fmt.Errorf("storage: invalid tenant object key %q", key)
		}
		return containedJoin(l.Tenants, append([]string{parts[1], "compose"}, parts[2:]...)...)
	case "certs":
		if len(parts) < 2 || !connSegmentRe.MatchString(parts[1]) {
			return "", fmt.Errorf("storage: invalid cert object key %q", key)
		}
		return containedJoin(l.HTTPD, rest)
	case "modsec":
		if len(parts) < 2 {
			return "", fmt.Errorf("storage: invalid modsec object key %q", key)
		}
		return containedJoin(l.Modsec, rest)
	case "state":
		if len(parts) < 2 {
			return "", fmt.Errorf("storage: invalid state object key %q", key)
		}
		return containedJoin(l.State, rest)
	default:
		return "", fmt.Errorf("storage: unknown object key class %q", cls)
	}
}

func canonicalKeyParts(key string) ([]string, error) {
	if key == "" || strings.Contains(key, "\\") || strings.Contains(key, "\x00") || path.IsAbs(key) {
		return nil, fmt.Errorf("storage: invalid object key %q", key)
	}
	if path.Clean(key) != key {
		return nil, fmt.Errorf("storage: non-canonical object key %q", key)
	}
	parts := strings.Split(key, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("storage: invalid object key %q", key)
		}
	}
	return parts, nil
}

func containedJoin(root string, elems ...string) (string, error) {
	cleanRoot := path.Clean(root)
	target := path.Join(append([]string{cleanRoot}, elems...)...)
	if target != cleanRoot && !strings.HasPrefix(target, strings.TrimRight(cleanRoot, "/")+"/") {
		return "", fmt.Errorf("storage: resolved path escapes root")
	}
	return target, nil
}
