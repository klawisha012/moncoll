package storage

import "testing"

func TestLocalLayoutPath(t *testing.T) {
	l := LocalLayout{Tenants: "/t", HTTPD: "/h", State: "/s", Modsec: "/m"}
	cases := map[string]string{
		"tenants/7/conn_3/3.conf":           "/t/7/compose/conn_3/3.conf",
		"tenants/7/conn_3/blocked_ips.conf": "/t/7/compose/conn_3/blocked_ips.conf",
		"certs/conn_3/3.key":                "/h/conn_3/3.key",
		"state/connections.json":            "/s/connections.json",
		"state/manifest.json":               "/s/manifest.json",
		"modsec/rules.conf":                 "/m/rules.conf",
	}
	for key, want := range cases {
		if got := l.Path(key); got != want {
			t.Errorf("Path(%q) = %q, want %q", key, got, want)
		}
	}
}
