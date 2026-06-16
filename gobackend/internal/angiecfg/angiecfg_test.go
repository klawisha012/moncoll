package angiecfg_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zwarder/waf/gobackend/internal/angiecfg"
)

// ptr returns a pointer to a string literal — handy for optional fields.
func ptr(s string) *string { return &s }

// ── helpers ──────────────────────────────────────────────────────────────────

func requireRender(t *testing.T, cfg angiecfg.ConnConfig) map[string]string {
	t.Helper()
	files, err := angiecfg.Render(cfg)
	require.NoError(t, err)
	return files
}

func confContent(t *testing.T, files map[string]string, connID int64) string {
	t.Helper()
	key := angiecfg.ConfFilename(connID)
	content, ok := files[key]
	require.Truef(t, ok, "expected file %q in rendered output; got keys: %v", key, mapKeys(files))
	return content
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ── Test: origin_tls_mode "off" → plain-HTTP origin proxy ───────────────────

func TestRender_OriginTLSOff_PlainHTTP(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID:             10,
		TenantID:       7,
		Name:           "WAF site",
		Domain:         "app.example.com",
		OriginHosts:    []string{"frontend"},
		OriginPort:     3000,
		Status:         "pending_dns",
		OriginTLSMode:  "off",
		HTTPVersions:   "h1,h2",
		Compression:    "auto",
		ModsecState:    "detection_only",
		CrowdsecActive: true,
	}

	conf := confContent(t, requireRender(t, cfg), cfg.ID)

	// Plain-HTTP origin proxy — NOT https, and NO proxy_ssl_* directives.
	assert.Contains(t, conf, "        proxy_pass                       http://conn_10_origin;")
	assert.NotContains(t, conf, "proxy_pass                       https://conn_10_origin;")
	assert.NotContains(t, conf, "proxy_ssl_verify")
	assert.NotContains(t, conf, "proxy_ssl_server_name")
	assert.NotContains(t, conf, "proxy_ssl_name")
	assert.NotContains(t, conf, "proxy_ssl_trusted_certificate")
	// tls=off recorded in the header comment.
	assert.Contains(t, conf, "## origin=frontend:3000 | tls=off")
	// WebSocket upgrade still wired (centrifugo / socket.io need it).
	assert.Contains(t, conf, "        proxy_set_header Connection      $connection_upgrade;")
}

// ── Test 1: pre-active (no cert), strict TLS, modsec=detection_only ─────────

func TestRender_PreActive_Strict_DetectionOnly(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID:            42,
		TenantID:      7,
		Name:          "my-site",
		Domain:        "example.com",
		OriginHosts:   []string{"1.2.3.4"},
		OriginPort:    443,
		Status:        "pending_verification",
		OriginTLSMode: "strict",
		HTTPVersions:  "h1,h2",
		Compression:   "auto",
		ModsecState:   "detection_only",
		GeoipDenied:   nil,
		CrowdsecActive: true,
		// No cert paths → pre-active mode
		SSLCertPath: nil,
		SSLKeyPath:  nil,
	}

	files := requireRender(t, cfg)

	// Must produce exactly 2 files: the .conf and blocked_ips.conf stub
	assert.Len(t, files, 2)
	_, hasBlockedIps := files["blocked_ips.conf"]
	assert.True(t, hasBlockedIps, "blocked_ips.conf must be present")

	conf := confContent(t, files, cfg.ID)

	// Comment header
	assert.Contains(t, conf, "## conn_42: my-site | example.com | status=pending_verification")
	assert.Contains(t, conf, "## origin=1.2.3.4:443 | tls=strict")
	assert.Contains(t, conf, "## Generated at:")

	// Upstream block
	assert.Contains(t, conf, "upstream conn_42_origin {")
	assert.Contains(t, conf, "    server 1.2.3.4:443 max_fails=3 fail_timeout=30s;")
	assert.Contains(t, conf, "    keepalive 128;")

	// HTTP server block
	assert.Contains(t, conf, "server {")
	assert.Contains(t, conf, "    listen 80;")
	assert.Contains(t, conf, "    server_name example.com;")
	assert.Contains(t, conf, "    if ($http_x_waf_loop) { return 508; }")
	assert.Contains(t, conf, "    access_log /var/log/angie/geoip.log with_geoip_json;")
	assert.Contains(t, conf, "    access_log /var/log/angie/access.log combined;")

	// CrowdSec blocked_ips include (crowdsec_active=true)
	assert.Contains(t, conf, "    include /etc/angie/tenants/7/compose/conn_42/blocked_ips.conf;")

	// ModSecurity state
	assert.Contains(t, conf, "    modsecurity on;")
	assert.Contains(t, conf, "    modsecurity_rules 'SecRuleEngine DetectionOnly';")

	// ACME challenge location
	assert.Contains(t, conf, "    location ^~ /.well-known/acme-challenge/ {")
	assert.Contains(t, conf, "        root /etc/angie/tenants/7/compose/conn_42/site;")
	assert.Contains(t, conf, "        try_files $uri =404;")

	// Pre-active: proxy locations (not redirect)
	assert.Contains(t, conf, "    location /socket.io/ {")
	assert.Contains(t, conf, "        modsecurity off;")
	assert.Contains(t, conf, "    location / {")

	// Proxy directives with $connection_upgrade — CRITICAL
	assert.Contains(t, conf, "        proxy_set_header Connection      $connection_upgrade;")
	assert.Contains(t, conf, "        proxy_pass                       https://conn_42_origin;")
	assert.Contains(t, conf, "        proxy_ssl_server_name            on;")
	assert.Contains(t, conf, "        proxy_ssl_name                   example.com;")
	assert.Contains(t, conf, "        proxy_ssl_verify                 on;")
	assert.Contains(t, conf, "        proxy_ssl_trusted_certificate    /etc/ssl/certs/ca-certificates.crt;")

	// Pre-active → NO TLS server block
	assert.Equal(t, 1, strings.Count(conf, "server {"), "pre-active config must have exactly 1 server block")

	// Ends with newline
	assert.True(t, strings.HasSuffix(conf, "\n"))
}

// ── Test 2: active, TLS strict, h2+h3, modsec=blocking, geoip, crowdsec on ─

func TestRender_Active_H2H3_Blocking_Geoip(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID:              5,
		TenantID:        3,
		Name:            "prod",
		Domain:          "secure.example.com",
		OriginHosts:     []string{"10.0.0.1", "10.0.0.2"},
		OriginPort:      8443,
		Status:          "active",
		OriginTLSMode:   "strict",
		HTTPVersions:    "h1,h2,h3",
		Compression:     "auto",
		ModsecState:     "blocking",
		GeoipDenied:     []string{"RU", "CN", "KP"},
		CrowdsecActive:  true,
		SSLCertPath:     ptr("/etc/angie/tenants/3/compose/conn_5/5.crt"),
		SSLKeyPath:      ptr("/etc/angie/tenants/3/compose/conn_5/5.key"),
		StatusDetail:    nil, // not self-signed → HSTS
	}

	files := requireRender(t, cfg)
	assert.Len(t, files, 2)

	conf := confContent(t, files, cfg.ID)

	// Two server blocks: port 80 + port 443
	assert.Equal(t, 2, strings.Count(conf, "server {"), "active config must have 2 server blocks")

	// Port-80 redirect block
	assert.Contains(t, conf, "    listen 80;")
	assert.Contains(t, conf, "        proxy_pass http://127.0.0.1:8082;")
	assert.Contains(t, conf, "        proxy_set_header Host $host;")
	assert.Contains(t, conf, "        proxy_http_version 1.1;")

	// TLS block structure
	assert.Contains(t, conf, "    listen 443 ssl;")
	assert.Contains(t, conf, "    http2 on;")
	assert.Contains(t, conf, "    listen 443 quic;")
	assert.Contains(t, conf, "    http3 on;")
	assert.Contains(t, conf, "    add_header Alt-Svc 'h3=\":443\"; ma=86400' always;")

	// Cert paths (Angie-side)
	assert.Contains(t, conf, "    ssl_certificate     /etc/angie/tenants/3/compose/conn_5/5.crt;")
	assert.Contains(t, conf, "    ssl_certificate_key /etc/angie/tenants/3/compose/conn_5/5.key;")

	// HSTS (not self-signed)
	assert.Contains(t, conf, `    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`)

	// Upstream with multiple servers
	assert.Contains(t, conf, "    server 10.0.0.1:8443 max_fails=3 fail_timeout=30s;")
	assert.Contains(t, conf, "    server 10.0.0.2:8443 max_fails=3 fail_timeout=30s;")

	// Modsec blocking
	assert.Contains(t, conf, "    modsecurity on;")
	assert.Contains(t, conf, "    modsecurity_rules 'SecRuleEngine On';")

	// GeoIP deny in non-ACME locations (sorted: CN KP RU)
	assert.Contains(t, conf, `        if ($geoip2_data_country_code ~ "^(CN|KP|RU)$") { return 403; }`)

	// $connection_upgrade present in TLS block
	assert.Contains(t, conf, "        proxy_set_header Connection      $connection_upgrade;")

	// Static assets location (modsecurity off)
	assert.Contains(t, conf, `    location ~* \.(?:jpg|jpeg|gif|png|ico|css|js|woff2?|svg|webp)$ {`)
	assert.Contains(t, conf, "        modsecurity off;")

	// CrowdSec include in both blocks
	assert.Equal(t, 2, strings.Count(conf, "    include /etc/angie/tenants/3/compose/conn_5/blocked_ips.conf;"))

	// blocked_ips stub
	bips, ok := files["blocked_ips.conf"]
	assert.True(t, ok)
	assert.Equal(t, "# Auto-generated — blocked IPs for this connection\n", bips)
}

// ── Test 3: active, TLS lenient, modsec=off, no geoip, crowdsec off ─────────

func TestRender_Active_Lenient_ModsecOff_NoCrowdsec(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID:             9,
		TenantID:       1,
		Name:           "shop",
		Domain:         "shop.example.com",
		OriginHosts:    []string{"192.168.1.100"},
		OriginPort:     443,
		Status:         "active",
		OriginTLSMode:  "lenient",
		HTTPVersions:   "h1,h2",
		Compression:    "gzip",
		ModsecState:    "off",
		GeoipDenied:    nil,
		CrowdsecActive: false,
		SSLCertPath:    ptr("/etc/angie/tenants/1/compose/conn_9/9.crt"),
		SSLKeyPath:     ptr("/etc/angie/tenants/1/compose/conn_9/9.key"),
		StatusDetail:   nil,
	}

	files := requireRender(t, cfg)
	conf := confContent(t, files, cfg.ID)

	// Lenient TLS: verify=off, no trusted cert line
	assert.Contains(t, conf, "        proxy_ssl_verify                 off;")
	assert.NotContains(t, conf, "proxy_ssl_trusted_certificate")

	// Modsec off
	assert.Contains(t, conf, "    modsecurity off;")
	assert.NotContains(t, conf, "modsecurity on;")
	assert.NotContains(t, conf, "modsecurity_rules")

	// No crowdsec include
	assert.NotContains(t, conf, "blocked_ips.conf;")

	// Compression: gzip pinned, brotli+zstd off
	assert.Contains(t, conf, "    # compression_algo=gzip — pin encoder, disable others")
	assert.Contains(t, conf, "    gzip on;")
	assert.Contains(t, conf, "    brotli off;")
	assert.Contains(t, conf, "    zstd off;")

	// h2 on, no h3
	assert.Contains(t, conf, "    http2 on;")
	assert.NotContains(t, conf, "listen 443 quic;")
	assert.NotContains(t, conf, "http3 on;")

	// No geoip deny
	assert.NotContains(t, conf, "geoip2_data_country_code")

	// HSTS still present (active + not self-signed)
	assert.Contains(t, conf, `    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`)

	// $connection_upgrade still present
	assert.Contains(t, conf, "        proxy_set_header Connection      $connection_upgrade;")
}

// ── Test 4: active, self-signed (HSTS suppressed) ────────────────────────────

func TestRender_Active_SelfSigned_NoHSTS(t *testing.T) {
	detail := "Certificate is self-signed"
	cfg := angiecfg.ConnConfig{
		ID:             11,
		TenantID:       2,
		Name:           "dev",
		Domain:         "dev.internal",
		OriginHosts:    []string{"127.0.0.1"},
		OriginPort:     443,
		Status:         "active",
		OriginTLSMode:  "strict",
		HTTPVersions:   "h1,h2",
		Compression:    "none",
		ModsecState:    "detection_only",
		GeoipDenied:    nil,
		CrowdsecActive: false,
		SSLCertPath:    ptr("/etc/angie/tenants/2/compose/conn_11/11.crt"),
		SSLKeyPath:     ptr("/etc/angie/tenants/2/compose/conn_11/11.key"),
		StatusDetail:   &detail,
	}

	files := requireRender(t, cfg)
	conf := confContent(t, files, cfg.ID)

	// HSTS suppressed
	assert.NotContains(t, conf, "Strict-Transport-Security")
	assert.Contains(t, conf, "    # HSTS suppressed: cert is self-signed; emitting it would lock browsers out.")

	// Compression=none: all encoders off
	assert.Contains(t, conf, "    # compression_algo=none — disable all encoders")
	assert.Contains(t, conf, "    gzip off;")
	assert.Contains(t, conf, "    brotli off;")
	assert.Contains(t, conf, "    zstd off;")
}

// ── Test 5: active, h1 only (no h2/h3) ───────────────────────────────────────

func TestRender_Active_H1Only(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID:             20,
		TenantID:       4,
		Name:           "legacy",
		Domain:         "legacy.example.com",
		OriginHosts:    []string{"203.0.113.10"},
		OriginPort:     80,
		Status:         "active",
		OriginTLSMode:  "strict",
		HTTPVersions:   "h1",
		Compression:    "brotli",
		ModsecState:    "detection_only",
		GeoipDenied:    []string{"us", "gb"}, // lowercase → normalised to US, GB
		CrowdsecActive: true,
		SSLCertPath:    ptr("/etc/angie/tenants/4/compose/conn_20/20.crt"),
		SSLKeyPath:     ptr("/etc/angie/tenants/4/compose/conn_20/20.key"),
	}

	files := requireRender(t, cfg)
	conf := confContent(t, files, cfg.ID)

	// h1 only: listen 443 ssl; no http2 on; no quic
	assert.Contains(t, conf, "    listen 443 ssl;")
	assert.NotContains(t, conf, "    http2 on;")
	assert.NotContains(t, conf, "    listen 443 quic;")
	assert.NotContains(t, conf, "    http3 on;")

	// Brotli compression: brotli on, gzip off, zstd off
	assert.Contains(t, conf, "    # compression_algo=brotli — pin encoder, disable others")
	assert.Contains(t, conf, "    brotli on;")
	assert.Contains(t, conf, "    gzip off;")
	assert.Contains(t, conf, "    zstd off;")

	// Geoip countries normalised to uppercase, sorted
	assert.Contains(t, conf, `        if ($geoip2_data_country_code ~ "^(GB|US)$") { return 403; }`)

	// proxy_pass uses origin port 80 but STILL https (origin_tls_mode=strict means HTTPS to origin)
	assert.Contains(t, conf, "        proxy_pass                       https://conn_20_origin;")
	assert.Contains(t, conf, "    server 203.0.113.10:80 max_fails=3 fail_timeout=30s;")
}

// ── Test 6: empty origin_hosts → broken upstream (deliberate) ────────────────

func TestRender_EmptyOriginHosts(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID:           99,
		TenantID:     1,
		Domain:       "broken.example.com",
		OriginHosts:  nil,
		OriginPort:   443,
		Status:       "pending_verification",
		OriginTLSMode: "strict",
		HTTPVersions: "h1,h2",
		Compression:  "auto",
		ModsecState:  "detection_only",
	}

	files := requireRender(t, cfg)
	conf := confContent(t, files, cfg.ID)

	// Deliberately broken upstream
	assert.Contains(t, conf, "upstream conn_99_origin { server 127.0.0.1:1 down; }")
}

// ── Test 7: crowdsec=false → no blocked_ips include in either block ──────────

func TestRender_CrowdsecOff_NoInclude(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID:             15,
		TenantID:       5,
		Domain:         "nocs.example.com",
		OriginHosts:    []string{"10.1.1.1"},
		OriginPort:     443,
		Status:         "active",
		OriginTLSMode:  "strict",
		HTTPVersions:   "h1,h2",
		Compression:    "auto",
		ModsecState:    "detection_only",
		CrowdsecActive: false,
		SSLCertPath:    ptr("/etc/angie/tenants/5/compose/conn_15/15.crt"),
		SSLKeyPath:     ptr("/etc/angie/tenants/5/compose/conn_15/15.key"),
	}

	files := requireRender(t, cfg)
	conf := confContent(t, files, cfg.ID)

	assert.NotContains(t, conf, "blocked_ips.conf;")
}

// ── Test 8: $connection_upgrade present in all proxy locations ───────────────

func TestRender_ConnectionUpgradeAlwaysPresent(t *testing.T) {
	for _, status := range []string{"pending_verification", "active"} {
		var certPath, keyPath *string
		if status == "active" {
			certPath = ptr("/etc/angie/tenants/1/compose/conn_1/1.crt")
			keyPath = ptr("/etc/angie/tenants/1/compose/conn_1/1.key")
		}
		cfg := angiecfg.ConnConfig{
			ID:            1,
			TenantID:      1,
			Domain:        "ws.example.com",
			OriginHosts:   []string{"10.0.0.1"},
			OriginPort:    443,
			Status:        status,
			OriginTLSMode: "strict",
			HTTPVersions:  "h1,h2",
			Compression:   "auto",
			ModsecState:   "detection_only",
			CrowdsecActive: true,
			SSLCertPath:   certPath,
			SSLKeyPath:    keyPath,
		}
		files, err := angiecfg.Render(cfg)
		require.NoError(t, err)
		conf := files[angiecfg.ConfFilename(cfg.ID)]
		count := strings.Count(conf, "        proxy_set_header Connection      $connection_upgrade;")
		assert.Greaterf(t, count, 0, "status=%s: $connection_upgrade must appear at least once", status)
	}
}

// ── Test 9: ConfFilename helper ───────────────────────────────────────────────

func TestConfFilename(t *testing.T) {
	assert.Equal(t, "42.conf", angiecfg.ConfFilename(42))
	assert.Equal(t, "1.conf", angiecfg.ConfFilename(1))
}

// ── Test 10: default http_versions (empty → h1,h2) ────────────────────────────

func TestRender_DefaultHTTPVersions(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID:             30,
		TenantID:       1,
		Domain:         "defaults.example.com",
		OriginHosts:    []string{"10.0.0.1"},
		OriginPort:     443,
		Status:         "active",
		OriginTLSMode:  "strict",
		HTTPVersions:   "", // empty → default h1,h2
		Compression:    "",   // empty → auto
		ModsecState:    "",   // empty → detection_only
		CrowdsecActive: true,
		SSLCertPath:    ptr("/etc/angie/tenants/1/compose/conn_30/30.crt"),
		SSLKeyPath:     ptr("/etc/angie/tenants/1/compose/conn_30/30.key"),
	}

	files := requireRender(t, cfg)
	conf := confContent(t, files, cfg.ID)

	// Default h1,h2 → http2 on, no h3
	assert.Contains(t, conf, "    http2 on;")
	assert.NotContains(t, conf, "listen 443 quic;")

	// Default modsec → detection_only
	assert.Contains(t, conf, "    modsecurity_rules 'SecRuleEngine DetectionOnly';")
}

// ── Test 11: zstd compression ─────────────────────────────────────────────────

func TestRender_ZstdCompression(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID:             31,
		TenantID:       1,
		Domain:         "zstd.example.com",
		OriginHosts:    []string{"10.0.0.1"},
		OriginPort:     443,
		Status:         "active",
		OriginTLSMode:  "lenient",
		HTTPVersions:   "h1,h2",
		Compression:    "zstd",
		ModsecState:    "detection_only",
		CrowdsecActive: false,
		SSLCertPath:    ptr("/etc/angie/tenants/1/compose/conn_31/31.crt"),
		SSLKeyPath:     ptr("/etc/angie/tenants/1/compose/conn_31/31.key"),
	}

	files := requireRender(t, cfg)
	conf := confContent(t, files, cfg.ID)

	assert.Contains(t, conf, "    # compression_algo=zstd — pin encoder, disable others")
	assert.Contains(t, conf, "    zstd on;")
	assert.Contains(t, conf, "    gzip off;")
	assert.Contains(t, conf, "    brotli off;")
}

// ── Anti-DDoS: active (TLS) connection with DdosProtection on ────────────────

func TestRender_Ddos_Active_EmitsLimits(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID: 7, TenantID: 3, Name: "ddos-site", Domain: "ddos.example.com",
		OriginHosts: []string{"9.9.9.9"}, OriginPort: 443,
		Status: "active", OriginTLSMode: "strict",
		HTTPVersions: "h1,h2", Compression: "auto", ModsecState: "blocking",
		CrowdsecActive: true, DdosProtection: true,
		SSLCertPath: ptr("/c.pem"), SSLKeyPath: ptr("/k.pem"),
	}
	conf := confContent(t, requireRender(t, cfg), cfg.ID)

	// http-context zones (per-connection, in this conn's own .conf)
	assert.Contains(t, conf, "limit_req_zone $binary_remote_addr zone=conn_7_rl:10m rate=20r/s;")
	assert.Contains(t, conf, "limit_conn_zone $binary_remote_addr zone=conn_7_cz:10m;")
	// server-level connection cap + 429 status
	assert.Contains(t, conf, "    limit_conn conn_7_cz 20;")
	assert.Contains(t, conf, "    limit_req_status 429;")
	assert.Contains(t, conf, "    limit_conn_status 429;")
	// request rate limit in the dynamic location only
	assert.Contains(t, conf, "        limit_req zone=conn_7_rl burst=40 nodelay;")
}

// ── Anti-DDoS off: no limit directives anywhere ──────────────────────────────

func TestRender_Ddos_Off_EmitsNoLimits(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID: 8, TenantID: 3, Name: "plain", Domain: "plain.example.com",
		OriginHosts: []string{"9.9.9.9"}, OriginPort: 443,
		Status: "active", OriginTLSMode: "strict",
		HTTPVersions: "h1,h2", Compression: "auto", ModsecState: "blocking",
		CrowdsecActive: true, DdosProtection: false,
		SSLCertPath: ptr("/c.pem"), SSLKeyPath: ptr("/k.pem"),
	}
	conf := confContent(t, requireRender(t, cfg), cfg.ID)

	assert.NotContains(t, conf, "limit_req")
	assert.NotContains(t, conf, "limit_conn")
}

// ── Anti-DDoS: pre-active connection still gets limits on the :80 server ──────

func TestRender_Ddos_PreActive_EmitsLimits(t *testing.T) {
	cfg := angiecfg.ConnConfig{
		ID: 9, TenantID: 3, Name: "pre", Domain: "pre.example.com",
		OriginHosts: []string{"9.9.9.9"}, OriginPort: 443,
		Status: "pending_verification", OriginTLSMode: "strict",
		HTTPVersions: "h1,h2", Compression: "auto", ModsecState: "detection_only",
		DdosProtection: true,
	}
	conf := confContent(t, requireRender(t, cfg), cfg.ID)

	assert.Contains(t, conf, "limit_req_zone $binary_remote_addr zone=conn_9_rl:10m rate=20r/s;")
	assert.Contains(t, conf, "    limit_conn conn_9_cz 20;")
	assert.Contains(t, conf, "        limit_req zone=conn_9_rl burst=40 nodelay;")
}
