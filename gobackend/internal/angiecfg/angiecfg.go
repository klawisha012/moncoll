// Package angiecfg generates per-connection Angie/nginx server-block configs.
//
// This is a pure Go port of backend/src/connections/angie_config.py.
// All render functions are pure (no I/O). Write() is the only side-effecting
// wrapper that flushes files to the per-connection compose directory.
//
// Filesystem layout (mirrors the Python module):
//
//	Backend writes to: /var/lib/waf/tenants/<tid>/compose/conn_<id>/
//	Angie sees at:     /etc/angie/tenants/<tid>/compose/conn_<id>/
//	Include glob:      /etc/angie/tenants/*/compose/*.conf (and subpaths)
package angiecfg

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// acmeTrustedCA is the system CA bundle path inside the Angie container.
const acmeTrustedCA = "/etc/ssl/certs/ca-certificates.crt"

// tenantsBase is the backend-side root for per-tenant trees.
const tenantsBase = "/var/lib/waf/tenants"

// validHTTPVersions and validCompression mirror the Python constants.
var validHTTPVersions = map[string]bool{"h1": true, "h2": true, "h3": true}
var validCompression = map[string]bool{"auto": true, "gzip": true, "brotli": true, "zstd": true, "none": true}

// ConnConfig carries all the per-connection fields needed to generate the
// Angie server-block configuration. It mirrors the columns that
// angie_config.py reads from the connection dict.
type ConnConfig struct {
	ID     int64
	TenantID int64
	Name   string
	Domain string

	OriginHosts   []string
	OriginPort    int    // default 443
	OriginTLSMode string // "strict" | "lenient"

	Status       string  // "pending_verification" | "pending_dns" | "provisioning_cert" | "active"
	StatusDetail *string // used to detect self-signed certs

	HTTPVersions string // comma-separated: "h1,h2,h3" — empty defaults to "h1,h2"
	Compression  string // "auto" | "gzip" | "brotli" | "zstd" | "none" — empty defaults to "auto"
	ModsecState  string // "off" | "detection_only" | "blocking" — empty defaults to "detection_only"

	GeoipDenied    []string // ISO 3166-1 alpha-2 country codes
	CrowdsecActive bool

	// Cert/key paths as Angie sees them (from inside the Angie container).
	// If both are non-nil AND Status=="active", the TLS server block is emitted.
	SSLCertPath *string
	SSLKeyPath  *string
}

// ConfFilename returns the filename for the per-connection .conf file.
func ConfFilename(connID int64) string {
	return fmt.Sprintf("%d.conf", connID)
}

// Render returns a map of filename → content for all files that should be
// written into the per-connection directory. It is pure — no I/O.
//
// Keys:
//
//	"<id>.conf"       — the Angie server-block config
//	"blocked_ips.conf" — stub (only if it does not exist yet; always returned
//	                     so the caller can skip-if-exists on write)
func Render(cfg ConnConfig) (map[string]string, error) {
	files := make(map[string]string)

	conf, err := renderConf(cfg)
	if err != nil {
		return nil, err
	}
	files[ConfFilename(cfg.ID)] = conf
	files["blocked_ips.conf"] = "# Auto-generated — blocked IPs for this connection\n"

	return files, nil
}

// Write renders the config and writes all files into baseDir/conn_<id>/.
// It also creates the ACME webroot skeleton (site/) and writes
// blocked_ips.conf only if it does not already exist (so live banlists are
// not wiped on config reload).
func Write(baseDir string, cfg ConnConfig) error {
	connDir := filepath.Join(baseDir, fmt.Sprintf("conn_%d", cfg.ID))
	if err := os.MkdirAll(connDir, 0o755); err != nil {
		return fmt.Errorf("angiecfg: mkdir conn dir: %w", err)
	}

	// ACME webroot
	acmeDir := filepath.Join(connDir, "site")
	if err := os.MkdirAll(acmeDir, 0o755); err != nil {
		return fmt.Errorf("angiecfg: mkdir acme dir: %w", err)
	}

	files, err := Render(cfg)
	if err != nil {
		return err
	}

	for name, content := range files {
		dest := filepath.Join(connDir, name)
		if name == "blocked_ips.conf" {
			// Only write if it does not exist — preserve live banlists.
			if _, statErr := os.Stat(dest); statErr == nil {
				continue
			}
		}
		if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
			return fmt.Errorf("angiecfg: write %s: %w", name, err)
		}
	}
	return nil
}

// Delete removes the conn_<id> directory tree (best-effort, ignores not-exist).
func Delete(baseDir string, connID int64) error {
	connDir := filepath.Join(baseDir, fmt.Sprintf("conn_%d", connID))
	err := os.RemoveAll(connDir)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ConnDir returns the backend-side path to the per-connection directory.
// Mirrors _conn_dir in angie_config.py.
func ConnDir(tenantID, connID int64) string {
	return fmt.Sprintf("%s/%d/compose/conn_%d", tenantsBase, tenantID, connID)
}

// ── internal rendering ────────────────────────────────────────────────────────

func renderConf(cfg ConnConfig) (string, error) {
	connID := cfg.ID
	tenantID := cfg.TenantID
	domain := cfg.Domain

	originHosts := cfg.OriginHosts
	originPort := cfg.OriginPort
	if originPort == 0 {
		originPort = 443
	}

	status := cfg.Status
	if status == "" {
		status = "pending_verification"
	}

	tlsMode := cfg.OriginTLSMode
	if tlsMode == "" {
		tlsMode = "strict"
	}

	httpVersions := parseHTTPVersions(cfg.HTTPVersions)
	compression := normCompression(cfg.Compression)
	modsecState := cfg.ModsecState
	if modsecState == "" {
		modsecState = "detection_only"
	}

	geoipDenied := cfg.GeoipDenied
	crowdsecActive := cfg.CrowdsecActive

	hasCert := cfg.SSLCertPath != nil && cfg.SSLKeyPath != nil && *cfg.SSLCertPath != "" && *cfg.SSLKeyPath != "" && status == "active"

	isSelfSigned := cfg.StatusDetail != nil && strings.Contains(strings.ToLower(*cfg.StatusDetail), "self-signed")
	emitHSTS := hasCert && !isSelfSigned

	// Angie-side paths (POSIX — these go inside .conf files for a Linux container)
	angieConnDir := fmt.Sprintf("/etc/angie/tenants/%d/compose/conn_%d", tenantID, connID)
	blockedIPsInclude := fmt.Sprintf("    include %s/blocked_ips.conf;", angieConnDir)
	acmeRoot := fmt.Sprintf("%s/site", angieConnDir)

	proxyBlock := emitProxyBlock(connID, domain, tlsMode)

	var b strings.Builder
	name := cfg.Name

	// ── Header comments ─────────────────────────────────────────────────────
	writeln(&b, fmt.Sprintf("## conn_%d: %s | %s | status=%s", connID, name, domain, status))
	originStr := strings.Join(originHosts, ",")
	writeln(&b, fmt.Sprintf("## origin=%s:%d | tls=%s", originStr, originPort, tlsMode))
	writeln(&b, fmt.Sprintf("## Generated at: %sZ", time.Now().UTC().Format("2006-01-02T15:04:05.999999")))
	writeln(&b, "")

	// ── Upstream block ───────────────────────────────────────────────────────
	for _, l := range emitUpstream(connID, originHosts, originPort) {
		writeln(&b, l)
	}
	writeln(&b, "")

	// ── Plain HTTP server block ──────────────────────────────────────────────
	writeln(&b, "server {")
	writeln(&b, "    listen 80;")
	writeln(&b, fmt.Sprintf("    server_name %s;", domain))
	writeln(&b, "    if ($http_x_waf_loop) { return 508; }")
	writeln(&b, "")
	writeln(&b, "    access_log /var/log/angie/geoip.log with_geoip_json;")
	writeln(&b, "    access_log /var/log/angie/access.log combined;")
	writeln(&b, "")
	if crowdsecActive {
		writeln(&b, blockedIPsInclude)
	}
	writeln(&b, "")
	for _, l := range emitModsecState(modsecState) {
		writeln(&b, l)
	}
	writeln(&b, "")
	writeln(&b, "    location ^~ /.well-known/acme-challenge/ {")
	writeln(&b, fmt.Sprintf("        root %s;", acmeRoot))
	writeln(&b, "        try_files $uri =404;")
	writeln(&b, "    }")
	writeln(&b, "")

	if hasCert {
		// Active: port-80 block proxies to loopback HTTPS redirect sink.
		writeln(&b, "    location / {")
		for _, l := range emitGeoIPDeny(geoipDenied) {
			writeln(&b, l)
		}
		writeln(&b, "        proxy_pass http://127.0.0.1:8082;")
		writeln(&b, "        proxy_set_header Host $host;")
		writeln(&b, "        proxy_http_version 1.1;")
		writeln(&b, "    }")
	} else {
		// Pre-active: proxy everything directly (site works during DNS/cert provisioning).
		writeln(&b, "    location /socket.io/ {")
		writeln(&b, "        modsecurity off;")
		for _, l := range emitGeoIPDeny(geoipDenied) {
			writeln(&b, l)
		}
		for _, l := range proxyBlock {
			writeln(&b, l)
		}
		writeln(&b, "    }")
		writeln(&b, "")
		writeln(&b, "    location / {")
		for _, l := range emitGeoIPDeny(geoipDenied) {
			writeln(&b, l)
		}
		for _, l := range proxyBlock {
			writeln(&b, l)
		}
		writeln(&b, "    }")
	}
	writeln(&b, "}")

	// ── TLS server block (active only) ───────────────────────────────────────
	if hasCert {
		writeln(&b, "")
		writeln(&b, "server {")

		// listen 443 ssl is always present regardless of h1/h2/h3 choice
		writeln(&b, "    listen 443 ssl;")

		if contains(httpVersions, "h2") {
			writeln(&b, "    http2 on;")
		}
		if contains(httpVersions, "h3") {
			writeln(&b, "    listen 443 quic;")
			writeln(&b, "    http3 on;")
			writeln(&b, "    add_header Alt-Svc 'h3=\":443\"; ma=86400' always;")
		}

		writeln(&b, fmt.Sprintf("    server_name %s;", domain))
		writeln(&b, "    if ($http_x_waf_loop) { return 508; }")
		writeln(&b, fmt.Sprintf("    ssl_certificate     %s;", *cfg.SSLCertPath))
		writeln(&b, fmt.Sprintf("    ssl_certificate_key %s;", *cfg.SSLKeyPath))

		if emitHSTS {
			writeln(&b, `    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`)
		} else {
			writeln(&b, "    # HSTS suppressed: cert is self-signed; emitting it would lock browsers out.")
		}

		writeln(&b, "")
		writeln(&b, "    access_log /var/log/angie/geoip.log with_geoip_json;")
		writeln(&b, "    access_log /var/log/angie/access.log combined;")

		if crowdsecActive {
			writeln(&b, blockedIPsInclude)
		}
		writeln(&b, "")

		for _, l := range emitModsecState(modsecState) {
			writeln(&b, l)
		}

		comp := emitCompressionOverrides(compression)
		if len(comp) > 0 {
			writeln(&b, "")
			for _, l := range comp {
				writeln(&b, l)
			}
		}

		writeln(&b, "")
		writeln(&b, "    location /socket.io/ {")
		writeln(&b, "        modsecurity off;")
		for _, l := range emitGeoIPDeny(geoipDenied) {
			writeln(&b, l)
		}
		for _, l := range proxyBlock {
			writeln(&b, l)
		}
		writeln(&b, "    }")

		writeln(&b, "")
		writeln(&b, `    location ~* \.(?:jpg|jpeg|gif|png|ico|css|js|woff2?|svg|webp)$ {`)
		writeln(&b, "        modsecurity off;")
		for _, l := range emitGeoIPDeny(geoipDenied) {
			writeln(&b, l)
		}
		for _, l := range proxyBlock {
			writeln(&b, l)
		}
		writeln(&b, "    }")

		writeln(&b, "")
		writeln(&b, "    location / {")
		for _, l := range emitGeoIPDeny(geoipDenied) {
			writeln(&b, l)
		}
		for _, l := range proxyBlock {
			writeln(&b, l)
		}
		writeln(&b, "    }")

		writeln(&b, "}")
	}

	return b.String(), nil
}

// writeln appends line + "\n" to b.
func writeln(b *strings.Builder, line string) {
	b.WriteString(line)
	b.WriteByte('\n')
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// ── helpers mirroring Python functions ───────────────────────────────────────

func parseHTTPVersions(value string) []string {
	if value == "" {
		return []string{"h1", "h2"}
	}
	var out []string
	seen := make(map[string]bool)
	for _, tok := range strings.Split(value, ",") {
		t := strings.ToLower(strings.TrimSpace(tok))
		if validHTTPVersions[t] && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return []string{"h1", "h2"}
	}
	return out
}

func normCompression(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return "auto"
	}
	if validCompression[v] {
		return v
	}
	return "auto"
}

// emitModsecState mirrors _emit_modsec_state in angie_config.py.
func emitModsecState(state string) []string {
	s := strings.ToLower(state)
	if s == "off" {
		return []string{"    modsecurity off;"}
	}
	engine := "DetectionOnly"
	if s == "blocking" {
		engine = "On"
	}
	return []string{
		"    modsecurity on;",
		fmt.Sprintf("    modsecurity_rules 'SecRuleEngine %s';", engine),
	}
}

// emitGeoIPDeny mirrors _emit_geoip_deny in angie_config.py.
func emitGeoIPDeny(countries []string) []string {
	if len(countries) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var codes []string
	for _, c := range countries {
		upper := strings.ToUpper(strings.TrimSpace(c))
		if upper != "" && !seen[upper] {
			seen[upper] = true
			codes = append(codes, upper)
		}
	}
	if len(codes) == 0 {
		return nil
	}
	sort.Strings(codes)
	pattern := strings.Join(codes, "|")
	return []string{
		fmt.Sprintf(`        if ($geoip2_data_country_code ~ "^(%s)$") { return 403; }`, pattern),
	}
}

// emitCompressionOverrides mirrors _emit_compression_overrides in angie_config.py.
func emitCompressionOverrides(algo string) []string {
	if algo == "auto" {
		return nil
	}
	if algo == "none" {
		return []string{
			"    # compression_algo=none — disable all encoders",
			"    gzip off;",
			"    brotli off;",
			"    zstd off;",
		}
	}
	var others []string
	for _, a := range []string{"gzip", "brotli", "zstd"} {
		if a != algo {
			others = append(others, a)
		}
	}
	out := []string{
		fmt.Sprintf("    # compression_algo=%s — pin encoder, disable others", algo),
		fmt.Sprintf("    %s on;", algo),
	}
	for _, o := range others {
		out = append(out, fmt.Sprintf("    %s off;", o))
	}
	return out
}

// emitUpstream mirrors _emit_upstream in angie_config.py.
func emitUpstream(connID int64, originHosts []string, originPort int) []string {
	if len(originHosts) == 0 {
		return []string{fmt.Sprintf("upstream conn_%d_origin { server 127.0.0.1:1 down; }", connID)}
	}
	lines := []string{fmt.Sprintf("upstream conn_%d_origin {", connID)}
	for _, ip := range originHosts {
		lines = append(lines, fmt.Sprintf("    server %s:%d max_fails=3 fail_timeout=30s;", ip, originPort))
	}
	lines = append(lines, "    keepalive 128;")
	lines = append(lines, "}")
	return lines
}

// emitProxyBlock mirrors _emit_proxy_block in angie_config.py.
// Always uses HTTPS to origin; verify depends on tls_mode.
func emitProxyBlock(connID int64, domain string, tlsMode string) []string {
	verify := "off"
	if tlsMode == "strict" {
		verify = "on"
	}
	lines := []string{
		fmt.Sprintf("        proxy_pass                       https://conn_%d_origin;", connID),
		"        proxy_ssl_server_name            on;",
		fmt.Sprintf("        proxy_ssl_name                   %s;", domain),
		fmt.Sprintf("        proxy_ssl_verify                 %s;", verify),
	}
	if tlsMode == "strict" {
		lines = append(lines, fmt.Sprintf("        proxy_ssl_trusted_certificate    %s;", acmeTrustedCA))
	}
	lines = append(lines,
		fmt.Sprintf("        proxy_set_header Host            %s;", domain),
		"        proxy_set_header X-Real-IP       $remote_addr;",
		"        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"        proxy_set_header X-Forwarded-Proto $scheme;",
		"        proxy_set_header X-WAF-Loop      '1';",
		"        proxy_http_version 1.1;",
		"        proxy_set_header Upgrade         $http_upgrade;",
		"        proxy_set_header Connection      $connection_upgrade;",
		"        proxy_buffering off;",
		"        proxy_request_buffering off;",
		"        proxy_redirect off;",
		"        proxy_read_timeout 3600s;",
		"        proxy_send_timeout 3600s;",
	)
	return lines
}
