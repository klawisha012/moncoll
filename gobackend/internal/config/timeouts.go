package config

import (
	"os"
	"strconv"
	"time"
)

// Timeouts holds I/O deadline budgets. Every value is configurable via a
// WAF_*_SECONDS env var with the documented default below — no deadline is
// hardcoded at a call site.
type Timeouts struct {
	// HTTPRequest bounds an inbound request end-to-end. The deadline is set once
	// on the request context at the gateway and inherited by every downstream
	// hop (gRPC → service → Postgres / ClickHouse / Redis / Centrifugo / outbound
	// HTTP), so a single stuck dependency fails fast instead of piling up
	// goroutines into a cascading failure. Default 30s.
	HTTPRequest time.Duration
	// CrowdSecSync bounds one iteration of the background blocked-IPs sync loop
	// (which has no request context of its own). Default 30s.
	CrowdSecSync time.Duration
}

// LoadTimeouts reads the timeout budget from the environment.
func LoadTimeouts() Timeouts {
	return Timeouts{
		HTTPRequest:  envSeconds("WAF_HTTP_REQUEST_TIMEOUT_SECONDS", 30*time.Second),
		CrowdSecSync: envSeconds("WAF_CROWDSEC_SYNC_TIMEOUT_SECONDS", 30*time.Second),
	}
}

// envSeconds reads an integer number of seconds from key, or returns def when
// unset or invalid (non-numeric / non-positive).
func envSeconds(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Second
}
