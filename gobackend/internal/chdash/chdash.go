// Package chdash provides the ClickHouse analytics client, Redis TTL cache,
// tenant-scoping host-filter logic, and SQL fragment helpers for the dashboard.
//
// Security contract
// -----------------
// DomainsForConnection returns either nil (no filter — admin only) or a
// []string (possibly empty). An empty slice is NOT the same as nil:
//   - nil   → _host_filter_nginx / _host_filter_waf return "" (no WHERE clause)
//   - empty → the filter expands to "AND host IN ('__none__')" which matches
//             nothing. This is the "fail closed" path for clients with zero
//             connections, ensuring they see an empty dashboard rather than
//             the entire platform's traffic.
//
// NEVER return nil for a caller with a non-nil tenantID. Tests enforce this.
package chdash

import (
	"context"
	"crypto/md5" //nolint:gosec // MD5 used only as a cache key hash, not for security
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strings"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/redis/go-redis/v9"

	"github.com/zwarder/waf/gobackend/internal/store"
)

// noDomainsSentinel is the placeholder inserted into IN-lists when the domain
// list is empty. It is guaranteed to never match a real host header.
const noDomainsSentinel = "__none__"

// queryTTL is the Redis cache TTL for ClickHouse query results.
// Mirrors Python: float(os.getenv("DASHBOARD_QUERY_TTL", "2")) seconds.
var queryTTL = func() time.Duration {
	if v := os.Getenv("DASHBOARD_QUERY_TTL"); v != "" {
		var f float64
		if _, err := fmt.Sscanf(v, "%f", &f); err == nil && f > 0 {
			return time.Duration(f * float64(time.Second))
		}
	}
	return 2 * time.Second
}()

// ─── ConnectionSource ────────────────────────────────────────────────────────

// ConnectionSource is the interface the tenant-scoping logic depends on.
// *store.Store satisfies it via its ListConnections method.
type ConnectionSource interface {
	ListConnections(ctx context.Context) ([]store.Connection, error)
}

// ─── ClickHouse client ───────────────────────────────────────────────────────

// openClickHouse creates a fresh clickhouse-go/v2 connection from env vars.
// Each call returns a new connection; callers must call conn.Close() when done.
//
// Env vars (matching Python _get_client exactly):
//
//	CLICKHOUSE_ENDPOINT      http://clickhouse:8123  (http URL; host is extracted)
//	CLICKHOUSE_NATIVE_PORT   9000
//	CLICKHOUSE_USER          default
//	CLICKHOUSE_PASSWORD      (empty)
//	CLICKHOUSE_DB            logs
func openClickHouse() (clickhouse.Conn, error) {
	httpEndpoint := getEnvDefault("CLICKHOUSE_ENDPOINT", "http://clickhouse:8123")
	// Strip scheme, e.g. "http://clickhouse:8123" → "clickhouse:8123".
	if idx := strings.Index(httpEndpoint, "://"); idx != -1 {
		httpEndpoint = httpEndpoint[idx+3:]
	}
	// Strip port from host, e.g. "clickhouse:8123" → "clickhouse".
	host := httpEndpoint
	if idx := strings.LastIndex(httpEndpoint, ":"); idx != -1 {
		host = httpEndpoint[:idx]
	}

	nativePort := 9000
	if v := os.Getenv("CLICKHOUSE_NATIVE_PORT"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &nativePort); err != nil {
			nativePort = 9000
		}
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", host, nativePort)},
		Auth: clickhouse.Auth{
			Database: getEnvDefault("CLICKHOUSE_DB", "logs"),
			Username: getEnvDefault("CLICKHOUSE_USER", "default"),
			Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		},
		DialTimeout:     5 * time.Second,
		MaxOpenConns:    1,
		MaxIdleConns:    0,
		ConnMaxLifetime: 0, // single-use
	})
	return conn, err
}

// ─── Redis cache ─────────────────────────────────────────────────────────────

// redisClient returns a best-effort Redis client from REDIS_URL.
// Returns nil (and logs) if the URL is missing or the client cannot be created.
// The returned client is lazy-connected — errors surface at first use.
func redisClient() *redis.Client {
	url := getEnvDefault("REDIS_URL", "redis://redis:6379/0")
	opt, err := redis.ParseURL(url)
	if err != nil {
		slog.Warn("chdash: failed to parse REDIS_URL", "err", err)
		return nil
	}
	opt.DialTimeout = 2 * time.Second
	opt.ReadTimeout = 2 * time.Second
	opt.WriteTimeout = 2 * time.Second
	return redis.NewClient(opt)
}

// ─── Query helpers ────────────────────────────────────────────────────────────

// Client bundles a ClickHouse connection factory and an optional Redis client
// so endpoint handlers can call Query / QueryCached without knowing the
// connection details.
type Client struct {
	rc *redis.Client // nil if Redis is unavailable
}

// NewClient constructs a Client. Best-effort: Redis errors are logged, not
// fatal. The ClickHouse connection is opened per-query (thread-safe).
func NewClient() *Client {
	return &Client{rc: redisClient()}
}

// queryResult is what we serialize into Redis. ClickHouse rows are
// [][]interface{}, so we JSON-encode/decode via json.RawMessage round-trip.
type queryResult [][]interface{}

// cacheKey returns the Redis key for a query (MD5 of the SQL string).
func cacheKey(query string) string {
	//nolint:gosec // MD5 used only as a non-cryptographic cache key
	sum := md5.Sum([]byte(query))
	return "waf:clickhouse:" + hex.EncodeToString(sum[:])
}

// Query executes a ClickHouse query WITHOUT the Redis cache (mirrors Python
// _direct_execute). Returns (rows, nil) on success, (nil, nil) on CH error
// (errors are logged, not propagated — dashboard degrades gracefully).
func (c *Client) Query(ctx context.Context, sql string) ([][]interface{}, error) {
	conn, err := openClickHouse()
	if err != nil {
		slog.Warn("chdash: clickhouse open failed", "err", err)
		return nil, nil
	}
	defer conn.Close()

	rows, err := conn.Query(ctx, sql)
	if err != nil {
		slog.Warn("chdash: clickhouse query failed", "sql", sql, "err", err)
		return nil, nil
	}
	defer rows.Close()

	cols := rows.ColumnTypes()
	var result [][]interface{}
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			slog.Warn("chdash: scan error", "err", err)
			continue
		}
		result = append(result, vals)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("chdash: rows error", "err", err)
		return nil, nil
	}
	return result, nil
}

// QueryCached executes a ClickHouse query with a short distributed TTL cache
// in Redis. Mirrors Python _safe_execute. Cache is best-effort: Redis
// unavailability or errors fall through to a direct ClickHouse call.
func (c *Client) QueryCached(ctx context.Context, sql string) ([][]interface{}, error) {
	key := cacheKey(sql)

	// Try cache read.
	if c.rc != nil {
		if raw, err := c.rc.Get(ctx, key).Bytes(); err == nil {
			var cached [][]interface{}
			if err2 := json.Unmarshal(raw, &cached); err2 == nil {
				return cached, nil
			}
		} else if err != redis.Nil {
			slog.Warn("chdash: redis get failed", "err", err)
		}
	}

	// Cache miss — execute.
	result, err := c.Query(ctx, sql)
	if err != nil || result == nil {
		return result, err
	}

	// Write to cache (best-effort).
	if c.rc != nil {
		if raw, err2 := json.Marshal(result); err2 == nil {
			if err3 := c.rc.Set(ctx, key, raw, queryTTL).Err(); err3 != nil {
				slog.Warn("chdash: redis set failed", "err", err3)
			}
		}
	}

	return result, nil
}

// Scalar extracts the first cell of the first row as an int64.
// Returns defaultVal on empty result or type error. Mirrors Python _scalar.
func Scalar(rows [][]interface{}, defaultVal int64) int64 {
	if len(rows) == 0 || len(rows[0]) == 0 {
		return defaultVal
	}
	switch v := rows[0][0].(type) {
	case int64:
		return v
	case uint64:
		return int64(v) //nolint:gosec
	case float64:
		return int64(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
	}
	return defaultVal
}

// ─── Time helpers ─────────────────────────────────────────────────────────────

// ClampMinutes converts hours to a clamped minute count.
// Mirrors Python _clamp_minutes: hours clamped to [0.0167, 8760], then
// converted to int minutes with a minimum of 1.
func ClampMinutes(hours float64) int {
	hours = math.Max(0.0167, math.Min(hours, 8760))
	m := int(hours * 60)
	if m < 1 {
		return 1
	}
	return m
}

// ISO formats a time.Time as an ISO-8601 string. Mirrors Python _iso.
func ISO(t time.Time) string {
	return t.Format(time.RFC3339Nano)
}

// ─── Tenant-scoping ───────────────────────────────────────────────────────────

// DomainsForConnection resolves the host-filter domain list for a dashboard
// query. The return-value contract (critical for security):
//
//	connectionID  tenantID  Returns
//	nil           nil       nil        — no filter (admin: see all traffic)
//	nil           non-nil   []string   — all enabled domains of that tenant;
//	                                     empty slice if the tenant has none
//	non-nil       nil       []string   — that connection's domain; empty if not found
//	non-nil       non-nil   []string   — that connection's domain IFF the tenant
//	                                     owns it AND it is enabled; else empty
//
// nil vs []string{} distinction is the security crux:
//   - nil   → no SQL filter (admin only)
//   - empty → SQL filter "AND host IN ('__none__')" matching nothing
//
// A non-nil tenantID NEVER returns nil.
func DomainsForConnection(
	ctx context.Context,
	src ConnectionSource,
	connectionID *int64,
	tenantID *int64,
) ([]string, error) {
	// Admin with no connection filter: no filter at all.
	if connectionID == nil && tenantID == nil {
		return nil, nil
	}

	conns, err := src.ListConnections(ctx)
	if err != nil {
		// Fail closed for clients, fail open for admins (same as Python).
		if tenantID != nil {
			return []string{}, fmt.Errorf("chdash: list connections: %w", err)
		}
		return nil, fmt.Errorf("chdash: list connections: %w", err)
	}

	if connectionID != nil {
		// Admin or client requesting a specific connection.
		for _, c := range conns {
			if c.ID != *connectionID {
				continue
			}
			// Connection must be enabled.
			if !c.Enabled {
				return []string{}, nil
			}
			// If a tenantID is set (client), the connection must belong to that tenant.
			if tenantID != nil && c.TenantID != *tenantID {
				return []string{}, nil
			}
			if c.Domain == "" {
				return []string{}, nil
			}
			return []string{c.Domain}, nil
		}
		// Connection not found.
		return []string{}, nil
	}

	// connectionID == nil, tenantID != nil: aggregate all enabled domains for
	// that tenant. Return empty slice (NOT nil) if there are none.
	var domains []string
	for _, c := range conns {
		if c.TenantID == *tenantID && c.Enabled && c.Domain != "" {
			domains = append(domains, c.Domain)
		}
	}
	if domains == nil {
		domains = []string{} // ensure non-nil for security contract
	}
	return domains, nil
}

// ─── Host filters ─────────────────────────────────────────────────────────────

// QuoteDomains renders an SQL IN-list, stripping characters that could break
// ClickHouse string parsing (single quotes, backslashes, NUL bytes).
// Mirrors Python _quote_domains exactly.
func QuoteDomains(domains []string) string {
	var cleaned []string
	for _, d := range domains {
		if d == "" {
			continue
		}
		d = strings.ReplaceAll(d, "'", "")
		d = strings.ReplaceAll(d, "\\", "")
		d = strings.ReplaceAll(d, "\x00", "")
		cleaned = append(cleaned, d)
	}
	if len(cleaned) == 0 {
		return "('" + noDomainsSentinel + "')"
	}
	var sb strings.Builder
	sb.WriteString("(")
	for i, d := range cleaned {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("'")
		sb.WriteString(d)
		sb.WriteString("'")
	}
	sb.WriteString(")")
	return sb.String()
}

// HostFilterNginx builds the nginx_access_log host WHERE fragment.
//
//	nil    → ""                             (admin: no filter)
//	[]     → " AND host IN ('__none__')"    (client with zero domains)
//	[d…]   → " AND host IN ('d1', 'd2')"
//
// Mirrors Python _host_filter_nginx exactly (column name: host).
func HostFilterNginx(domains []string) string {
	if domains == nil {
		return ""
	}
	return " AND host IN " + QuoteDomains(domains)
}

// HostFilterWAF builds the WAF audit log host WHERE fragment.
//
//	nil    → ""
//	[]     → " AND request_headers['Host'] IN ('__none__')"
//	[d…]   → " AND request_headers['Host'] IN ('d1', 'd2')"
//
// Mirrors Python _host_filter_waf exactly (column: request_headers['Host']).
func HostFilterWAF(domains []string) string {
	if domains == nil {
		return ""
	}
	return " AND request_headers['Host'] IN " + QuoteDomains(domains)
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
