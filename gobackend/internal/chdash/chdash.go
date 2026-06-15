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
	"reflect"
	"strings"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"

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
	rc  *redis.Client      // nil if Redis is unavailable
	ex  Executor           // test double if non-nil
	obs Observer           // nil-safe; records ClickHouse call metrics
	sf  singleflight.Group // coalesces concurrent cache-miss executions
}

// Executor is a query runner interface, allowing tests to mock database calls.
type Executor interface {
	Query(ctx context.Context, sql string) ([][]interface{}, error)
	QueryCached(ctx context.Context, sql string) ([][]interface{}, error)
}

// Observer records the duration and error outcome of a ClickHouse call. It is
// satisfied by *observability.Metrics; declared locally so chdash stays
// decoupled from the metrics implementation.
type Observer interface {
	ObserveDB(subsystem, operation string, start time.Time, err error)
}

// NewClient constructs a Client. Best-effort: Redis errors are logged, not
// fatal. The ClickHouse connection is opened per-query (thread-safe). An
// optional Observer instruments ClickHouse calls with duration + error metrics.
func NewClient(obs ...Observer) *Client {
	c := &Client{rc: redisClient()}
	if len(obs) > 0 {
		c.obs = obs[0]
	}
	return c
}

// NewClientWithExecutor constructs a Client wrapping an Executor for testing.
func NewClientWithExecutor(ex Executor) *Client {
	return &Client{ex: ex}
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
	if c.ex != nil {
		return c.ex.Query(ctx, sql)
	}

	conn, err := openClickHouse()
	if err != nil {
		slog.Warn("chdash: clickhouse open failed", "err", err)
		return nil, nil
	}
	defer conn.Close()

	start := time.Now()
	rows, err := conn.Query(ctx, sql)
	if c.obs != nil {
		c.obs.ObserveDB("clickhouse", "query", start, err)
	}
	if err != nil {
		slog.Warn("chdash: clickhouse query failed", "sql", sql, "err", err)
		return nil, nil
	}
	defer rows.Close()

	cols := rows.ColumnTypes()
	var result [][]interface{}
	for rows.Next() {
		// clickhouse-go refuses to scan typed columns into a bare *interface{}
		// ("converting UInt64 to *interface {} is unsupported. try using
		// *uint64"). Allocate a correctly-typed destination per column from the
		// driver's reported ScanType, then unwrap into the generic row. The
		// downstream coercion helpers (toInt64/toFloat64/toString/Scalar) accept
		// these native driver types as well as their JSON-decoded forms.
		ptrs := make([]interface{}, len(cols))
		for i, ct := range cols {
			ptrs[i] = reflect.New(ct.ScanType()).Interface()
		}
		if err := rows.Scan(ptrs...); err != nil {
			slog.Warn("chdash: scan error", "err", err)
			continue
		}
		vals := make([]interface{}, len(cols))
		for i := range ptrs {
			vals[i] = reflect.ValueOf(ptrs[i]).Elem().Interface()
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

	// Cache miss — coalesce concurrent executions of the same query so that a
	// hot key expiring does not stampede ClickHouse: the first caller executes,
	// the rest wait for and share its result. singleflight is in-flight only,
	// which is the right scope for per-process peak concurrency.
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		var (
			result [][]interface{}
			qerr   error
		)
		if c.ex != nil {
			result, qerr = c.ex.QueryCached(ctx, sql)
		} else {
			result, qerr = c.Query(ctx, sql)
		}
		if qerr != nil || result == nil {
			return result, qerr
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
	})
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	return v.([][]interface{}), nil
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

// ─── Domain Models ───────────────────────────────────────────────────────────

type Metrics struct {
	TotalRequests       int64
	TotalRequestsChange float64
	BlockedThreats      int64
	HighSeverityCount   int64
	SystemHealth        float64
	AvgLatencyMs        float64
	ActiveRules         int64
}

type TrafficPoint struct {
	Timestamp time.Time
	Clean     int64
	Malicious int64
}

type GeoipMapPoint struct {
	Longitude   float64
	Latitude    float64
	CountryCode string
	CityName    string
	Hits        int64
}

type UnresolvedIp struct {
	Ip   string
	Hits int64
}

type ThreatOrigins struct {
	TotalBlocks int64
	Origins     []ThreatOrigin
}

type ThreatOrigin struct {
	CountryCode string
	Hits        int64
}

type SecurityEvent struct {
	Timestamp time.Time
	RuleId    string
	ClientIp  string
	Severity  int64
	Path      string
	Message   string
}

type TimelinePoint struct {
	Timestamp time.Time
	Hits      int64
}

type RuleHit struct {
	Rule string
	Hits int64
}

type SeveritySlice struct {
	Severity int64
	Hits     int64
}

type IpHit struct {
	Ip   string
	Hits int64
}

type AnomalyPoint struct {
	Timestamp time.Time
	Score     int64
}

type TagHit struct {
	Tag  string
	Hits int64
}

type UriHit struct {
	Uri  string
	Hits int64
}

type RuleFileHit struct {
	File string
	Hits int64
}

type StatusCodePoint struct {
	Timestamp time.Time
	C2xx      int64
	C3xx      int64
	C4xx      int64
	C5xx      int64
}

type UserAgentHit struct {
	UserAgent string
	Hits      int64
}

type BytesPoint struct {
	Timestamp time.Time
	Bytes     int64
}

type RpsPoint struct {
	Timestamp time.Time
	Rps       float64
}

type CountryHit struct {
	CountryCode string
	Hits        int64
}

type TestTrafficEvent struct {
	Timestamp    time.Time
	RuleId       string
	ClientIp     string
	Uri          string
	Method       string
	Severity     int64
	Message      string
	AnomalyScore int64
}

// ─── Coercion Helpers ────────────────────────────────────────────────────────

func toInt64(v interface{}) int64 {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case int64:
		return x
	case uint64:
		return int64(x) //nolint:gosec
	case uint32:
		return int64(x)
	case int32:
		return int64(x)
	case float64:
		return int64(x)
	case int:
		return int64(x)
	}
	return 0
}

func toFloat64(v interface{}) float64 {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int64:
		return float64(x)
	case uint64:
		return float64(x) //nolint:gosec
	case int:
		return float64(x)
	}
	return 0
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// toTime coerces a row cell into a time.Time. ClickHouse DateTime columns
// arrive as a native time.Time on the cache-miss path, but the Redis cache
// serialises results to JSON, so on a cache hit the same value comes back as an
// RFC3339 string. Both forms must be accepted or every time-keyed widget
// (traffic timeline, RPS, bytes, anomalies) silently drops its rows on cache
// hits and renders empty.
func toTime(v interface{}) (time.Time, bool) {
	switch x := v.(type) {
	case time.Time:
		return x, true
	case string:
		if x == "" {
			return time.Time{}, false
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
			if t, err := time.Parse(layout, x); err == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

func sortTimes(ts []time.Time) {
	for i := 1; i < len(ts); i++ {
		for j := i; j > 0 && ts[j].Before(ts[j-1]); j-- {
			ts[j], ts[j-1] = ts[j-1], ts[j]
		}
	}
}

const TestMarkerHeader = "X-Test-Marker"

func safeMarker(marker string) string {
	marker = strings.ReplaceAll(marker, "'", "")
	marker = strings.ReplaceAll(marker, "\\", "")
	marker = strings.ReplaceAll(marker, "\x00", "")
	return marker
}

// ─── Client Methods ──────────────────────────────────────────────────────────

// GetMetrics gets core dashboard metrics.
func (c *Client) GetMetrics(ctx context.Context, minutes, prevMinutes int, domains []string) (*Metrics, error) {
	nginxFilter := HostFilterNginx(domains)
	wafFilter := HostFilterWAF(domains)

	totalRows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.nginx_access_log WHERE time_local >= now() - INTERVAL %d MINUTE%s",
		minutes, nginxFilter))
	totalRequests := Scalar(totalRows, 0)

	prevRows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.nginx_access_log WHERE time_local >= now() - INTERVAL %d MINUTE AND time_local < now() - INTERVAL %d MINUTE%s",
		prevMinutes, minutes, nginxFilter))
	prevTotal := Scalar(prevRows, 0)

	var totalRequestsChange float64
	if prevTotal > 0 {
		totalRequestsChange = math.Round(float64(totalRequests-prevTotal)/float64(prevTotal)*100*10) / 10
	}

	blockedRows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.waf_audit_log WHERE timestamp >= now() - INTERVAL %d MINUTE%s",
		minutes, wafFilter))
	blockedThreats := Scalar(blockedRows, 0)

	highRows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.waf_audit_log ARRAY JOIN messages AS m WHERE timestamp >= now() - INTERVAL %d MINUTE AND m.severity >= 2%s",
		minutes, wafFilter))
	highSeverity := Scalar(highRows, 0)

	activeRulesRows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT count(DISTINCT m.ruleId) FROM logs.waf_audit_log ARRAY JOIN messages AS m WHERE timestamp >= now() - INTERVAL %d MINUTE%s",
		minutes, wafFilter))
	activeRules := Scalar(activeRulesRows, 0)

	errorRows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.nginx_access_log WHERE time_local >= now() - INTERVAL %d MINUTE AND status >= 500%s",
		minutes, nginxFilter))
	errorResponses := Scalar(errorRows, 0)

	systemHealth := 100.0
	if totalRequests > 0 {
		systemHealth = math.Round(float64(totalRequests-errorResponses)/float64(totalRequests)*100*10) / 10
	}

	return &Metrics{
		TotalRequests:       totalRequests,
		TotalRequestsChange: totalRequestsChange,
		BlockedThreats:      blockedThreats,
		HighSeverityCount:   highSeverity,
		SystemHealth:        systemHealth,
		AvgLatencyMs:        0.0,
		ActiveRules:         activeRules,
	}, nil
}

// GetTraffic gets traffic points over time.
func (c *Client) GetTraffic(ctx context.Context, minutes int, timeFunc string, domains []string) ([]TrafficPoint, error) {
	nginxFilter := HostFilterNginx(domains)
	wafFilter := HostFilterWAF(domains)

	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT %s(time_local) AS t, count() AS total FROM logs.nginx_access_log WHERE time_local >= now() - INTERVAL %d MINUTE%s GROUP BY t ORDER BY t",
		timeFunc, minutes, nginxFilter))
	malRows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT %s(timestamp) AS t, count() AS total FROM logs.waf_audit_log WHERE timestamp >= now() - INTERVAL %d MINUTE%s GROUP BY t ORDER BY t",
		timeFunc, minutes, wafFilter))

	nginxMap := make(map[time.Time]int64)
	malMap := make(map[time.Time]int64)
	allTimes := make(map[time.Time]struct{})

	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		if t, ok := toTime(r[0]); ok {
			nginxMap[t] = toInt64(r[1])
			allTimes[t] = struct{}{}
		}
	}
	for _, r := range malRows {
		if len(r) < 2 {
			continue
		}
		if t, ok := toTime(r[0]); ok {
			malMap[t] = toInt64(r[1])
			allTimes[t] = struct{}{}
		}
	}

	times := make([]time.Time, 0, len(allTimes))
	for t := range allTimes {
		times = append(times, t)
	}
	sortTimes(times)

	points := make([]TrafficPoint, 0, len(times))
	for _, t := range times {
		total := nginxMap[t]
		mal := malMap[t]
		clean := total - mal
		if clean < 0 {
			clean = 0
		}
		points = append(points, TrafficPoint{
			Timestamp: t,
			Clean:     clean,
			Malicious: mal,
		})
	}
	return points, nil
}

// GetGeoipMap gets IP locations for geoip mapping.
func (c *Client) GetGeoipMap(ctx context.Context, minutes int, domains []string) ([]GeoipMapPoint, error) {
	nginxFilter := HostFilterNginx(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT geoip_longitude, geoip_latitude, geoip_country_code, geoip_city_name, count() AS cnt "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE "+
			"AND geoip_latitude != 0 AND geoip_longitude != 0 "+
			"AND geoip_country_code != ''%s "+
			"GROUP BY geoip_longitude, geoip_latitude, geoip_country_code, geoip_city_name "+
			"ORDER BY cnt DESC "+
			"LIMIT 500",
		minutes, nginxFilter))

	var points []GeoipMapPoint
	for _, r := range rows {
		if len(r) < 5 {
			continue
		}
		cc := toString(r[2])
		if cc == "" {
			cc = "UNKNOWN"
		}
		points = append(points, GeoipMapPoint{
			Longitude:   toFloat64(r[0]),
			Latitude:    toFloat64(r[1]),
			CountryCode: cc,
			CityName:    toString(r[3]),
			Hits:        toInt64(r[4]),
		})
	}
	return points, nil
}

// GetGeoipUnresolved gets unresolved IPs.
func (c *Client) GetGeoipUnresolved(ctx context.Context, minutes int, domains []string) ([]UnresolvedIp, error) {
	nginxFilter := HostFilterNginx(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT IPv4NumToString(remote_addr) AS ip, count() AS cnt "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE "+
			"AND toUInt32(remote_addr) != 0 "+
			"AND (geoip_country_code = '' OR geoip_latitude = 0 OR geoip_longitude = 0) "+
			"AND NOT (toUInt32(remote_addr) BETWEEN toUInt32(toIPv4('127.0.0.0')) AND toUInt32(toIPv4('127.255.255.255'))) "+
			"AND NOT (toUInt32(remote_addr) BETWEEN toUInt32(toIPv4('10.0.0.0')) AND toUInt32(toIPv4('10.255.255.255'))) "+
			"AND NOT (toUInt32(remote_addr) BETWEEN toUInt32(toIPv4('172.16.0.0')) AND toUInt32(toIPv4('172.31.255.255'))) "+
			"AND NOT (toUInt32(remote_addr) BETWEEN toUInt32(toIPv4('192.168.0.0')) AND toUInt32(toIPv4('192.168.255.255'))) "+
			"AND NOT (toUInt32(remote_addr) BETWEEN toUInt32(toIPv4('169.254.0.0')) AND toUInt32(toIPv4('169.254.255.255'))) "+
			"%s "+
			"GROUP BY remote_addr "+
			"ORDER BY cnt DESC "+
			"LIMIT 30",
		minutes, nginxFilter))

	var ips []UnresolvedIp
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		ips = append(ips, UnresolvedIp{
			Ip:   toString(r[0]),
			Hits: toInt64(r[1]),
		})
	}
	return ips, nil
}

// GetThreatOrigins gets WAF blocks by country.
func (c *Client) GetThreatOrigins(ctx context.Context, minutes int, domains []string) (*ThreatOrigins, error) {
	wafFilter := HostFilterWAF(domains)

	totalRows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.waf_audit_log WHERE timestamp >= now() - INTERVAL %d MINUTE%s",
		minutes, wafFilter))
	totalBlocks := Scalar(totalRows, 0)
	if totalBlocks == 0 {
		return &ThreatOrigins{TotalBlocks: 0, Origins: []ThreatOrigin{}}, nil
	}

	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT n.geoip_country_code AS country_code, count() AS cnt "+
			"FROM logs.waf_audit_log AS w "+
			"INNER JOIN ("+
			"  SELECT toString(remote_addr) AS ip, any(geoip_country_code) AS geoip_country_code "+
			"  FROM logs.nginx_access_log "+
			"  WHERE time_local >= now() - INTERVAL %d MINUTE "+
			"  AND toString(remote_addr) IN ("+
			"    SELECT DISTINCT toString(client_ip) FROM logs.waf_audit_log "+
			"    WHERE timestamp >= now() - INTERVAL %d MINUTE%s"+
			"  ) GROUP BY ip"+
			") AS n ON toString(w.client_ip) = n.ip "+
			"WHERE w.timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY n.geoip_country_code "+
			"ORDER BY cnt DESC "+
			"LIMIT 10",
		minutes, minutes, wafFilter, minutes, wafFilter))

	if rows == nil {
		return &ThreatOrigins{
			TotalBlocks: totalBlocks,
			Origins: []ThreatOrigin{
				{CountryCode: "UNKNOWN", Hits: totalBlocks},
			},
		}, nil
	}

	var origins []ThreatOrigin
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		cc := toString(r[0])
		if cc == "" {
			cc = "UNKNOWN"
		}
		origins = append(origins, ThreatOrigin{
			CountryCode: cc,
			Hits:        toInt64(r[1]),
		})
	}
	return &ThreatOrigins{TotalBlocks: totalBlocks, Origins: origins}, nil
}

// GetEvents gets security events list.
func (c *Client) GetEvents(ctx context.Context, minutes int, severityFilter string, domains []string, limit int64) ([]SecurityEvent, error) {
	wafFilter := HostFilterWAF(domains)
	severitySQL := ""
	switch severityFilter {
	case "high":
		severitySQL = "AND m.severity >= 2"
	case "critical":
		severitySQL = "AND m.severity >= 3"
	}

	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT w.timestamp, m.ruleId, w.client_ip, m.severity, w.request_uri, m.message "+
			"FROM logs.waf_audit_log AS w "+
			"ARRAY JOIN messages AS m "+
			"WHERE w.timestamp >= now() - INTERVAL %d MINUTE "+
			"%s%s "+
			"ORDER BY w.timestamp DESC "+
			"LIMIT %d",
		minutes, severitySQL, wafFilter, limit))

	var events []SecurityEvent
	for _, r := range rows {
		if len(r) < 6 {
			continue
		}
		var ts time.Time
		if t, ok := toTime(r[0]); ok {
			ts = t
		}
		events = append(events, SecurityEvent{
			Timestamp: ts,
			RuleId:    toString(r[1]),
			ClientIp:  toString(r[2]),
			Severity:  toInt64(r[3]),
			Path:      toString(r[4]),
			Message:   toString(r[5]),
		})
	}
	return events, nil
}

// GetWafEventsTimeline gets timeline of WAF event hits.
func (c *Client) GetWafEventsTimeline(ctx context.Context, minutes int, domains []string) ([]TimelinePoint, error) {
	wafFilter := HostFilterWAF(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT toStartOfMinute(timestamp) AS t, count() AS hits "+
			"FROM logs.waf_audit_log "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY t ORDER BY t",
		minutes, wafFilter))

	var points []TimelinePoint
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		var ts time.Time
		if t, ok := toTime(r[0]); ok {
			ts = t
		}
		points = append(points, TimelinePoint{
			Timestamp: ts,
			Hits:      toInt64(r[1]),
		})
	}
	return points, nil
}

// GetTopRules gets rule hits breakdown.
func (c *Client) GetTopRules(ctx context.Context, minutes int, domains []string) ([]RuleHit, error) {
	wafFilter := HostFilterWAF(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT m.ruleId AS rule, count() AS hits FROM logs.waf_audit_log "+
			"ARRAY JOIN messages AS m "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY rule ORDER BY hits DESC LIMIT 10",
		minutes, wafFilter))

	var rules []RuleHit
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		rules = append(rules, RuleHit{
			Rule: toString(r[0]),
			Hits: toInt64(r[1]),
		})
	}
	return rules, nil
}

// GetSeverityDistribution gets hits count grouped by severity.
func (c *Client) GetSeverityDistribution(ctx context.Context, minutes int, domains []string) ([]SeveritySlice, error) {
	wafFilter := HostFilterWAF(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT m.severity AS sev, count() AS hits FROM logs.waf_audit_log "+
			"ARRAY JOIN messages AS m "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY sev ORDER BY sev",
		minutes, wafFilter))

	var slices []SeveritySlice
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		slices = append(slices, SeveritySlice{
			Severity: toInt64(r[0]),
			Hits:     toInt64(r[1]),
		})
	}
	return slices, nil
}

// GetTopAttackingIps gets IPs with highest WAF block counts.
func (c *Client) GetTopAttackingIps(ctx context.Context, minutes int, domains []string) ([]IpHit, error) {
	wafFilter := HostFilterWAF(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT client_ip, count() AS hits FROM logs.waf_audit_log "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY client_ip ORDER BY hits DESC LIMIT 15",
		minutes, wafFilter))

	var ips []IpHit
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		ips = append(ips, IpHit{
			Ip:   toString(r[0]),
			Hits: toInt64(r[1]),
		})
	}
	return ips, nil
}

// GetAnomalyScore gets maximum anomaly score over time.
func (c *Client) GetAnomalyScore(ctx context.Context, minutes int, domains []string) ([]AnomalyPoint, error) {
	wafFilter := HostFilterWAF(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT toStartOfMinute(timestamp) AS t, max(anomaly_score) AS score "+
			"FROM logs.waf_audit_log "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY t ORDER BY t",
		minutes, wafFilter))

	var points []AnomalyPoint
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		var ts time.Time
		if t, ok := toTime(r[0]); ok {
			ts = t
		}
		points = append(points, AnomalyPoint{
			Timestamp: ts,
			Score:     toInt64(r[1]),
		})
	}
	return points, nil
}

// GetTopTags gets tag hits breakdown.
func (c *Client) GetTopTags(ctx context.Context, minutes int, domains []string) ([]TagHit, error) {
	wafFilter := HostFilterWAF(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT tag, count() AS hits FROM logs.waf_audit_log "+
			"ARRAY JOIN messages_tags AS tags ARRAY JOIN tags AS tag "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY tag ORDER BY hits DESC LIMIT 10",
		minutes, wafFilter))

	var tags []TagHit
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		tags = append(tags, TagHit{
			Tag:  toString(r[0]),
			Hits: toInt64(r[1]),
		})
	}
	return tags, nil
}

// GetTopUris gets URIs with highest block counts.
func (c *Client) GetTopUris(ctx context.Context, minutes int, domains []string) ([]UriHit, error) {
	wafFilter := HostFilterWAF(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT request_uri AS uri, count() AS hits FROM logs.waf_audit_log "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY uri ORDER BY hits DESC LIMIT 10",
		minutes, wafFilter))

	var uris []UriHit
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		uris = append(uris, UriHit{
			Uri:  toString(r[0]),
			Hits: toInt64(r[1]),
		})
	}
	return uris, nil
}

// GetTopRuleFiles gets top rule files triggered.
func (c *Client) GetTopRuleFiles(ctx context.Context, minutes int, domains []string) ([]RuleFileHit, error) {
	wafFilter := HostFilterWAF(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT replaceRegexpOne(replaceRegexpOne(m.file, '\\.conf$', ''), '^.*/', '') AS rf, "+
			"count() AS hits FROM logs.waf_audit_log "+
			"ARRAY JOIN messages AS m "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY rf ORDER BY hits DESC LIMIT 10",
		minutes, wafFilter))

	var files []RuleFileHit
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		files = append(files, RuleFileHit{
			File: toString(r[0]),
			Hits: toInt64(r[1]),
		})
	}
	return files, nil
}

// GetStatusCodes gets status code distribution over time.
func (c *Client) GetStatusCodes(ctx context.Context, minutes int, domains []string) ([]StatusCodePoint, error) {
	nginxFilter := HostFilterNginx(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT toStartOfMinute(time_local) AS t, "+
			"countIf(status >= 200 AND status < 300) AS c2xx, "+
			"countIf(status >= 300 AND status < 400) AS c3xx, "+
			"countIf(status >= 400 AND status < 500) AS c4xx, "+
			"countIf(status >= 500) AS c5xx "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY t ORDER BY t",
		minutes, nginxFilter))

	var points []StatusCodePoint
	for _, r := range rows {
		if len(r) < 5 {
			continue
		}
		var ts time.Time
		if t, ok := toTime(r[0]); ok {
			ts = t
		}
		points = append(points, StatusCodePoint{
			Timestamp: ts,
			C2xx:      toInt64(r[1]),
			C3xx:      toInt64(r[2]),
			C4xx:      toInt64(r[3]),
			C5xx:      toInt64(r[4]),
		})
	}
	return points, nil
}

// GetTopUserAgents gets top user agents.
func (c *Client) GetTopUserAgents(ctx context.Context, minutes int, domains []string) ([]UserAgentHit, error) {
	nginxFilter := HostFilterNginx(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT http_user_agent AS ua, count() AS hits "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY ua ORDER BY hits DESC LIMIT 15",
		minutes, nginxFilter))

	var agents []UserAgentHit
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		agents = append(agents, UserAgentHit{
			UserAgent: toString(r[0]),
			Hits:      toInt64(r[1]),
		})
	}
	return agents, nil
}

// GetTrafficVolume gets bytes sent over time.
func (c *Client) GetTrafficVolume(ctx context.Context, minutes int, domains []string) ([]BytesPoint, error) {
	nginxFilter := HostFilterNginx(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT toStartOfMinute(time_local) AS t, sum(body_bytes_sent) AS bytes "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY t ORDER BY t",
		minutes, nginxFilter))

	var points []BytesPoint
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		var ts time.Time
		if t, ok := toTime(r[0]); ok {
			ts = t
		}
		points = append(points, BytesPoint{
			Timestamp: ts,
			Bytes:     toInt64(r[1]),
		})
	}
	return points, nil
}

// GetRequestsPerSecond gets requests per second over time.
func (c *Client) GetRequestsPerSecond(ctx context.Context, minutes int, metric, timeFunc string, domains []string) ([]RpsPoint, error) {
	nginxFilter := HostFilterNginx(domains)
	var sql string
	if metric == "volume" {
		sql = fmt.Sprintf(
			"SELECT %s(time_local) AS t, count() AS rps "+
				"FROM logs.nginx_access_log "+
				"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
				"GROUP BY t ORDER BY t",
			timeFunc, minutes, nginxFilter)
	} else {
		sql = fmt.Sprintf(
			"SELECT %s(time_local) AS t, max(rps_sec) AS rps "+
				"FROM ("+
				"  SELECT time_local, count() AS rps_sec "+
				"  FROM logs.nginx_access_log "+
				"  WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
				"  GROUP BY time_local"+
				") GROUP BY t ORDER BY t",
			timeFunc, minutes, nginxFilter)
	}

	rows, _ := c.QueryCached(ctx, sql)

	var points []RpsPoint
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		var ts time.Time
		if t, ok := toTime(r[0]); ok {
			ts = t
		}
		points = append(points, RpsPoint{
			Timestamp: ts,
			Rps:       toFloat64(r[1]),
		})
	}
	return points, nil
}

// GetRequestsByCountry gets requests grouped by country.
func (c *Client) GetRequestsByCountry(ctx context.Context, minutes int, domains []string) ([]CountryHit, error) {
	nginxFilter := HostFilterNginx(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT if(geoip_country_code = '' OR geoip_country_code IS NULL, 'Unknown', geoip_country_code) "+
			"AS country, count() AS hits FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY country ORDER BY hits DESC LIMIT 15",
		minutes, nginxFilter))

	var countries []CountryHit
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		countries = append(countries, CountryHit{
			CountryCode: toString(r[0]),
			Hits:        toInt64(r[1]),
		})
	}
	return countries, nil
}

// GetTopClientIps gets client IPs with highest request counts.
func (c *Client) GetTopClientIps(ctx context.Context, minutes int, domains []string) ([]IpHit, error) {
	nginxFilter := HostFilterNginx(domains)
	rows, _ := c.QueryCached(ctx, fmt.Sprintf(
		"SELECT toString(remote_addr) AS ip, count() AS hits "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY ip ORDER BY hits DESC LIMIT 15",
		minutes, nginxFilter))

	var ips []IpHit
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		ips = append(ips, IpHit{
			Ip:   toString(r[0]),
			Hits: toInt64(r[1]),
		})
	}
	return ips, nil
}

// GetTestTraffic gets WAF events matching a test marker.
func (c *Client) GetTestTraffic(ctx context.Context, marker string, domains []string) ([]TestTrafficEvent, error) {
	wafFilter := HostFilterWAF(domains)
	safe := safeMarker(marker)

	rows, _ := c.Query(ctx, fmt.Sprintf(
		"SELECT w.timestamp, m.ruleId, w.client_ip, w.request_uri, "+
			"w.request_method, m.severity, m.message, w.anomaly_score "+
			"FROM logs.waf_audit_log AS w "+
			"LEFT ARRAY JOIN messages AS m "+
			"WHERE w.request_headers['%s'] = '%s' "+
			"AND w.timestamp >= now() - INTERVAL 1 HOUR%s "+
			"ORDER BY w.timestamp",
		TestMarkerHeader, safe, wafFilter))

	var events []TestTrafficEvent
	for _, r := range rows {
		if len(r) < 8 {
			continue
		}
		var ts time.Time
		if t, ok := toTime(r[0]); ok {
			ts = t
		}
		events = append(events, TestTrafficEvent{
			Timestamp:    ts,
			RuleId:       toString(r[1]),
			ClientIp:     toString(r[2]),
			Uri:          toString(r[3]),
			Method:       toString(r[4]),
			Severity:     toInt64(r[5]),
			Message:      toString(r[6]),
			AnomalyScore: toInt64(r[7]),
		})
	}
	return events, nil
}
