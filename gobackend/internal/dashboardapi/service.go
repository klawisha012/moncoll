// Package dashboardapi implements the DashboardService gRPC server, faithfully
// porting backend/src/dashboard/service.py into Go.
//
// Security contract: every RPC extracts the caller's tenantID from context and
// passes it to chdash.DomainsForConnection before constructing any SQL. A
// non-nil tenantID NEVER yields a nil domain list (which would mean "no
// filter"); it yields either a list of the tenant's domains or an empty slice
// that expands to IN ('__none__') — matching nothing. This is verified by the
// test suite.
package dashboardapi

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dashboardv1 "github.com/zwarder/waf/gobackend/gen/dashboard/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/chdash"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// Executor is the query interface used by every RPC handler. It is satisfied by
// *chdash.Client and by fakeExecutor in tests.
type Executor interface {
	// Query executes without the Redis cache (for test-traffic / fresh data).
	Query(ctx context.Context, sql string) ([][]interface{}, error)
	// QueryCached executes with the Redis TTL cache.
	QueryCached(ctx context.Context, sql string) ([][]interface{}, error)
}

// DomainResolver is the tenant-scoping interface. It is satisfied by
// *chdash.Client (indirectly via the helper below) and by fakeDomainResolver
// in tests.
type DomainResolver interface {
	DomainsForConnection(ctx context.Context, connID *int64, tenantID *int64) ([]string, error)
}

// storeResolver wraps *store.Store to satisfy DomainResolver via
// chdash.DomainsForConnection.
type storeResolver struct{ s *store.Store }

func (r *storeResolver) DomainsForConnection(ctx context.Context, connID *int64, tenantID *int64) ([]string, error) {
	return chdash.DomainsForConnection(ctx, r.s, connID, tenantID)
}

// ─── Service ─────────────────────────────────────────────────────────────────

// Service implements dashboardv1.DashboardServiceServer.
type Service struct {
	dashboardv1.UnimplementedDashboardServiceServer
	ex  Executor
	dr  DomainResolver
}

// New constructs a Service with a real *chdash.Client and *store.Store.
func New(ch *chdash.Client, st *store.Store) *Service {
	return &Service{ex: ch, dr: &storeResolver{s: st}}
}

// newWithDeps constructs a Service with injected executor + resolver (for tests).
func newWithDeps(ex Executor, dr DomainResolver) *Service {
	return &Service{ex: ex, dr: dr}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// connIDFromWrapper converts a *wrapperspb.Int64Value to *int64 (nil if nil).
func connIDFromWrapper(w interface{ GetValue() int64 }) *int64 {
	if w == nil {
		return nil
	}
	// The wrapper itself might be a nil proto pointer; check via interface.
	// We rely on the generated proto accessor: if GetConnectionId() returns nil,
	// w is nil here.
	v := w.GetValue()
	return &v
}

// tenantID extracts the caller's tenantID from the context (nil for admin).
func tenantID(ctx context.Context) *int64 {
	id, ok := auth.IdentityFromContext(ctx)
	if !ok || id == nil {
		return nil
	}
	return id.TenantID
}

// domains resolves host-filter domains, logging errors and returning an empty
// list for clients (fail-closed) or nil for admins (fail-open) on error.
func (s *Service) domains(ctx context.Context, connID *int64, tid *int64) []string {
	d, err := s.dr.DomainsForConnection(ctx, connID, tid)
	if err != nil {
		slog.Warn("dashboardapi: DomainsForConnection error", "err", err)
		if tid != nil {
			return []string{} // fail-closed for clients
		}
		return nil // fail-open for admins
	}
	return d
}

// toInt64 safely converts an interface{} cell from a ClickHouse row to int64.
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

// toFloat64 safely converts an interface{} cell to float64.
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

// toString safely converts an interface{} cell to string.
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// toISO converts a ClickHouse time.Time cell to an ISO-8601 string.
// Mirrors Python _iso.
func toISO(v interface{}) string {
	if v == nil {
		return ""
	}
	if t, ok := v.(time.Time); ok {
		return t.Format(time.RFC3339Nano)
	}
	return toString(v)
}

// scalar extracts the first cell of the first row as int64. Mirrors Python _scalar.
func scalar(rows [][]interface{}) int64 {
	return chdash.Scalar(rows, 0)
}

// clampMinutes wraps chdash.ClampMinutes.
func clampMinutes(hours float64) int {
	return chdash.ClampMinutes(hours)
}

// defaultHours returns hours or 24 if hours is 0 (proto default).
func defaultHours(hours float64) float64 {
	if hours == 0 {
		return 24
	}
	return hours
}

// defaultLimit returns lim or 50 if lim is 0.
func defaultLimit(lim int64, def int64) int64 {
	if lim == 0 {
		return def
	}
	return lim
}

// ─── severity name map (matches Python _SEVERITY_NAMES) ──────────────────────

var severityNames = map[int64]string{
	0: "EMERGENCY",
	1: "ALERT",
	2: "CRITICAL",
	3: "ERROR",
	4: "WARNING",
	5: "NOTICE",
	6: "INFO",
	7: "DEBUG",
}

// severityLabel maps a numeric WAF severity to its label. Matches Python _SEVERITY_NAMES.
func severityLabel(sev int64) string {
	if s, ok := severityNames[sev]; ok {
		return s
	}
	return fmt.Sprintf("%d", sev)
}

// secSeverityLabel maps numeric WAF severity to the dashboard event labels.
// Mirrors Python get_security_events severity_labels dict.
var secSeverityLabels = map[int64]string{
	0: "info",
	1: "low",
	2: "medium",
	3: "high",
	4: "critical",
}

func secSeverityLabel(sev int64) string {
	if s, ok := secSeverityLabels[sev]; ok {
		return s
	}
	return "info"
}

// uuid4RE is the strict UUID4 validator for the test-traffic marker. It mirrors
// the Python router's _UUID4_RE (backend/src/dashboard/router.py) exactly:
//   - case-insensitive (?i)
//   - version nibble fixed to 4, variant nibble in [89ab]
//   - anchored with \A ... \z (NOT $) so a trailing newline cannot smuggle a
//     payload like "<uuid>\n; DROP ..." past the check.
//
// Validation runs BEFORE any SQL is constructed — it is the SQL-injection
// barrier for GetTestTraffic, which interpolates the marker into a ClickHouse
// query string.
var uuid4RE = regexp.MustCompile(
	`(?i)\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z`,
)

// safeMarker strips characters that could break ClickHouse string parsing.
// Mirrors Python safe_marker in get_test_traffic_by_marker.
func safeMarker(marker string) string {
	marker = strings.ReplaceAll(marker, "'", "")
	marker = strings.ReplaceAll(marker, "\\", "")
	marker = strings.ReplaceAll(marker, "\x00", "")
	return marker
}

// testMarkerHeader mirrors Python _TEST_MARKER_HEADER.
const testMarkerHeader = "X-Test-Marker"

// ─── 1. GetMetrics ────────────────────────────────────────────────────────────

func (s *Service) GetMetrics(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.MetricsResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)
	prevMinutes := int(math.Max(1, float64(minutes*2)))

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	nginxFilter := chdash.HostFilterNginx(doms)
	wafFilter := chdash.HostFilterWAF(doms)

	totalRows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.nginx_access_log WHERE time_local >= now() - INTERVAL %d MINUTE%s",
		minutes, nginxFilter))
	totalRequests := scalar(totalRows)

	prevRows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.nginx_access_log WHERE time_local >= now() - INTERVAL %d MINUTE AND time_local < now() - INTERVAL %d MINUTE%s",
		prevMinutes, minutes, nginxFilter))
	prevTotal := scalar(prevRows)

	var totalRequestsChange float64
	if prevTotal > 0 {
		totalRequestsChange = math.Round(float64(totalRequests-prevTotal)/float64(prevTotal)*100*10) / 10
	}

	blockedRows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.waf_audit_log WHERE timestamp >= now() - INTERVAL %d MINUTE%s",
		minutes, wafFilter))
	blockedThreats := scalar(blockedRows)

	highRows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.waf_audit_log ARRAY JOIN messages AS m WHERE timestamp >= now() - INTERVAL %d MINUTE AND m.severity >= 2%s",
		minutes, wafFilter))
	highSeverity := scalar(highRows)

	activeRulesRows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT count(DISTINCT m.ruleId) FROM logs.waf_audit_log ARRAY JOIN messages AS m WHERE timestamp >= now() - INTERVAL %d MINUTE%s",
		minutes, wafFilter))
	activeRules := scalar(activeRulesRows)

	errorRows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.nginx_access_log WHERE time_local >= now() - INTERVAL %d MINUTE AND status >= 500%s",
		minutes, nginxFilter))
	errorResponses := scalar(errorRows)

	systemHealth := 100.0
	if totalRequests > 0 {
		systemHealth = math.Round(float64(totalRequests-errorResponses)/float64(totalRequests)*100*10) / 10
	}

	return &dashboardv1.MetricsResponse{
		TotalRequests:       totalRequests,
		TotalRequestsChange: totalRequestsChange,
		BlockedThreats:      blockedThreats,
		HighSeverityCount:   highSeverity,
		SystemHealth:        systemHealth,
		AvgLatencyMs:        0.0,
		ActiveRules:         activeRules,
	}, nil
}

// ─── 2. GetTraffic ────────────────────────────────────────────────────────────

func (s *Service) GetTraffic(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.TrafficListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	nginxFilter := chdash.HostFilterNginx(doms)
	wafFilter := chdash.HostFilterWAF(doms)

	timeFunc := "toStartOfHour"
	if hours <= 2.0 {
		timeFunc = "toStartOfMinute"
	}

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT %s(time_local) AS t, count() AS total FROM logs.nginx_access_log WHERE time_local >= now() - INTERVAL %d MINUTE%s GROUP BY t ORDER BY t",
		timeFunc, minutes, nginxFilter))
	malRows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT %s(timestamp) AS t, count() AS total FROM logs.waf_audit_log WHERE timestamp >= now() - INTERVAL %d MINUTE%s GROUP BY t ORDER BY t",
		timeFunc, minutes, wafFilter))

	// Build maps keyed by time.Time for merge.
	nginxMap := make(map[time.Time]int64)
	malMap := make(map[time.Time]int64)
	allTimes := make(map[time.Time]struct{})

	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		if t, ok := r[0].(time.Time); ok {
			nginxMap[t] = toInt64(r[1])
			allTimes[t] = struct{}{}
		}
	}
	for _, r := range malRows {
		if len(r) < 2 {
			continue
		}
		if t, ok := r[0].(time.Time); ok {
			malMap[t] = toInt64(r[1])
			allTimes[t] = struct{}{}
		}
	}

	// Sort times.
	times := make([]time.Time, 0, len(allTimes))
	for t := range allTimes {
		times = append(times, t)
	}
	sortTimes(times)

	points := make([]*dashboardv1.TrafficPoint, 0, len(times))
	for _, t := range times {
		total := nginxMap[t]
		mal := malMap[t]
		clean := total - mal
		if clean < 0 {
			clean = 0
		}
		points = append(points, &dashboardv1.TrafficPoint{
			Timestamp: chdash.ISO(t),
			Clean:     clean,
			Malicious: mal,
		})
	}
	return &dashboardv1.TrafficListResponse{Points: points}, nil
}

func sortTimes(ts []time.Time) {
	// Simple insertion sort for small slices; correct for any size.
	for i := 1; i < len(ts); i++ {
		for j := i; j > 0 && ts[j].Before(ts[j-1]); j-- {
			ts[j], ts[j-1] = ts[j-1], ts[j]
		}
	}
}

// ─── 3. GetGeoipMap ───────────────────────────────────────────────────────────

func (s *Service) GetGeoipMap(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.GeoipMapListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	nginxFilter := chdash.HostFilterNginx(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT geoip_longitude, geoip_latitude, geoip_country_code, geoip_city_name, count() AS cnt "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE "+
			"AND geoip_latitude != 0 AND geoip_longitude != 0 "+
			"AND geoip_country_code != ''%s "+
			"GROUP BY geoip_longitude, geoip_latitude, geoip_country_code, geoip_city_name "+
			"ORDER BY cnt DESC "+
			"LIMIT 500",
		minutes, nginxFilter))

	points := make([]*dashboardv1.GeoipMapPoint, 0, len(rows))
	for _, r := range rows {
		if len(r) < 5 {
			continue
		}
		cc := toString(r[2])
		if cc == "" {
			cc = "UNKNOWN"
		}
		points = append(points, &dashboardv1.GeoipMapPoint{
			Longitude:   toFloat64(r[0]),
			Latitude:    toFloat64(r[1]),
			CountryCode: cc,
			CityName:    toString(r[3]),
			Hits:        toInt64(r[4]),
		})
	}
	return &dashboardv1.GeoipMapListResponse{Points: points}, nil
}

// ─── 4. GetGeoipUnresolved ────────────────────────────────────────────────────

func (s *Service) GetGeoipUnresolved(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.UnresolvedIpListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	nginxFilter := chdash.HostFilterNginx(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
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

	ips := make([]*dashboardv1.UnresolvedIp, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		ips = append(ips, &dashboardv1.UnresolvedIp{
			Ip:   toString(r[0]),
			Hits: toInt64(r[1]),
		})
	}
	return &dashboardv1.UnresolvedIpListResponse{Ips: ips}, nil
}

// ─── 5. GetThreatOrigins ──────────────────────────────────────────────────────

func (s *Service) GetThreatOrigins(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.ThreatOriginListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	totalRows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT count() FROM logs.waf_audit_log WHERE timestamp >= now() - INTERVAL %d MINUTE%s",
		minutes, wafFilter))
	totalBlocks := scalar(totalRows)
	if totalBlocks == 0 {
		return &dashboardv1.ThreatOriginListResponse{}, nil
	}

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT any(n.geoip_country_code) AS country_code, count() AS cnt "+
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
			"GROUP BY country_code "+
			"ORDER BY cnt DESC "+
			"LIMIT 10",
		minutes, minutes, wafFilter, minutes, wafFilter))

	if rows == nil {
		// Fallback: all blocks attributed to UNKNOWN (mirrors Python: rows = [("UNKNOWN", total_blocks)]).
		return &dashboardv1.ThreatOriginListResponse{
			Origins: []*dashboardv1.ThreatOrigin{
				{Country: "UNKNOWN", CountryCode: "UNKNOWN", BlocksPercent: 100.0},
			},
		}, nil
	}

	origins := make([]*dashboardv1.ThreatOrigin, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		cc := toString(r[0])
		if cc == "" {
			cc = "UNKNOWN"
		}
		cnt := toInt64(r[1])
		pct := math.Round(float64(cnt)/float64(totalBlocks)*100*10) / 10
		origins = append(origins, &dashboardv1.ThreatOrigin{
			Country:       cc,
			CountryCode:   cc,
			BlocksPercent: pct,
		})
	}
	return &dashboardv1.ThreatOriginListResponse{Origins: origins}, nil
}

// ─── 6. GetEvents ─────────────────────────────────────────────────────────────

func (s *Service) GetEvents(ctx context.Context, req *dashboardv1.EventsRequest) (*dashboardv1.SecurityEventListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)
	limit := defaultLimit(req.GetLimit(), 50)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	severityFilter := ""
	switch req.GetSeverity() {
	case "high":
		severityFilter = "AND m.severity >= 2"
	case "critical":
		severityFilter = "AND m.severity >= 3"
	}

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT w.timestamp, m.ruleId, w.client_ip, m.severity, w.request_uri, m.message "+
			"FROM logs.waf_audit_log AS w "+
			"ARRAY JOIN messages AS m "+
			"WHERE w.timestamp >= now() - INTERVAL %d MINUTE "+
			"%s%s "+
			"ORDER BY w.timestamp DESC "+
			"LIMIT %d",
		minutes, severityFilter, wafFilter, limit))

	events := make([]*dashboardv1.SecurityEvent, 0, len(rows))
	for _, r := range rows {
		if len(r) < 6 {
			continue
		}
		sev := toInt64(r[3])
		ruleID := toString(r[1])
		if ruleID == "" {
			ruleID = "unknown"
		}
		ip := toString(r[2])
		if ip == "" {
			ip = "0.0.0.0"
		}
		events = append(events, &dashboardv1.SecurityEvent{
			Timestamp: toISO(r[0]),
			Type:      ruleID,
			Ip:        ip,
			Country:   "",
			Path:      toString(r[4]),
			Severity:  secSeverityLabel(sev),
		})
	}
	return &dashboardv1.SecurityEventListResponse{Events: events}, nil
}

// ─── 7. GetWafEventsTimeline ──────────────────────────────────────────────────

func (s *Service) GetWafEventsTimeline(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.TimelineListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT toStartOfMinute(timestamp) AS t, count() AS hits "+
			"FROM logs.waf_audit_log "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY t ORDER BY t",
		minutes, wafFilter))

	points := make([]*dashboardv1.TimelinePoint, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		points = append(points, &dashboardv1.TimelinePoint{
			Timestamp: toISO(r[0]),
			Hits:      toInt64(r[1]),
		})
	}
	return &dashboardv1.TimelineListResponse{Points: points}, nil
}

// ─── 8. GetTopRules ───────────────────────────────────────────────────────────

func (s *Service) GetTopRules(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.RuleHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT m.ruleId AS rule, count() AS hits FROM logs.waf_audit_log "+
			"ARRAY JOIN messages AS m "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY rule ORDER BY hits DESC LIMIT 10",
		minutes, wafFilter))

	rules := make([]*dashboardv1.RuleHit, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		rule := toString(r[0])
		if rule == "" {
			rule = "unknown"
		}
		rules = append(rules, &dashboardv1.RuleHit{Rule: rule, Hits: toInt64(r[1])})
	}
	return &dashboardv1.RuleHitListResponse{Rules: rules}, nil
}

// ─── 9. GetSeverityDistribution ───────────────────────────────────────────────

func (s *Service) GetSeverityDistribution(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.SeveritySliceListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT m.severity AS sev, count() AS hits FROM logs.waf_audit_log "+
			"ARRAY JOIN messages AS m "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY sev ORDER BY sev",
		minutes, wafFilter))

	slices := make([]*dashboardv1.SeveritySlice, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		sev := toInt64(r[0])
		slices = append(slices, &dashboardv1.SeveritySlice{
			Severity: severityLabel(sev),
			Hits:     toInt64(r[1]),
		})
	}
	return &dashboardv1.SeveritySliceListResponse{Slices: slices}, nil
}

// ─── 10. GetTopAttackingIps ───────────────────────────────────────────────────

func (s *Service) GetTopAttackingIps(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.IpHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT client_ip, count() AS hits FROM logs.waf_audit_log "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY client_ip ORDER BY hits DESC LIMIT 15",
		minutes, wafFilter))

	ips := make([]*dashboardv1.IpHit, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		ip := toString(r[0])
		if ip == "" {
			ip = "0.0.0.0"
		}
		ips = append(ips, &dashboardv1.IpHit{Ip: ip, Hits: toInt64(r[1])})
	}
	return &dashboardv1.IpHitListResponse{Ips: ips}, nil
}

// ─── 11. GetAnomalyScore ──────────────────────────────────────────────────────

func (s *Service) GetAnomalyScore(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.AnomalyPointListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT toStartOfMinute(timestamp) AS t, max(anomaly_score) AS score "+
			"FROM logs.waf_audit_log "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY t ORDER BY t",
		minutes, wafFilter))

	points := make([]*dashboardv1.AnomalyPoint, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		points = append(points, &dashboardv1.AnomalyPoint{
			Timestamp: toISO(r[0]),
			Score:     toInt64(r[1]),
		})
	}
	return &dashboardv1.AnomalyPointListResponse{Points: points}, nil
}

// ─── 12. GetTopTags ───────────────────────────────────────────────────────────

func (s *Service) GetTopTags(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.TagHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT tag, count() AS hits FROM logs.waf_audit_log "+
			"ARRAY JOIN messages_tags AS tags ARRAY JOIN tags AS tag "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY tag ORDER BY hits DESC LIMIT 10",
		minutes, wafFilter))

	tags := make([]*dashboardv1.TagHit, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		tags = append(tags, &dashboardv1.TagHit{Tag: toString(r[0]), Hits: toInt64(r[1])})
	}
	return &dashboardv1.TagHitListResponse{Tags: tags}, nil
}

// ─── 13. GetTopUris ───────────────────────────────────────────────────────────

func (s *Service) GetTopUris(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.UriHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT request_uri AS uri, count() AS hits FROM logs.waf_audit_log "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY uri ORDER BY hits DESC LIMIT 10",
		minutes, wafFilter))

	uris := make([]*dashboardv1.UriHit, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		uri := toString(r[0])
		if uri == "" {
			uri = "/"
		}
		uris = append(uris, &dashboardv1.UriHit{Uri: uri, Hits: toInt64(r[1])})
	}
	return &dashboardv1.UriHitListResponse{Uris: uris}, nil
}

// ─── 14. GetTopRuleFiles ──────────────────────────────────────────────────────

func (s *Service) GetTopRuleFiles(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.RuleFileHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT replaceRegexpOne(replaceRegexpOne(m.file, '\\.conf$', ''), '^.*/', '') AS rf, "+
			"count() AS hits FROM logs.waf_audit_log "+
			"ARRAY JOIN messages AS m "+
			"WHERE timestamp >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY rf ORDER BY hits DESC LIMIT 10",
		minutes, wafFilter))

	files := make([]*dashboardv1.RuleFileHit, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		rf := toString(r[0])
		if rf == "" {
			rf = "unknown"
		}
		files = append(files, &dashboardv1.RuleFileHit{File: rf, Hits: toInt64(r[1])})
	}
	return &dashboardv1.RuleFileHitListResponse{Files: files}, nil
}

// ─── 15. GetStatusCodes ───────────────────────────────────────────────────────

func (s *Service) GetStatusCodes(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.StatusCodeListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	nginxFilter := chdash.HostFilterNginx(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT toStartOfMinute(time_local) AS t, "+
			"countIf(status >= 200 AND status < 300) AS c2xx, "+
			"countIf(status >= 300 AND status < 400) AS c3xx, "+
			"countIf(status >= 400 AND status < 500) AS c4xx, "+
			"countIf(status >= 500) AS c5xx "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY t ORDER BY t",
		minutes, nginxFilter))

	points := make([]*dashboardv1.StatusCodePoint, 0, len(rows))
	for _, r := range rows {
		if len(r) < 5 {
			continue
		}
		points = append(points, &dashboardv1.StatusCodePoint{
			Timestamp: toISO(r[0]),
			C2Xx:      toInt64(r[1]),
			C3Xx:      toInt64(r[2]),
			C4Xx:      toInt64(r[3]),
			C5Xx:      toInt64(r[4]),
		})
	}
	return &dashboardv1.StatusCodeListResponse{Points: points}, nil
}

// ─── 16. GetTopUserAgents ─────────────────────────────────────────────────────

func (s *Service) GetTopUserAgents(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.UserAgentHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	nginxFilter := chdash.HostFilterNginx(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT http_user_agent AS ua, count() AS hits "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY ua ORDER BY hits DESC LIMIT 15",
		minutes, nginxFilter))

	agents := make([]*dashboardv1.UserAgentHit, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		ua := toString(r[0])
		if ua == "" {
			ua = "-"
		}
		agents = append(agents, &dashboardv1.UserAgentHit{UserAgent: ua, Hits: toInt64(r[1])})
	}
	return &dashboardv1.UserAgentHitListResponse{Agents: agents}, nil
}

// ─── 17. GetTrafficVolume ─────────────────────────────────────────────────────

func (s *Service) GetTrafficVolume(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.BytesPointListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	nginxFilter := chdash.HostFilterNginx(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT toStartOfMinute(time_local) AS t, sum(body_bytes_sent) AS bytes "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY t ORDER BY t",
		minutes, nginxFilter))

	points := make([]*dashboardv1.BytesPoint, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		points = append(points, &dashboardv1.BytesPoint{
			Timestamp: toISO(r[0]),
			Bytes:     toInt64(r[1]),
		})
	}
	return &dashboardv1.BytesPointListResponse{Points: points}, nil
}

// ─── 18. GetRequestsPerSecond ─────────────────────────────────────────────────

func (s *Service) GetRequestsPerSecond(ctx context.Context, req *dashboardv1.RequestsPerSecondRequest) (*dashboardv1.RpsPointListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	nginxFilter := chdash.HostFilterNginx(doms)

	timeFunc := "toStartOfHour"
	if hours <= 2.0 {
		timeFunc = "toStartOfMinute"
	}

	var sql string
	if req.GetMetric() == "volume" {
		sql = fmt.Sprintf(
			"SELECT %s(time_local) AS t, count() AS rps "+
				"FROM logs.nginx_access_log "+
				"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
				"GROUP BY t ORDER BY t",
			timeFunc, minutes, nginxFilter)
	} else {
		// Peak RPS: max per-second count inside each bucket.
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

	rows, _ := s.ex.QueryCached(ctx, sql)

	points := make([]*dashboardv1.RpsPoint, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		points = append(points, &dashboardv1.RpsPoint{
			Timestamp: toISO(r[0]),
			Rps:       toFloat64(r[1]),
		})
	}
	return &dashboardv1.RpsPointListResponse{Points: points}, nil
}

// ─── 19. GetRequestsByCountry ─────────────────────────────────────────────────

func (s *Service) GetRequestsByCountry(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.CountryHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	nginxFilter := chdash.HostFilterNginx(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT if(geoip_country_code = '' OR geoip_country_code IS NULL, 'Unknown', geoip_country_code) "+
			"AS country, count() AS hits FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY country ORDER BY hits DESC LIMIT 15",
		minutes, nginxFilter))

	countries := make([]*dashboardv1.CountryHit, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		countries = append(countries, &dashboardv1.CountryHit{
			CountryCode: toString(r[0]),
			Hits:        toInt64(r[1]),
		})
	}
	return &dashboardv1.CountryHitListResponse{Countries: countries}, nil
}

// ─── 20. GetTopClientIps ──────────────────────────────────────────────────────

func (s *Service) GetTopClientIps(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.IpHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := clampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)
	nginxFilter := chdash.HostFilterNginx(doms)

	rows, _ := s.ex.QueryCached(ctx, fmt.Sprintf(
		"SELECT toString(remote_addr) AS ip, count() AS hits "+
			"FROM logs.nginx_access_log "+
			"WHERE time_local >= now() - INTERVAL %d MINUTE%s "+
			"GROUP BY ip ORDER BY hits DESC LIMIT 15",
		minutes, nginxFilter))

	ips := make([]*dashboardv1.IpHit, 0, len(rows))
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		ip := toString(r[0])
		if ip == "" {
			ip = "0.0.0.0"
		}
		ips = append(ips, &dashboardv1.IpHit{Ip: ip, Hits: toInt64(r[1])})
	}
	return &dashboardv1.IpHitListResponse{Ips: ips}, nil
}

// ─── 21. GetTestTraffic ───────────────────────────────────────────────────────

func (s *Service) GetTestTraffic(ctx context.Context, req *dashboardv1.TestTrafficRequest) (*dashboardv1.TestTrafficResponse, error) {
	// SQL-injection barrier: the marker is interpolated into the ClickHouse
	// query below, so it MUST be a strict UUID4 and nothing else. Reject any
	// non-conforming value with InvalidArgument (→ HTTP 400 via the gateway)
	// BEFORE building any SQL — mirrors the Python router's _UUID4_RE guard.
	if !uuid4RE.MatchString(req.GetMarker()) {
		return nil, status.Error(codes.InvalidArgument, "marker must be a UUID4")
	}

	tid := tenantID(ctx)
	// Resolve domains for tenant scoping (connection_id is always nil for test traffic).
	doms := s.domains(ctx, nil, tid)
	wafFilter := chdash.HostFilterWAF(doms)

	safe := safeMarker(req.GetMarker())

	// Uses Query (not QueryCached) — mirrors Python _direct_execute so a
	// freshly-fired marker is never served stale from cache.
	rows, _ := s.ex.Query(ctx, fmt.Sprintf(
		"SELECT w.timestamp, m.ruleId, w.client_ip, w.request_uri, "+
			"w.request_method, m.severity, m.message, w.anomaly_score "+
			"FROM logs.waf_audit_log AS w "+
			"LEFT ARRAY JOIN messages AS m "+
			"WHERE w.request_headers['%s'] = '%s' "+
			"AND w.timestamp >= now() - INTERVAL 1 HOUR%s "+
			"ORDER BY w.timestamp",
		testMarkerHeader, safe, wafFilter))

	events := make([]*dashboardv1.TestTrafficEvent, 0, len(rows))
	timestamps := make([]string, 0)
	seenTS := make(map[string]struct{})

	for _, r := range rows {
		if len(r) < 8 {
			continue
		}
		iso := toISO(r[0])
		ruleID := toString(r[1])
		if ruleID == "" {
			ruleID = "unknown"
		}
		ip := toString(r[2])
		if ip == "" {
			ip = "0.0.0.0"
		}
		sev := toInt64(r[5])

		events = append(events, &dashboardv1.TestTrafficEvent{
			Timestamp:    iso,
			RuleId:       ruleID,
			ClientIp:     ip,
			Uri:          toString(r[3]),
			Method:       toString(r[4]),
			Severity:     secSeverityLabel(sev),
			Message:      toString(r[6]),
			AnomalyScore: toInt64(r[7]),
		})
		if _, seen := seenTS[iso]; !seen {
			seenTS[iso] = struct{}{}
			timestamps = append(timestamps, iso)
		}
	}
	return &dashboardv1.TestTrafficResponse{Events: events, Timestamps: timestamps}, nil
}
