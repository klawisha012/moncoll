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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dashboardv1 "github.com/zwarder/waf/gobackend/gen/dashboard/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/chdash"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// DashboardBackend is the interface used by every RPC handler to fetch ClickHouse analytics.
// It is satisfied by *chdash.Client.
type DashboardBackend interface {
	GetMetrics(ctx context.Context, minutes, prevMinutes int, domains []string) (*chdash.Metrics, error)
	GetTraffic(ctx context.Context, minutes int, timeFunc string, domains []string) ([]chdash.TrafficPoint, error)
	GetGeoipMap(ctx context.Context, minutes int, domains []string) ([]chdash.GeoipMapPoint, error)
	GetGeoipUnresolved(ctx context.Context, minutes int, domains []string) ([]chdash.UnresolvedIp, error)
	GetThreatOrigins(ctx context.Context, minutes int, domains []string) (*chdash.ThreatOrigins, error)
	GetEvents(ctx context.Context, minutes int, severityFilter string, domains []string, limit int64) ([]chdash.SecurityEvent, error)
	GetWafEventsTimeline(ctx context.Context, minutes int, domains []string) ([]chdash.TimelinePoint, error)
	GetTopRules(ctx context.Context, minutes int, domains []string) ([]chdash.RuleHit, error)
	GetSeverityDistribution(ctx context.Context, minutes int, domains []string) ([]chdash.SeveritySlice, error)
	GetTopAttackingIps(ctx context.Context, minutes int, domains []string) ([]chdash.IpHit, error)
	GetAnomalyScore(ctx context.Context, minutes int, domains []string) ([]chdash.AnomalyPoint, error)
	GetTopTags(ctx context.Context, minutes int, domains []string) ([]chdash.TagHit, error)
	GetTopUris(ctx context.Context, minutes int, domains []string) ([]chdash.UriHit, error)
	GetTopRuleFiles(ctx context.Context, minutes int, domains []string) ([]chdash.RuleFileHit, error)
	GetStatusCodes(ctx context.Context, minutes int, domains []string) ([]chdash.StatusCodePoint, error)
	GetTopUserAgents(ctx context.Context, minutes int, domains []string) ([]chdash.UserAgentHit, error)
	GetTrafficVolume(ctx context.Context, minutes int, domains []string) ([]chdash.BytesPoint, error)
	GetRequestsPerSecond(ctx context.Context, minutes int, metric, timeFunc string, domains []string) ([]chdash.RpsPoint, error)
	GetRequestsByCountry(ctx context.Context, minutes int, domains []string) ([]chdash.CountryHit, error)
	GetTopClientIps(ctx context.Context, minutes int, domains []string) ([]chdash.IpHit, error)
	GetTestTraffic(ctx context.Context, marker string, domains []string) ([]chdash.TestTrafficEvent, error)
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
	db  DashboardBackend
	dr  DomainResolver
}

// New constructs a Service with a real *chdash.Client and *store.Store.
func New(ch *chdash.Client, st *store.Store) *Service {
	return &Service{db: ch, dr: &storeResolver{s: st}}
}

func (s *Service) AuthLevels() map[string]auth.Level {
	return map[string]auth.Level{
		dashboardv1.DashboardService_GetMetrics_FullMethodName:              auth.LevelVerified,
		dashboardv1.DashboardService_GetTraffic_FullMethodName:              auth.LevelVerified,
		dashboardv1.DashboardService_GetGeoipMap_FullMethodName:             auth.LevelVerified,
		dashboardv1.DashboardService_GetGeoipUnresolved_FullMethodName:      auth.LevelVerified,
		dashboardv1.DashboardService_GetThreatOrigins_FullMethodName:        auth.LevelVerified,
		dashboardv1.DashboardService_GetEvents_FullMethodName:               auth.LevelVerified,
		dashboardv1.DashboardService_GetWafEventsTimeline_FullMethodName:    auth.LevelVerified,
		dashboardv1.DashboardService_GetTopRules_FullMethodName:             auth.LevelVerified,
		dashboardv1.DashboardService_GetSeverityDistribution_FullMethodName: auth.LevelVerified,
		dashboardv1.DashboardService_GetTopAttackingIps_FullMethodName:      auth.LevelVerified,
		dashboardv1.DashboardService_GetAnomalyScore_FullMethodName:         auth.LevelVerified,
		dashboardv1.DashboardService_GetTopTags_FullMethodName:              auth.LevelVerified,
		dashboardv1.DashboardService_GetTopUris_FullMethodName:              auth.LevelVerified,
		dashboardv1.DashboardService_GetTopRuleFiles_FullMethodName:         auth.LevelVerified,
		dashboardv1.DashboardService_GetStatusCodes_FullMethodName:          auth.LevelVerified,
		dashboardv1.DashboardService_GetTopUserAgents_FullMethodName:        auth.LevelVerified,
		dashboardv1.DashboardService_GetTrafficVolume_FullMethodName:        auth.LevelVerified,
		dashboardv1.DashboardService_GetRequestsPerSecond_FullMethodName:    auth.LevelVerified,
		dashboardv1.DashboardService_GetRequestsByCountry_FullMethodName:    auth.LevelVerified,
		dashboardv1.DashboardService_GetTopClientIps_FullMethodName:         auth.LevelVerified,
		dashboardv1.DashboardService_GetTestTraffic_FullMethodName:          auth.LevelVerified,
	}
}

// newWithDeps constructs a Service with injected backend + resolver (for tests).
func newWithDeps(db DashboardBackend, dr DomainResolver) *Service {
	return &Service{db: db, dr: dr}
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

// uuid4RE is the strict UUID4 validator for the test-traffic marker.
var uuid4RE = regexp.MustCompile(
	`(?i)\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z`,
)

// ─── 1. GetMetrics ────────────────────────────────────────────────────────────

func (s *Service) GetMetrics(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.MetricsResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)
	prevMinutes := int(math.Max(1, float64(minutes*2)))

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	metrics, err := s.db.GetMetrics(ctx, minutes, prevMinutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if metrics == nil {
		return &dashboardv1.MetricsResponse{}, nil
	}

	return &dashboardv1.MetricsResponse{
		TotalRequests:       metrics.TotalRequests,
		TotalRequestsChange: metrics.TotalRequestsChange,
		BlockedThreats:      metrics.BlockedThreats,
		HighSeverityCount:   metrics.HighSeverityCount,
		SystemHealth:        metrics.SystemHealth,
		AvgLatencyMs:        metrics.AvgLatencyMs,
		ActiveRules:         metrics.ActiveRules,
	}, nil
}

// ─── 2. GetTraffic ────────────────────────────────────────────────────────────

func (s *Service) GetTraffic(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.TrafficListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	timeFunc := "toStartOfHour"
	if hours <= 2.0 {
		timeFunc = "toStartOfMinute"
	}

	points, err := s.db.GetTraffic(ctx, minutes, timeFunc, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respPoints := make([]*dashboardv1.TrafficPoint, 0, len(points))
	for _, p := range points {
		respPoints = append(respPoints, &dashboardv1.TrafficPoint{
			Timestamp: chdash.ISO(p.Timestamp),
			Clean:     p.Clean,
			Malicious: p.Malicious,
		})
	}
	return &dashboardv1.TrafficListResponse{Points: respPoints}, nil
}

// ─── 3. GetGeoipMap ───────────────────────────────────────────────────────────

func (s *Service) GetGeoipMap(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.GeoipMapListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	points, err := s.db.GetGeoipMap(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respPoints := make([]*dashboardv1.GeoipMapPoint, 0, len(points))
	for _, p := range points {
		respPoints = append(respPoints, &dashboardv1.GeoipMapPoint{
			Longitude:   p.Longitude,
			Latitude:    p.Latitude,
			CountryCode: p.CountryCode,
			CityName:    p.CityName,
			Hits:        p.Hits,
		})
	}
	return &dashboardv1.GeoipMapListResponse{Points: respPoints}, nil
}

// ─── 4. GetGeoipUnresolved ────────────────────────────────────────────────────

func (s *Service) GetGeoipUnresolved(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.UnresolvedIpListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	ips, err := s.db.GetGeoipUnresolved(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respIps := make([]*dashboardv1.UnresolvedIp, 0, len(ips))
	for _, ip := range ips {
		respIps = append(respIps, &dashboardv1.UnresolvedIp{
			Ip:   ip.Ip,
			Hits: ip.Hits,
		})
	}
	return &dashboardv1.UnresolvedIpListResponse{Ips: respIps}, nil
}

// ─── 5. GetThreatOrigins ──────────────────────────────────────────────────────

func (s *Service) GetThreatOrigins(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.ThreatOriginListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	origins, err := s.db.GetThreatOrigins(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if origins == nil || origins.TotalBlocks == 0 {
		return &dashboardv1.ThreatOriginListResponse{}, nil
	}

	respOrigins := make([]*dashboardv1.ThreatOrigin, 0, len(origins.Origins))
	for _, o := range origins.Origins {
		pct := math.Round(float64(o.Hits)/float64(origins.TotalBlocks)*100*10) / 10
		respOrigins = append(respOrigins, &dashboardv1.ThreatOrigin{
			Country:       o.CountryCode,
			CountryCode:   o.CountryCode,
			BlocksPercent: pct,
		})
	}
	return &dashboardv1.ThreatOriginListResponse{Origins: respOrigins}, nil
}

// ─── 6. GetEvents ─────────────────────────────────────────────────────────────

func (s *Service) GetEvents(ctx context.Context, req *dashboardv1.EventsRequest) (*dashboardv1.SecurityEventListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)
	limit := defaultLimit(req.GetLimit(), 50)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	events, err := s.db.GetEvents(ctx, minutes, req.GetSeverity(), doms, limit)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respEvents := make([]*dashboardv1.SecurityEvent, 0, len(events))
	for _, e := range events {
		ruleID := e.RuleId
		if ruleID == "" {
			ruleID = "unknown"
		}
		ip := e.ClientIp
		if ip == "" {
			ip = "0.0.0.0"
		}
		respEvents = append(respEvents, &dashboardv1.SecurityEvent{
			Timestamp: chdash.ISO(e.Timestamp),
			Type:      ruleID,
			Ip:        ip,
			Country:   "",
			Path:      e.Path,
			Severity:  secSeverityLabel(e.Severity),
		})
	}
	return &dashboardv1.SecurityEventListResponse{Events: respEvents}, nil
}

// ─── 7. GetWafEventsTimeline ──────────────────────────────────────────────────

func (s *Service) GetWafEventsTimeline(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.TimelineListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	points, err := s.db.GetWafEventsTimeline(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respPoints := make([]*dashboardv1.TimelinePoint, 0, len(points))
	for _, p := range points {
		respPoints = append(respPoints, &dashboardv1.TimelinePoint{
			Timestamp: chdash.ISO(p.Timestamp),
			Hits:      p.Hits,
		})
	}
	return &dashboardv1.TimelineListResponse{Points: respPoints}, nil
}

// ─── 8. GetTopRules ───────────────────────────────────────────────────────────

func (s *Service) GetTopRules(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.RuleHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	rules, err := s.db.GetTopRules(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respRules := make([]*dashboardv1.RuleHit, 0, len(rules))
	for _, r := range rules {
		rule := r.Rule
		if rule == "" {
			rule = "unknown"
		}
		respRules = append(respRules, &dashboardv1.RuleHit{
			Rule: rule,
			Hits: r.Hits,
		})
	}
	return &dashboardv1.RuleHitListResponse{Rules: respRules}, nil
}

// ─── 9. GetSeverityDistribution ───────────────────────────────────────────────

func (s *Service) GetSeverityDistribution(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.SeveritySliceListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	slices, err := s.db.GetSeverityDistribution(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respSlices := make([]*dashboardv1.SeveritySlice, 0, len(slices))
	for _, sl := range slices {
		respSlices = append(respSlices, &dashboardv1.SeveritySlice{
			Severity: severityLabel(sl.Severity),
			Hits:     sl.Hits,
		})
	}
	return &dashboardv1.SeveritySliceListResponse{Slices: respSlices}, nil
}

// ─── 10. GetTopAttackingIps ───────────────────────────────────────────────────

func (s *Service) GetTopAttackingIps(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.IpHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	ips, err := s.db.GetTopAttackingIps(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respIps := make([]*dashboardv1.IpHit, 0, len(ips))
	for _, ip := range ips {
		respIp := ip.Ip
		if respIp == "" {
			respIp = "0.0.0.0"
		}
		respIps = append(respIps, &dashboardv1.IpHit{
			Ip:   respIp,
			Hits: ip.Hits,
		})
	}
	return &dashboardv1.IpHitListResponse{Ips: respIps}, nil
}

// ─── 11. GetAnomalyScore ──────────────────────────────────────────────────────

func (s *Service) GetAnomalyScore(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.AnomalyPointListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	points, err := s.db.GetAnomalyScore(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respPoints := make([]*dashboardv1.AnomalyPoint, 0, len(points))
	for _, p := range points {
		respPoints = append(respPoints, &dashboardv1.AnomalyPoint{
			Timestamp: chdash.ISO(p.Timestamp),
			Score:     p.Score,
		})
	}
	return &dashboardv1.AnomalyPointListResponse{Points: respPoints}, nil
}

// ─── 12. GetTopTags ───────────────────────────────────────────────────────────

func (s *Service) GetTopTags(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.TagHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	tags, err := s.db.GetTopTags(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respTags := make([]*dashboardv1.TagHit, 0, len(tags))
	for _, t := range tags {
		respTags = append(respTags, &dashboardv1.TagHit{
			Tag:  t.Tag,
			Hits: t.Hits,
		})
	}
	return &dashboardv1.TagHitListResponse{Tags: respTags}, nil
}

// ─── 13. GetTopUris ───────────────────────────────────────────────────────────

func (s *Service) GetTopUris(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.UriHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	uris, err := s.db.GetTopUris(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respUris := make([]*dashboardv1.UriHit, 0, len(uris))
	for _, u := range uris {
		uri := u.Uri
		if uri == "" {
			uri = "/"
		}
		respUris = append(respUris, &dashboardv1.UriHit{
			Uri:  uri,
			Hits: u.Hits,
		})
	}
	return &dashboardv1.UriHitListResponse{Uris: respUris}, nil
}

// ─── 14. GetTopRuleFiles ──────────────────────────────────────────────────────

func (s *Service) GetTopRuleFiles(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.RuleFileHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	files, err := s.db.GetTopRuleFiles(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respFiles := make([]*dashboardv1.RuleFileHit, 0, len(files))
	for _, f := range files {
		rf := f.File
		if rf == "" {
			rf = "unknown"
		}
		respFiles = append(respFiles, &dashboardv1.RuleFileHit{
			File: rf,
			Hits: f.Hits,
		})
	}
	return &dashboardv1.RuleFileHitListResponse{Files: respFiles}, nil
}

// ─── 15. GetStatusCodes ───────────────────────────────────────────────────────

func (s *Service) GetStatusCodes(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.StatusCodeListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	points, err := s.db.GetStatusCodes(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respPoints := make([]*dashboardv1.StatusCodePoint, 0, len(points))
	for _, p := range points {
		respPoints = append(respPoints, &dashboardv1.StatusCodePoint{
			Timestamp: chdash.ISO(p.Timestamp),
			C2Xx:      p.C2xx,
			C3Xx:      p.C3xx,
			C4Xx:      p.C4xx,
			C5Xx:      p.C5xx,
		})
	}
	return &dashboardv1.StatusCodeListResponse{Points: respPoints}, nil
}

// ─── 16. GetTopUserAgents ─────────────────────────────────────────────────────

func (s *Service) GetTopUserAgents(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.UserAgentHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	agents, err := s.db.GetTopUserAgents(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respAgents := make([]*dashboardv1.UserAgentHit, 0, len(agents))
	for _, a := range agents {
		ua := a.UserAgent
		if ua == "" {
			ua = "-"
		}
		respAgents = append(respAgents, &dashboardv1.UserAgentHit{
			UserAgent: ua,
			Hits:      a.Hits,
		})
	}
	return &dashboardv1.UserAgentHitListResponse{Agents: respAgents}, nil
}

// ─── 17. GetTrafficVolume ─────────────────────────────────────────────────────

func (s *Service) GetTrafficVolume(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.BytesPointListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	points, err := s.db.GetTrafficVolume(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respPoints := make([]*dashboardv1.BytesPoint, 0, len(points))
	for _, p := range points {
		respPoints = append(respPoints, &dashboardv1.BytesPoint{
			Timestamp: chdash.ISO(p.Timestamp),
			Bytes:     p.Bytes,
		})
	}
	return &dashboardv1.BytesPointListResponse{Points: respPoints}, nil
}

// ─── 18. GetRequestsPerSecond ─────────────────────────────────────────────────

func (s *Service) GetRequestsPerSecond(ctx context.Context, req *dashboardv1.RequestsPerSecondRequest) (*dashboardv1.RpsPointListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	timeFunc := "toStartOfHour"
	if hours <= 2.0 {
		timeFunc = "toStartOfMinute"
	}

	points, err := s.db.GetRequestsPerSecond(ctx, minutes, req.GetMetric(), timeFunc, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respPoints := make([]*dashboardv1.RpsPoint, 0, len(points))
	for _, p := range points {
		respPoints = append(respPoints, &dashboardv1.RpsPoint{
			Timestamp: chdash.ISO(p.Timestamp),
			Rps:       p.Rps,
		})
	}
	return &dashboardv1.RpsPointListResponse{Points: respPoints}, nil
}

// ─── 19. GetRequestsByCountry ─────────────────────────────────────────────────

func (s *Service) GetRequestsByCountry(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.CountryHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	countries, err := s.db.GetRequestsByCountry(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respCountries := make([]*dashboardv1.CountryHit, 0, len(countries))
	for _, c := range countries {
		respCountries = append(respCountries, &dashboardv1.CountryHit{
			CountryCode: c.CountryCode,
			Hits:        c.Hits,
		})
	}
	return &dashboardv1.CountryHitListResponse{Countries: respCountries}, nil
}

// ─── 20. GetTopClientIps ──────────────────────────────────────────────────────

func (s *Service) GetTopClientIps(ctx context.Context, req *dashboardv1.DashboardRequest) (*dashboardv1.IpHitListResponse, error) {
	hours := defaultHours(req.GetHours())
	minutes := chdash.ClampMinutes(hours)

	var connID *int64
	if req.GetConnectionId() != nil {
		v := req.GetConnectionId().GetValue()
		connID = &v
	}
	tid := tenantID(ctx)
	doms := s.domains(ctx, connID, tid)

	ips, err := s.db.GetTopClientIps(ctx, minutes, doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respIps := make([]*dashboardv1.IpHit, 0, len(ips))
	for _, ip := range ips {
		respIp := ip.Ip
		if respIp == "" {
			respIp = "0.0.0.0"
		}
		respIps = append(respIps, &dashboardv1.IpHit{
			Ip:   respIp,
			Hits: ip.Hits,
		})
	}
	return &dashboardv1.IpHitListResponse{Ips: respIps}, nil
}

// ─── 21. GetTestTraffic ───────────────────────────────────────────────────────

func (s *Service) GetTestTraffic(ctx context.Context, req *dashboardv1.TestTrafficRequest) (*dashboardv1.TestTrafficResponse, error) {
	if !uuid4RE.MatchString(req.GetMarker()) {
		return nil, status.Error(codes.InvalidArgument, "marker must be a UUID4")
	}

	tid := tenantID(ctx)
	doms := s.domains(ctx, nil, tid)

	events, err := s.db.GetTestTraffic(ctx, req.GetMarker(), doms)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	respEvents := make([]*dashboardv1.TestTrafficEvent, 0, len(events))
	timestamps := make([]string, 0)
	seenTS := make(map[string]struct{})

	for _, e := range events {
		iso := chdash.ISO(e.Timestamp)
		ruleID := e.RuleId
		if ruleID == "" {
			ruleID = "unknown"
		}
		ip := e.ClientIp
		if ip == "" {
			ip = "0.0.0.0"
		}

		respEvents = append(respEvents, &dashboardv1.TestTrafficEvent{
			Timestamp:    iso,
			RuleId:       ruleID,
			ClientIp:     ip,
			Uri:          e.Uri,
			Method:       e.Method,
			Severity:     secSeverityLabel(e.Severity),
			Message:      e.Message,
			AnomalyScore: e.AnomalyScore,
		})
		if _, seen := seenTS[iso]; !seen {
			seenTS[iso] = struct{}{}
			timestamps = append(timestamps, iso)
		}
	}
	return &dashboardv1.TestTrafficResponse{Events: respEvents, Timestamps: timestamps}, nil
}
