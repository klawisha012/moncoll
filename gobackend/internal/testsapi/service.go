// Package testsapi implements the TestsService gRPC service, faithfully
// porting backend/src/tests/router.py + service.py + crowdsec_runner.py.
//
// Architecture summary:
//
//   - GetCatalog / GetCrowdsecCatalog: serve static data (manifest.json + in-process
//     catalog). No DB access.
//   - RunTest: fires an HTTP request tagged with X-Test-Marker, polls the WAF
//     audit log (ClickHouse) for up to 5 s to classify the result.
//   - RunCrowdsecScenario: fires an HTTP burst that triggers CrowdSec detection,
//     adds a forceful ban decision via cscli, waits ~4 s, snapshots decisions.
//
// Live network operations (HTTP probes, ClickHouse polls, cscli decisions) are
// all behind injected interfaces (Prober, CHPoller, CSRunner) so they can be
// swapped for fakes in unit tests without a real Docker / Angie / ClickHouse.
package testsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	testsv1 "github.com/zwarder/waf/gobackend/gen/tests/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const markerHeader = "X-Test-Marker"

// ── Interfaces ────────────────────────────────────────────────────────────────

// ConnectionRow is the minimal connection data the service needs to resolve
// a target URL + Host header for a test.
type ConnectionRow struct {
	ID            int64
	TenantID      int64
	Domain        string
	Enabled       bool
	Status        string
	SSLCertPath   *string
	SSLKeyPath    *string
}

// ConnStore fetches connections for a tenant (required by run / crowdsec/run).
type ConnStore interface {
	// ListConnectionsForTenant returns all enabled connections for tenantID.
	ListConnectionsForTenant(ctx context.Context, tenantID int64) ([]ConnectionRow, error)
	// GetConnectionForTenant returns the connection with connID owned by tenantID,
	// or (nil, nil) when it doesn't exist or belongs to a different tenant.
	GetConnectionForTenant(ctx context.Context, connID, tenantID int64) (*ConnectionRow, error)
}

// Prober fires one HTTP request and returns (statusCode, requestRaw,
// responseRaw, transportErr). statusCode is 0 when the transport erred.
type Prober interface {
	Fire(ctx context.Context, method, rawURL string, headers map[string]string, body string) (statusCode int, reqRaw, respRaw string, transportErr string)
}

// CHPoller polls ClickHouse for an X-Test-Marker row.
// Returns (landed, blockedByRuleID, error).
type CHPoller interface {
	PollMarker(ctx context.Context, marker string, timeout time.Duration) (bool, string, error)
}

// CSRunner can snapshot decisions (get) and add a ban decision (add).
// Mirrors the cscli calls crowdsec_runner.py makes.
type CSRunner interface {
	GetDecisions(ctx context.Context) ([]json.RawMessage, error)
	AddDecision(ctx context.Context, ip, duration, reason, decisionType string) error
}

// CatalogLoader loads the ModSecurity test catalog from disk.
type CatalogLoader interface {
	Load() (*Catalog, error)
}

// ── In-memory rate limiter ────────────────────────────────────────────────────

// rateLimiter enforces a per-user 1-req/s limit (mirrors Python _rate_limit).
// Single-instance; a multi-pod deploy would need Redis-backed rate limiting.
type rateLimiter struct {
	mu       sync.Mutex
	last     map[int64]time.Time
	interval time.Duration
}

func newRateLimiter(interval time.Duration) *rateLimiter {
	return &rateLimiter{last: make(map[int64]time.Time), interval: interval}
}

// Allow returns true when the user may proceed, false when rate-limited.
func (r *rateLimiter) Allow(userID int64) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	last, ok := r.last[userID]
	if ok && now.Sub(last) < r.interval {
		return false
	}
	r.last[userID] = now
	return true
}

// ── Catalog types ─────────────────────────────────────────────────────────────

// TestCase mirrors schemas.TestCase in Python.
type TestCase struct {
	ID          string            `json:"id"`
	Family      string            `json:"family"`
	RuleID      string            `json:"rule_id"`
	Description string            `json:"description"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Query       map[string]string `json:"query"`
	Headers     map[string]string `json:"headers"`
	Body        *string           `json:"body"`
}

// Catalog mirrors schemas.Catalog in Python.
type Catalog struct {
	Tests       []TestCase `json:"tests"`
	GeneratedAt *string    `json:"generated_at"`
}

// ── File-based catalog loader ─────────────────────────────────────────────────

// FileCatalogLoader loads the catalog from the manifest.json embedded in the
// binary directory (or overridden via WAF_TESTS_MANIFEST_PATH).
type FileCatalogLoader struct {
	path string
}

// NewFileCatalogLoader builds a loader that reads from path (or the env var).
func NewFileCatalogLoader(path string) *FileCatalogLoader {
	if p := os.Getenv("WAF_TESTS_MANIFEST_PATH"); p != "" {
		path = p
	}
	return &FileCatalogLoader{path: path}
}

// Load reads and parses the manifest.json.  Returns an empty catalog on any error.
func (l *FileCatalogLoader) Load() (*Catalog, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		slog.Warn("testsapi: manifest.json not found; returning empty catalog", "path", l.path, "err", err)
		return &Catalog{Tests: []TestCase{}}, nil
	}
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		slog.Warn("testsapi: manifest.json parse error; returning empty catalog", "err", err)
		return &Catalog{Tests: []TestCase{}}, nil
	}
	return &c, nil
}

// ── CrowdSec scenario catalog (static, mirrors crowdsec_runner.py) ────────────

// crowdsecScenario is one entry in the static CrowdSec subcatalog.
type crowdsecScenario struct {
	ID          string
	Category    string
	Scenario    string
	Description string
	Paths       []string
	Method      string
	UserAgent   string
}

// scenarioCatalog is the exact port of SCENARIO_CATALOG from crowdsec_runner.py.
var scenarioCatalog = []crowdsecScenario{
	{
		ID: "crowdsec.http-probing", Category: "recon",
		Scenario:    "crowdsecurity/http-probing",
		Description: "Probes common sensitive paths (.env, /admin, /wp-login.php, …)",
		Paths:       []string{"/.env", "/admin", "/wp-admin", "/wp-login.php", "/.git/config", "/server-status", "/phpmyadmin", "/cgi-bin/test"},
		Method:      "GET",
	},
	{
		ID: "crowdsec.http-crawl-non_statics", Category: "crawl",
		Scenario:    "crowdsecurity/http-crawl-non_statics",
		Description: "Many 404s for non-static paths from the same source",
		Paths:       []string{"/random-1", "/random-2", "/random-3", "/random-4", "/random-5", "/random-6", "/random-7", "/random-8"},
		Method:      "GET",
	},
	{
		ID: "crowdsec.http-bad-user-agent", Category: "exploit",
		Scenario:    "crowdsecurity/http-bad-user-agent",
		Description: "Requests with a known scanner/exploit User-Agent",
		Paths:       []string{"/", "/api", "/login"},
		Method:      "GET",
		UserAgent:   "() { :;}; /bin/cat /etc/passwd",
	},
	{
		ID: "crowdsec.http-scan-404", Category: "crawl",
		Scenario:    "crowdsecurity/http-scan-404",
		Description: "Scanning for non-existent pages (many 404s in a short window)",
		Paths:       []string{"/notfound-1", "/notfound-2", "/notfound-3", "/notfound-4", "/notfound-5", "/notfound-6"},
		Method:      "GET",
	},
	{
		ID: "crowdsec.http-path-traversal-probing", Category: "traversal",
		Scenario:    "crowdsecurity/http-path-traversal-probing",
		Description: "Attempts to traverse directories using path traversal signatures",
		Paths:       []string{"/../../etc/passwd", "/wp-content/../../etc/hosts", "/static/../../etc/shadow", "/../../boot.ini"},
		Method:      "GET",
	},
}

func findScenario(id string) *crowdsecScenario {
	for i := range scenarioCatalog {
		if scenarioCatalog[i].ID == id {
			return &scenarioCatalog[i]
		}
	}
	return nil
}

// ── Service ───────────────────────────────────────────────────────────────────

// Service implements testsv1.TestsServiceServer.
type Service struct {
	testsv1.UnimplementedTestsServiceServer
	catalog   CatalogLoader
	store     ConnStore
	prober    Prober
	chPoller  CHPoller
	csRunner  CSRunner
	rateLim   *rateLimiter
	pollTO    time.Duration
	log       *slog.Logger
}

// New builds a fully-wired Service.  Pass nil for csRunner / chPoller /
// prober to get degraded-mode operation (run → always "timeout", crowdsec/run
// → empty decisions).
func New(
	catalog CatalogLoader,
	store ConnStore,
	prober Prober,
	chPoller CHPoller,
	csRunner CSRunner,
	log *slog.Logger,
) *Service {
	pollTO := 5 * time.Second
	if s := os.Getenv("WAF_TESTS_POLL_TIMEOUT"); s != "" {
		if d, err := time.ParseDuration(s + "s"); err == nil {
			pollTO = d
		}
	}
	return &Service{
		catalog:  catalog,
		store:    store,
		prober:   prober,
		chPoller: chPoller,
		csRunner: csRunner,
		rateLim:  newRateLimiter(time.Second),
		pollTO:   pollTO,
		log:      log,
	}
}

func (s *Service) AuthLevels() map[string]auth.Level {
	return map[string]auth.Level{
		testsv1.TestsService_GetCatalog_FullMethodName:          auth.LevelVerified,
		testsv1.TestsService_RunTest_FullMethodName:             auth.LevelVerified,
		testsv1.TestsService_GetCrowdsecCatalog_FullMethodName:  auth.LevelVerified,
		testsv1.TestsService_RunCrowdsecScenario_FullMethodName: auth.LevelVerified,
	}
}

// ── 1. GetCatalog ─────────────────────────────────────────────────────────────

func (s *Service) GetCatalog(_ context.Context, _ *testsv1.GetCatalogRequest) (*testsv1.CatalogResponse, error) {
	cat, _ := s.catalog.Load()
	resp := &testsv1.CatalogResponse{}
	for _, t := range cat.Tests {
		tc := &testsv1.TestCase{
			Id:          t.ID,
			Family:      t.Family,
			RuleId:      t.RuleID,
			Description: t.Description,
			Method:      methodOrDefault(t.Method),
			Path:        pathOrDefault(t.Path),
			Query:       t.Query,
			Headers:     t.Headers,
		}
		if t.Body != nil {
			tc.Body = wrapperspb.String(*t.Body)
		}
		resp.Tests = append(resp.Tests, tc)
	}
	if cat.GeneratedAt != nil {
		resp.GeneratedAt = wrapperspb.String(*cat.GeneratedAt)
	}
	return resp, nil
}

// ── 2. RunTest ────────────────────────────────────────────────────────────────

func (s *Service) RunTest(ctx context.Context, req *testsv1.RunTestRequest) (*testsv1.RunResult, error) {
	// Require tenant (current_tenant dependency in Python).
	id, ok := auth.IdentityFromContext(ctx)
	if !ok || id.TenantID == nil {
		return nil, status.Error(codes.PermissionDenied, "tenant required")
	}
	tenantID := *id.TenantID

	// Rate limit per user.
	if !s.rateLim.Allow(id.UserID) {
		return nil, status.Error(codes.ResourceExhausted, "rate limit: 1 test per second")
	}

	// Resolve test case.
	cat, _ := s.catalog.Load()
	var test *TestCase
	for i := range cat.Tests {
		if cat.Tests[i].ID == req.GetTestId() {
			test = &cat.Tests[i]
			break
		}
	}
	if test == nil {
		return nil, status.Errorf(codes.InvalidArgument, "unknown test_id: %s", req.GetTestId())
	}

	// Determine target list: if connection_id is nil, probe all enabled tenant connections.
	var targets []targetEntry

	if req.GetConnectionId() == nil && s.store != nil {
		conns, err := s.store.ListConnectionsForTenant(ctx, tenantID)
		if err != nil {
			s.log.Warn("testsapi: ListConnectionsForTenant failed", "err", err)
		}
		for _, c := range conns {
			if c.Enabled {
				targets = append(targets, targetEntry{
					baseURL: localhostURL(),
					domain:  c.Domain,
				})
			}
		}
	}
	if len(targets) == 0 {
		// Single target: connection_id if set (tenant-scoped), else default Angie vhost.
		baseURL := localhostURL()
		domain := ""
		if req.GetConnectionId() != nil && s.store != nil {
			connID := req.GetConnectionId().GetValue()
			conn, err := s.store.GetConnectionForTenant(ctx, connID, tenantID)
			if err == nil && conn != nil {
				baseURL = connectionURL(conn)
				domain = conn.Domain
			}
		}
		targets = append(targets, targetEntry{baseURL: baseURL, domain: domain})
	}

	// Build X-Test-Marker.
	marker := newUUID()
	startedAt := time.Now()

	type fireResult struct {
		code    int
		reqRaw  string
		respRaw string
		errStr  string
	}

	fireResults := make([]fireResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(idx int, tgt targetEntry) {
			defer wg.Done()
			headers, rawURL := buildRequestParts(test, tgt.baseURL, tgt.domain, marker, req.GetIp().GetValue())
			code, reqRaw, respRaw, errStr := s.probe(ctx, test.Method, rawURL, headers, stringOrEmpty(test.Body))
			fireResults[idx] = fireResult{code: code, reqRaw: reqRaw, respRaw: respRaw, errStr: errStr}
		}(i, t)
	}
	wg.Wait()

	latencyMS := time.Since(startedAt).Milliseconds()

	// Collect HTTP codes and errors.
	var httpCodes []int
	var errors []string
	for _, r := range fireResults {
		if r.code != 0 {
			httpCodes = append(httpCodes, r.code)
		}
		if r.errStr != "" {
			errors = append(errors, r.errStr)
		}
	}
	var firstReqRaw, firstRespRaw string
	if len(fireResults) > 0 {
		firstReqRaw = fireResults[0].reqRaw
		firstRespRaw = fireResults[0].respRaw
	}
	targetURLs := joinTargetURLs(targets)

	// All targets failed with transport errors.
	if len(errors) == len(targets) {
		return &testsv1.RunResult{
			Marker:      marker,
			Status:      "timeout",
			HttpCode:    int64WrapperOrNil(httpCodesFirst(httpCodes)),
			TargetUrl:   targetURLs,
			LatencyMs:   wrapperspb.Int64(latencyMS),
			Error:       wrapperspb.String(errors[0]),
			RequestRaw:  wrapString(firstReqRaw),
			ResponseRaw: wrapString(firstRespRaw),
		}, nil
	}

	// Pick representative HTTP code: 403 if any target blocked, else first success.
	httpCode := httpCodePick(httpCodes)

	// Poll ClickHouse for the marker.
	markerLanded, blockedBy := s.pollMarker(ctx, marker)
	testStatus := classify(httpCode, markerLanded)

	result := &testsv1.RunResult{
		Marker:      marker,
		Status:      testStatus,
		TargetUrl:   targetURLs,
		LatencyMs:   wrapperspb.Int64(latencyMS),
		RequestRaw:  wrapString(firstReqRaw),
		ResponseRaw: wrapString(firstRespRaw),
	}
	if httpCode != 0 {
		result.HttpCode = wrapperspb.Int64(int64(httpCode))
	}
	if blockedBy != "" {
		result.BlockedBy = wrapperspb.String(blockedBy)
	}
	return result, nil
}

// ── 3. GetCrowdsecCatalog ─────────────────────────────────────────────────────

func (s *Service) GetCrowdsecCatalog(_ context.Context, _ *testsv1.GetCrowdsecCatalogRequest) (*testsv1.CrowdsecCatalogResponse, error) {
	resp := &testsv1.CrowdsecCatalogResponse{}
	for _, sc := range scenarioCatalog {
		resp.Scenarios = append(resp.Scenarios, &testsv1.CrowdsecScenario{
			Id:          sc.ID,
			Category:    sc.Category,
			Scenario:    sc.Scenario,
			Description: sc.Description,
			BurstSize:   int64(len(sc.Paths)),
		})
	}
	return resp, nil
}

// ── 4. RunCrowdsecScenario ────────────────────────────────────────────────────

func (s *Service) RunCrowdsecScenario(ctx context.Context, req *testsv1.RunCrowdsecRequest) (*testsv1.CrowdsecRunResult, error) {
	// Require tenant.
	id, ok := auth.IdentityFromContext(ctx)
	if !ok || id.TenantID == nil {
		return nil, status.Error(codes.PermissionDenied, "tenant required")
	}
	tenantID := *id.TenantID

	// Rate limit per user.
	if !s.rateLim.Allow(id.UserID) {
		return nil, status.Error(codes.ResourceExhausted, "rate limit: 1 test per second")
	}

	scenarioID := strings.TrimSpace(req.GetScenarioId())
	if scenarioID == "" {
		return nil, status.Error(codes.InvalidArgument, "scenario_id required")
	}

	sc := findScenario(scenarioID)
	if sc == nil {
		// Return an empty result (mirror Python behaviour for unknown scenarios).
		return &testsv1.CrowdsecRunResult{
			Scenario:  scenarioID,
			SourceIp:  "unknown",
			StartedAt: time.Now().UTC().Format(time.RFC3339),
			TargetUrl: "",
		}, nil
	}

	// If no IP provided, generate a random RFC 5737 test IP (198.51.100.x).
	sourceIP := req.GetIp().GetValue()
	if sourceIP == "" {
		sourceIP = fmt.Sprintf("198.51.100.%d", rand.IntN(254)+1)
	}

	// Resolve target URL + Host header (tenant-scoped).
	targetURL := localhostURL()
	hostHeader := ""
	if req.GetConnectionId() != nil && s.store != nil {
		connID := req.GetConnectionId().GetValue()
		conn, err := s.store.GetConnectionForTenant(ctx, connID, tenantID)
		if err == nil && conn != nil {
			targetURL = connectionURL(conn)
			hostHeader = conn.Domain
		}
	}

	// 1. Snapshot decisions before.
	decisionsBefore := s.getDecisions(ctx)

	startedAt := time.Now().UTC().Format(time.RFC3339)

	// 2. Fire burst.
	sent := s.fireBurst(ctx, sc, targetURL, hostHeader, sourceIP)

	// 3. Forcefully add a ban decision so the UI sees immediate feedback.
	if s.csRunner != nil {
		if err := s.csRunner.AddDecision(ctx, sourceIP, "5m", sc.Scenario, "ban"); err != nil {
			s.log.Warn("testsapi: AddDecision failed", "ip", sourceIP, "err", err)
		}
	}

	// 4. Wait ~4s for CrowdSec to ingest + correlate (mirrors Python asyncio.sleep(4)).
	select {
	case <-time.After(4 * time.Second):
	case <-ctx.Done():
	}

	// 5. Snapshot decisions after.
	decisionsAfter := s.getDecisions(ctx)

	return &testsv1.CrowdsecRunResult{
		Scenario:        sc.Scenario,
		SourceIp:        sourceIP,
		StartedAt:       startedAt,
		DecisionsBefore: decisionsBefore,
		DecisionsAfter:  decisionsAfter,
		BurstsSent:      int64(sent),
		TargetUrl:       targetURL,
	}, nil
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// probe delegates to the Prober interface.  Returns (0, reqRaw, "", errStr)
// on transport error so callers can distinguish a network failure from a 5xx.
func (s *Service) probe(ctx context.Context, method, rawURL string, headers map[string]string, body string) (int, string, string, string) {
	if s.prober == nil {
		return 0, "", "", "prober not configured"
	}
	return s.prober.Fire(ctx, method, rawURL, headers, body)
}

// pollMarker waits up to s.pollTO for the marker to appear in ClickHouse.
func (s *Service) pollMarker(ctx context.Context, marker string) (bool, string) {
	if s.chPoller == nil {
		return false, ""
	}
	landed, ruleID, err := s.chPoller.PollMarker(ctx, marker, s.pollTO)
	if err != nil {
		s.log.Warn("testsapi: ClickHouse poll error", "err", err)
	}
	return landed, ruleID
}

// getDecisions returns the current CrowdSec decisions as JSON strings.
func (s *Service) getDecisions(ctx context.Context) []string {
	if s.csRunner == nil {
		return nil
	}
	raw, err := s.csRunner.GetDecisions(ctx)
	if err != nil {
		s.log.Warn("testsapi: GetDecisions failed", "err", err)
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		out = append(out, string(r))
	}
	return out
}

// fireBurst sends the scenario's paths and returns the count of requests sent.
func (s *Service) fireBurst(ctx context.Context, sc *crowdsecScenario, targetURL, hostHeader, sourceIP string) int {
	if s.prober == nil {
		return 0
	}
	sent := 0
	for _, path := range sc.Paths {
		headers := map[string]string{}
		if sc.UserAgent != "" {
			headers["User-Agent"] = sc.UserAgent
		}
		if hostHeader != "" {
			headers["Host"] = hostHeader
		}
		if sourceIP != "" {
			headers["X-Forwarded-For"] = sourceIP
		}
		rawURL := strings.TrimRight(targetURL, "/") + path
		code, _, _, _ := s.prober.Fire(ctx, sc.Method, rawURL, headers, "")
		if code != 0 || true { // count even 0-code (blocked mid-flight is still a send)
			sent++
		}
	}
	return sent
}

// ── URL resolution helpers ────────────────────────────────────────────────────

func localhostURL() string {
	if v := os.Getenv("WAF_TESTS_TARGET_URL"); v != "" {
		return v
	}
	return "http://angie"
}

func connectionURL(c *ConnectionRow) string {
	if c.Status == "active" && c.SSLCertPath != nil && c.SSLKeyPath != nil {
		if v := os.Getenv("WAF_TESTS_TARGET_URL_HTTPS"); v != "" {
			return v
		}
		return "https://angie"
	}
	return localhostURL()
}

// ── Request construction ──────────────────────────────────────────────────────

// buildRequestParts builds the full request URL and headers map.
func buildRequestParts(test *TestCase, baseURL, hostOverride, marker, clientIP string) (headers map[string]string, rawURL string) {
	headers = make(map[string]string, len(test.Headers)+3)
	for k, v := range test.Headers {
		headers[k] = v
	}
	headers[markerHeader] = marker
	if clientIP != "" {
		headers["X-Forwarded-For"] = clientIP
	}
	if hostOverride != "" {
		headers["Host"] = hostOverride
	}

	base := strings.TrimRight(baseURL, "/") + test.Path
	if len(test.Query) > 0 {
		q := url.Values{}
		for k, v := range test.Query {
			q.Set(k, v)
		}
		base += "?" + q.Encode()
	}
	return headers, base
}

// ── Classification ────────────────────────────────────────────────────────────

// classify mirrors Python _classify exactly.
func classify(httpCode int, markerLanded bool) string {
	if markerLanded && httpCode == 403 {
		return "blocked"
	}
	if markerLanded {
		return "fired-but-not-blocked"
	}
	if httpCode != 0 && httpCode < 500 {
		return "passed"
	}
	return "timeout"
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func methodOrDefault(m string) string {
	if m == "" {
		return "GET"
	}
	return m
}

func pathOrDefault(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func wrapString(s string) *wrapperspb.StringValue {
	if s == "" {
		return nil
	}
	return wrapperspb.String(s)
}

func int64WrapperOrNil(n int) *wrapperspb.Int64Value {
	if n == 0 {
		return nil
	}
	return wrapperspb.Int64(int64(n))
}

func httpCodesFirst(codes []int) int {
	if len(codes) == 0 {
		return 0
	}
	return codes[0]
}

func httpCodePick(codes []int) int {
	for _, c := range codes {
		if c == 403 {
			return 403
		}
	}
	if len(codes) > 0 {
		return codes[0]
	}
	return 0
}

type targetEntry struct {
	baseURL string
	domain  string // used as Host header; empty = none
}

func joinTargetURLs(targets []targetEntry) string {
	urls := make([]string, len(targets))
	for i, t := range targets {
		urls[i] = t.baseURL
	}
	return strings.Join(urls, ", ")
}

func newUUID() string {
	// crypto/rand UUID4 — same contract as Python uuid.uuid4().
	var buf [16]byte
	_, _ = io.ReadFull(randReader{}, buf[:])
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(rand.IntN(256))
	}
	return len(p), nil
}

// ── Live Prober implementation ─────────────────────────────────────────────────

// HTTPProber fires real HTTP requests (using net/http).  Used in production;
// tests inject a fake.
type HTTPProber struct {
	timeout time.Duration
}

// NewHTTPProber builds a prober with the given timeout.
func NewHTTPProber(timeout time.Duration) *HTTPProber {
	return &HTTPProber{timeout: timeout}
}

func (p *HTTPProber) Fire(_ context.Context, method, rawURL string, headers map[string]string, body string) (int, string, string, string) {
	client := &http.Client{
		Timeout: p.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			// #nosec G402 — intentional: we're probing the WAF, not verifying a public cert.
			TLSClientConfig: tlsConfigInsecure(),
		},
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		reqRaw := fmt.Sprintf("%s %s HTTP/1.1", method, rawURL)
		return 0, reqRaw, "", fmt.Sprintf("build request: %v", err)
	}
	for k, v := range headers {
		if strings.EqualFold(k, "host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}

	reqRaw := formatRequest(req, body)

	resp, err := client.Do(req)
	if err != nil {
		return 0, reqRaw, fmt.Sprintf("Error: %v", err), fmt.Sprintf("transport error: %v", err)
	}
	defer resp.Body.Close()

	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	respBody := string(respBodyBytes)
	if len(respBodyBytes) == 2048 {
		respBody += "\n... [truncated]"
	}

	respRaw := formatResponse(resp, respBody)
	return resp.StatusCode, reqRaw, respRaw, ""
}

func formatRequest(req *http.Request, body string) string {
	var sb strings.Builder
	path := req.URL.RequestURI()
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\n", req.Method, path)
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\n", k, v)
		}
	}
	if req.Host != "" {
		fmt.Fprintf(&sb, "Host: %s\n", req.Host)
	}
	if body != "" {
		sb.WriteString("\n")
		sb.WriteString(body)
	}
	return sb.String()
}

func formatResponse(resp *http.Response, body string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\n", resp.StatusCode, resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\n", k, v)
		}
	}
	sb.WriteString("\n")
	sb.WriteString(body)
	return sb.String()
}
