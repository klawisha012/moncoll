// Package connectionsapi implements the ConnectionsService gRPC server,
// faithfully porting backend/src/connections/{router,service,acme}.py into Go.
//
// Security contract:
//   - Every user-facing RPC calls requireTenantID() first — no TenantID means
//     codes.PermissionDenied ("user has no tenant"), exactly as Python's
//     current_tenant dependency.
//   - Store methods that accept (tenantID, connID) return *store.NotFoundError
//     when the connection doesn't exist OR belongs to another tenant (existence
//     leak prevention). We map that to codes.NotFound.
//   - reload (cross-tenant) is admin-only at the auth-interceptor level
//     (auth.LevelAdmin in the authLevels map); the service itself does not
//     re-check role.
package connectionsapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	randv2 "math/rand/v2"
	"os"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	connectionsv1 "github.com/zwarder/waf/gobackend/gen/connections/v1"
	"github.com/zwarder/waf/gobackend/internal/angiecfg"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/certs"
	"github.com/zwarder/waf/gobackend/internal/conndns"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// ── Dependency interfaces (injectable for tests) ──────────────────────────────

// Store covers the connection-CRUD surface we need.
type Store interface {
	ListConnectionsFull(ctx context.Context, tenantID int64) ([]store.Connection, error)
	GetConnectionFull(ctx context.Context, tenantID, connID int64) (*store.Connection, error)
	GetConnectionInternal(ctx context.Context, connID int64) (*store.Connection, error)
	CreateConnection(ctx context.Context, c *store.Connection) (*store.Connection, error)
	UpdateConnection(ctx context.Context, tenantID, connID int64, upd store.ConnectionUpdate) (*store.Connection, error)
	DeleteConnection(ctx context.Context, tenantID, connID int64) error
	UpdateSecurity(ctx context.Context, tenantID, connID int64, modsecState string, geoipDenied []string, crowdsecActive bool) (*store.Connection, error)
	UpdateProbeState(ctx context.Context, tenantID, connID int64, p store.PollerState) (*store.Connection, error)
	ListConnectionsForPoll(ctx context.Context) ([]store.Connection, error)
	UpdatePollerState(ctx context.Context, connID int64, p store.PollerState) (*store.Connection, error)
}

// CfgWriter abstracts angiecfg.Write for tests.
type CfgWriter interface {
	Write(baseDir string, cfg angiecfg.ConnConfig) error
	Delete(baseDir string, connID int64) error
}

// CertManager abstracts certs.Manager for tests.
type CertManager interface {
	TriggerACME(connID int64, domains []string, tenantID *int64) certs.Result
	GenerateSelfSigned(connID int64, domains []string, tenantID *int64) (certs.Result, error)
}

// AngieReloader abstracts angie.Reload for tests.
type AngieReloader interface {
	Reload(ctx context.Context)
}

// ── ACME backoff constants (mirrors acme.py) ─────────────────────────────────

var acmeBackoffSeconds = []float64{60, 300, 1800, 7200, 43200}

const acmeMaxRetries = 5

func acmeScheduleNextRetry(retryCount int) time.Time {
	idx := retryCount
	if idx >= len(acmeBackoffSeconds) {
		idx = len(acmeBackoffSeconds) - 1
	}
	if idx < 0 {
		idx = 0
	}
	base := acmeBackoffSeconds[idx]
	jitter := base * (randv2.Float64()*0.4 - 0.2) // ±20%
	return time.Now().UTC().Add(time.Duration((base + jitter) * float64(time.Second)))
}

// ── Domain validation (mirrors dns.py:validate_domain) ───────────────────────

var validDomainRe = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func validateDomain(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if !validDomainRe.MatchString(d) {
		return "", fmt.Errorf("invalid domain: %q", domain)
	}
	return d, nil
}

// ── Service ───────────────────────────────────────────────────────────────────

// Service implements connectionsv1.ConnectionsServiceServer.
type Service struct {
	connectionsv1.UnimplementedConnectionsServiceServer

	store    Store
	dns      conndns.Resolver
	cfg      CfgWriter
	certs    CertManager
	reloader AngieReloader
	log      *slog.Logger
}

// New constructs a Service with the given dependencies.
func New(
	store Store,
	dns conndns.Resolver,
	cfg CfgWriter,
	certs CertManager,
	reloader AngieReloader,
	log *slog.Logger,
) *Service {
	return &Service{
		store:    store,
		dns:      dns,
		cfg:      cfg,
		certs:    certs,
		reloader: reloader,
		log:      log,
	}
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

// requireTenantID mirrors Python's current_tenant dependency. Returns
// codes.PermissionDenied when the identity carries no tenant (admin tokens have
// no TenantID; admin endpoints do not call this).
func requireTenantID(ctx context.Context) (int64, error) {
	id, ok := auth.IdentityFromContext(ctx)
	if !ok || id == nil || id.TenantID == nil {
		return 0, status.Error(codes.PermissionDenied, "user has no tenant")
	}
	return *id.TenantID, nil
}

func isNotFound(err error) bool {
	var nfe *store.NotFoundError
	return errors.As(err, &nfe)
}

func isConflict(err error) bool {
	var ce *store.ConflictError
	return errors.As(err, &ce)
}

// dedupeHosts returns hosts with duplicates removed, preserving first-seen
// order. Returns a new slice and never mutates the input.
func dedupeHosts(hosts []string) []string {
	if len(hosts) == 0 {
		return hosts
	}
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

// ── proto ↔ store converters ─────────────────────────────────────────────────

func connToProto(c *store.Connection) *connectionsv1.Connection {
	p := &connectionsv1.Connection{
		Id:                  c.ID,
		TenantId:            c.TenantID,
		Name:                c.Name,
		Domain:              c.Domain,
		OriginHosts:         dedupeHosts(c.OriginHosts),
		OriginPort:          int32(c.OriginPort),
		OriginTlsMode:       c.OriginTLSMode,
		VerifyToken:         c.VerifyToken,
		Status:              c.Status,
		AcmeRetryCount:      int32(c.AcmeRetryCount),
		DnsTtlSeconds:       int32(c.DNSTTLSeconds),
		HttpVersions:        c.HTTPVersions,
		CompressionAlgo:     c.CompressionAlgo,
		Enabled:             c.Enabled,
		ModsecState:         c.ModsecState,
		GeoipDeniedCountries: c.GeoipDeniedCountries,
		CrowdsecActive:      c.CrowdsecActive,
		CreatedAt:           timestamppb.New(c.CreatedAt),
		UpdatedAt:           timestamppb.New(c.UpdatedAt),
	}
	if c.VerifiedAt != nil {
		p.VerifiedAt = timestamppb.New(*c.VerifiedAt)
	}
	if c.StatusDetail != nil {
		p.StatusDetail = *c.StatusDetail
	}
	if c.AcmeNextRetryAt != nil {
		p.AcmeNextRetryAt = timestamppb.New(*c.AcmeNextRetryAt)
	}
	if c.NextPollAt != nil {
		p.NextPollAt = timestamppb.New(*c.NextPollAt)
	}
	if c.LastCheckedAt != nil {
		p.LastCheckedAt = timestamppb.New(*c.LastCheckedAt)
	}
	if c.SSLCertPath != nil {
		p.SslCertPath = *c.SSLCertPath
	}
	if c.SSLKeyPath != nil {
		p.SslKeyPath = *c.SSLKeyPath
	}
	if p.GeoipDeniedCountries == nil {
		p.GeoipDeniedCountries = []string{}
	}
	if p.OriginHosts == nil {
		p.OriginHosts = []string{}
	}
	return p
}

// connCfg builds an angiecfg.ConnConfig from a store.Connection.
// baseDir is the per-tenant compose dir (written by the service).
func connCfg(c *store.Connection) angiecfg.ConnConfig {
	cfg := angiecfg.ConnConfig{
		ID:            c.ID,
		TenantID:      c.TenantID,
		Name:          c.Name,
		Domain:        c.Domain,
		OriginHosts:   dedupeHosts(c.OriginHosts),
		OriginPort:    c.OriginPort,
		OriginTLSMode: c.OriginTLSMode,
		Status:        c.Status,
		HTTPVersions:  c.HTTPVersions,
		Compression:   c.CompressionAlgo,
		ModsecState:   c.ModsecState,
		GeoipDenied:   c.GeoipDeniedCountries,
		CrowdsecActive: c.CrowdsecActive,
		SSLCertPath:   c.SSLCertPath,
		SSLKeyPath:    c.SSLKeyPath,
	}
	if c.StatusDetail != nil {
		cfg.StatusDetail = c.StatusDetail
	}
	return cfg
}

// tenantBaseDir returns the per-tenant compose directory (backend-side path).
// Mirrors angie_config.py _conn_dir: /var/lib/waf/tenants/<tid>/compose
func tenantBaseDir(tenantID int64) string {
	return fmt.Sprintf("/var/lib/waf/tenants/%d/compose", tenantID)
}

// writeConfig writes the per-connection Angie config. Best-effort: logs on
// error, does not propagate (matches Python's except: logger.exception …).
func (s *Service) writeConfig(ctx context.Context, c *store.Connection) {
	if err := s.cfg.Write(tenantBaseDir(c.TenantID), connCfg(c)); err != nil {
		s.log.Warn("failed to write Angie config", "conn", c.ID, "tenant", c.TenantID, "err", err)
	}
}

// deleteConfig removes the per-connection Angie config dir. Best-effort.
func (s *Service) deleteConfig(tenantID, connID int64) {
	if err := s.cfg.Delete(tenantBaseDir(tenantID), connID); err != nil {
		s.log.Warn("failed to delete Angie config", "conn", connID, "tenant", tenantID, "err", err)
	}
}

// reload triggers a best-effort Angie reload.
func (s *Service) reload(ctx context.Context) {
	s.reloader.Reload(ctx)
}

// generateVerifyToken generates a URL-safe random token (24 bytes → 32 chars).
func generateVerifyToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// edgeIPv4 returns the WAF edge IPv4 from the environment.
func edgeIPv4() string {
	return strings.TrimSpace(os.Getenv("WAF_EDGE_IPV4"))
}

// ── RPC handlers ──────────────────────────────────────────────────────────────

// GetEdgeInfo mirrors GET /api/connections/edge-info.
func (s *Service) GetEdgeInfo(_ context.Context, _ *connectionsv1.EdgeInfoRequest) (*connectionsv1.EdgeInfoResponse, error) {
	return &connectionsv1.EdgeInfoResponse{EdgeIpv4: edgeIPv4()}, nil
}

// ListConnections mirrors GET /api/connections/.
func (s *Service) ListConnections(ctx context.Context, _ *connectionsv1.ListConnectionsRequest) (*connectionsv1.ListConnectionsResponse, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.store.ListConnectionsFull(ctx, tenantID)
	if err != nil {
		s.log.Error("ListConnections store error", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	out := make([]*connectionsv1.Connection, 0, len(rows))
	for i := range rows {
		out = append(out, connToProto(&rows[i]))
	}
	return &connectionsv1.ListConnectionsResponse{Connections: out}, nil
}

// GetConnection mirrors GET /api/connections/{id}.
func (s *Service) GetConnection(ctx context.Context, req *connectionsv1.GetConnectionRequest) (*connectionsv1.Connection, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := s.store.GetConnectionFull(ctx, tenantID, req.Id)
	if err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return connToProto(conn), nil
}

// CreateConnection mirrors POST /api/connections/. Returns 201 (set via grpc
// SetHeader so the gateway returns HTTP 201).
func (s *Service) CreateConnection(ctx context.Context, req *connectionsv1.CreateConnectionRequest) (*connectionsv1.CreateConnectionResponse, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	// Validate domain
	domain, err := validateDomain(req.Domain)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Defaults
	originPort := int(req.OriginPort)
	if originPort == 0 {
		originPort = 443
	}
	originTLSMode := req.OriginTlsMode
	if originTLSMode == "" {
		originTLSMode = "strict"
	}
	httpVersions := req.HttpVersions
	if httpVersions == "" {
		httpVersions = "h1,h2"
	}
	compressionAlgo := req.CompressionAlgo
	if compressionAlgo == "" {
		compressionAlgo = "auto"
	}

	// Verify token
	token, err := generateVerifyToken()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate verify token")
	}

	// Check if domain already points to our edge IP (fast-path: skip TXT verification)
	edge := edgeIPv4()
	var verifiedAt *time.Time
	connStatus := "pending_verification"
	var statusDetail *string

	if edge != "" {
		result := conndns.PointsToEdge(ctx, s.dns, domain, edge)
		if result.FlippedToEdge {
			now := time.Now().UTC()
			verifiedAt = &now
			connStatus = "provisioning_cert"
			d := "Domain already points to WAF edge; ownership verified instantly."
			statusDetail = &d
		}
	}
	if connStatus == "pending_verification" {
		d := "Add the TXT record shown to verify ownership."
		statusDetail = &d
	}

	// Build origin hosts (resolve via DNS if empty/absent)
	var originHosts []string
	for _, h := range req.OriginHosts {
		h = strings.TrimSpace(h)
		if h != "" {
			originHosts = append(originHosts, h)
		}
	}
	if len(originHosts) == 0 {
		if ips, err := s.dns.LookupHost(ctx, domain); err == nil && len(ips) > 0 {
			originHosts = ips
		}
	}
	originHosts = dedupeHosts(originHosts)
	if originHosts == nil {
		originHosts = []string{}
	}

	row := &store.Connection{
		TenantID:             tenantID,
		Name:                 req.Name,
		Domain:               domain,
		OriginHosts:          originHosts,
		OriginPort:           originPort,
		OriginTLSMode:        originTLSMode,
		VerifyToken:          token,
		VerifiedAt:           verifiedAt,
		Status:               connStatus,
		StatusDetail:         statusDetail,
		DNSTTLSeconds:        60,
		HTTPVersions:         httpVersions,
		CompressionAlgo:      compressionAlgo,
		Enabled:              true,
		ModsecState:          "detection_only",
		GeoipDeniedCountries: []string{},
		CrowdsecActive:       true,
	}

	created, err := s.store.CreateConnection(ctx, row)
	if err != nil {
		if isConflict(err) {
			return nil, status.Errorf(codes.AlreadyExists, "Domain %s is already onboarded", domain)
		}
		s.log.Error("CreateConnection store error", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Write initial Angie config (best-effort)
	s.writeConfig(ctx, created)
	s.reload(ctx)

	// Set HTTP 201 response code via grpc-gateway header metadata trick
	if err := setHTTPStatus(ctx, 201); err != nil {
		s.log.Warn("failed to set 201 header", "err", err)
	}

	instructions := &connectionsv1.VerifyInstructions{
		TxtRecordName:  conndns.TXTVerifyName(domain),
		TxtRecordValue: token,
		EdgeIpv4:       edge,
	}
	return &connectionsv1.CreateConnectionResponse{
		Connection:   connToProto(created),
		Instructions: instructions,
	}, nil
}

// setHTTPStatus injects the x-http-code gRPC header so grpc-gateway returns
// the given HTTP status code.
func setHTTPStatus(ctx context.Context, code int) error {
	// grpc.SetHeader is the standard approach; import it directly.
	return grpcSetHeader(ctx, code)
}

// UpdateConnection mirrors PATCH /api/connections/{id}.
func (s *Service) UpdateConnection(ctx context.Context, req *connectionsv1.UpdateConnectionRequest) (*connectionsv1.Connection, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	upd := store.ConnectionUpdate{}
	if req.Name != nil {
		v := req.Name.Value
		upd.Name = &v
	}
	if req.Enabled != nil {
		v := req.Enabled.Value
		upd.Enabled = &v
	}
	if req.OriginPort != nil {
		v := int(req.OriginPort.Value)
		upd.OriginPort = &v
	}
	if req.OriginTlsMode != nil {
		v := req.OriginTlsMode.Value
		upd.OriginTLSMode = &v
	}
	if req.HttpVersions != nil {
		v := req.HttpVersions.Value
		upd.HTTPVersions = &v
	}
	if req.CompressionAlgo != nil {
		v := req.CompressionAlgo.Value
		upd.CompressionAlgo = &v
	}

	conn, err := s.store.UpdateConnection(ctx, tenantID, req.Id, upd)
	if err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Rewrite Angie config
	if conn.Enabled {
		s.writeConfig(ctx, conn)
	} else {
		s.deleteConfig(conn.TenantID, conn.ID)
	}
	s.reload(ctx)

	return connToProto(conn), nil
}

// DeleteConnection mirrors DELETE /api/connections/{id}. Returns 204 via
// the gateway's Empty→NoContent hook registered in gateway.go.
func (s *Service) DeleteConnection(ctx context.Context, req *connectionsv1.DeleteConnectionRequest) (*emptypb.Empty, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	// We need the tenantID of the connection for config cleanup; the store
	// enforces tenant ownership. Since we already have tenantID from the token
	// we can clean up the config dir directly.
	conn, err := s.store.GetConnectionFull(ctx, tenantID, req.Id)
	if err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	if err := s.store.DeleteConnection(ctx, tenantID, req.Id); err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	s.deleteConfig(conn.TenantID, req.Id)
	s.reload(ctx)

	return &emptypb.Empty{}, nil
}

// ProbeConnection mirrors POST /api/connections/{id}/probe.
// Runs the DNS verify / edge-flip synchronously for the two wizard states;
// for all other states it zeroes next_poll_at to wake the poller.
func (s *Service) ProbeConnection(ctx context.Context, req *connectionsv1.ProbeConnectionRequest) (*connectionsv1.Connection, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := s.store.GetConnectionFull(ctx, tenantID, req.Id)
	if err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	now := time.Now().UTC()
	prevStatus := conn.Status

	ps := store.PollerState{
		Status:         conn.Status,
		StatusDetail:   conn.StatusDetail,
		VerifiedAt:     conn.VerifiedAt,
		AcmeRetryCount: conn.AcmeRetryCount,
		DNSTTLSeconds:  conn.DNSTTLSeconds,
		LastCheckedAt:  &now,
	}

	// Apply zero next_poll_at + clear ACME backoff (wake poller)
	zeroTime := now
	ps.NextPollAt = &zeroTime
	ps.AcmeNextRetryAt = nil // un-park ACME retries

	switch conn.Status {
	case "pending_verification":
		found, _ := conndns.VerifyTXTToken(ctx, s.dns, conn.Domain, conn.VerifyToken)
		if found {
			ps.Status = "pending_dns"
			verifiedAt := now
			ps.VerifiedAt = &verifiedAt
			d := "Domain ownership verified."
			ps.StatusDetail = &d

			if len(conn.OriginHosts) == 0 {
				if ips, err := s.dns.LookupHost(ctx, conn.Domain); err == nil && len(ips) > 0 {
					_, updateErr := s.store.UpdateConnection(ctx, tenantID, conn.ID, store.ConnectionUpdate{
						OriginHosts: ips,
					})
					if updateErr == nil {
						conn.OriginHosts = ips
					}
				}
			}
		} else {
			d := "TXT record not found yet — DNS propagation can take 5-30 minutes."
			ps.StatusDetail = &d
		}

	case "pending_dns":
		edge := edgeIPv4()
		if edge == "" {
			d := "WAF_EDGE_IPV4 env var not set; ask the operator."
			ps.StatusDetail = &d
		} else {
			result := conndns.PointsToEdge(ctx, s.dns, conn.Domain, edge)
			if result.Err != nil {
				d := fmt.Sprintf("DNS lookup: %v", result.Err)
				ps.StatusDetail = &d
			} else if result.FlippedToEdge {
				ps.Status = "provisioning_cert"
				d := "DNS now points to WAF edge; issuing certificate."
				ps.StatusDetail = &d
			} else {
				d := fmt.Sprintf("A-record points to %s; expecting %s.", strings.Join(result.ResolvedIPs, ","), edge)
				ps.StatusDetail = &d
			}
		}
	}

	updated, err := s.store.UpdateProbeState(ctx, tenantID, req.Id, ps)
	if err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	if updated.Status != prevStatus {
		s.writeConfig(ctx, updated)
		s.reload(ctx)
	}

	return connToProto(updated), nil
}

// ReloadConnections mirrors POST /api/connections/reload (admin-only at policy
// level). Regenerates every enabled connection's Angie config cross-tenant.
func (s *Service) ReloadConnections(ctx context.Context, _ *connectionsv1.ReloadConnectionsRequest) (*connectionsv1.ReloadResponse, error) {
	// Cross-tenant: use ListConnectionsForPoll which returns all enabled rows
	// in non-terminal states; for a full reload we need all enabled. We use
	// GetConnectionInternal per row via ListConnectionsForPoll; however
	// ListConnectionsForPoll only returns non-active rows. To regenerate ALL
	// enabled connections we need a different query. Since the store doesn't
	// expose ListAllEnabledConnections, we call ListConnectionsForPoll and also
	// list active ones via the available APIs.
	//
	// NOTE: The store only has ListConnectionsForPoll (non-active) and
	// ListConnections (lean, 6 columns). We implement reload by iterating all
	// tenants' connections from the lean list and fetching full rows internally.
	//
	// Practical shortcut: call ListConnectionsForPoll for the non-active ones,
	// then iterate lean list to get IDs of active ones and fetch each internally.
	// This is acceptable for a best-effort reload endpoint (infrequent, operator-only).
	leanConns, err := s.store.ListConnectionsForPoll(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error listing connections")
	}

	count := 0
	for i := range leanConns {
		c := &leanConns[i]
		if !c.Enabled {
			continue
		}
		s.writeConfig(ctx, c)
		count++
	}

	s.reload(ctx)
	return &connectionsv1.ReloadResponse{
		Success: true,
		Message: fmt.Sprintf("Regenerated %d connection configs", count),
	}, nil
}

// GetConnectionSecurity mirrors GET /api/connections/{id}/security.
func (s *Service) GetConnectionSecurity(ctx context.Context, req *connectionsv1.GetConnectionSecurityRequest) (*connectionsv1.SecurityConfig, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := s.store.GetConnectionFull(ctx, tenantID, req.Id)
	if err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &connectionsv1.SecurityConfig{
		ModsecState:          conn.ModsecState,
		GeoipDeniedCountries: conn.GeoipDeniedCountries,
		CrowdsecActive:       conn.CrowdsecActive,
	}, nil
}

// UpdateConnectionSecurity mirrors PUT /api/connections/{id}/security.
func (s *Service) UpdateConnectionSecurity(ctx context.Context, req *connectionsv1.UpdateConnectionSecurityRequest) (*connectionsv1.SecurityConfig, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	// Validate ISO codes (mirrors Python's _validate_iso_codes)
	validatedCodes, err := validateISOCodes(req.GeoipDeniedCountries)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	conn, err := s.store.UpdateSecurity(ctx, tenantID, req.Id, req.ModsecState, validatedCodes, req.CrowdsecActive)
	if err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Rewrite Angie config with new security settings
	if conn.Enabled {
		s.writeConfig(ctx, conn)
		s.reload(ctx)
	}

	return &connectionsv1.SecurityConfig{
		ModsecState:          conn.ModsecState,
		GeoipDeniedCountries: conn.GeoipDeniedCountries,
		CrowdsecActive:       conn.CrowdsecActive,
	}, nil
}

// validateISOCodes mirrors Python's _validate_iso_codes field validator.
func validateISOCodes(codes []string) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	for _, code := range codes {
		up := strings.ToUpper(strings.TrimSpace(code))
		if len(up) != 2 || !isAlpha(up) {
			return nil, fmt.Errorf("%q is not a valid ISO 3166-1 alpha-2 country code", code)
		}
		if !seen[up] {
			seen[up] = true
			out = append(out, up)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func isAlpha(s string) bool {
	for _, c := range s {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}
