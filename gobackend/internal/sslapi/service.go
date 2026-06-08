// Package sslapi implements the SSLService gRPC server, faithfully porting
// backend/src/certificates/router.py into Go.
//
// Security contract: every RPC reproduces the current_tenant dependency:
//   - If the caller's Identity.TenantID is nil (e.g. admin token), the RPC
//     returns codes.PermissionDenied with "user has no tenant" — exactly what
//     Python's current_tenant raises (HTTP 403, detail "user has no tenant").
//   - GetConnectionForTenant enforces tenant ownership: a tenant can only touch
//     its own connections (codes.NotFound "Connection not found" otherwise).
package sslapi

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sslv1 "github.com/zwarder/waf/gobackend/gen/ssl/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/certs"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// ConnectionResolver resolves a connection scoped to a tenant. Satisfied by
// *store.Store (via StoreResolver) and by fakes in tests.
type ConnectionResolver interface {
	GetConnectionForTenant(ctx context.Context, connID, tenantID int64) (*store.Connection, error)
}

// CertManager is the certificate operations interface. Satisfied by
// *certs.Manager and by fakeCertManager in tests.
type CertManager interface {
	CheckStatus(connID int64, tenantID *int64) certs.StatusResult
	TriggerACME(connID int64, domains []string, tenantID *int64) certs.Result
	Regenerate(connID int64, domains []string, tenantID *int64) certs.Result
}

// Service implements sslv1.SSLServiceServer.
type Service struct {
	sslv1.UnimplementedSSLServiceServer
	resolver ConnectionResolver
	manager  CertManager
}

// New constructs a Service with the given resolver and manager.
func New(resolver ConnectionResolver, manager CertManager) *Service {
	return &Service{resolver: resolver, manager: manager}
}

func (s *Service) AuthLevels() map[string]auth.Level {
	return map[string]auth.Level{
		sslv1.SSLService_GetCertificateStatus_FullMethodName:  auth.LevelVerified,
		sslv1.SSLService_RequestCertificate_FullMethodName:    auth.LevelVerified,
		sslv1.SSLService_RegenerateCertificate_FullMethodName: auth.LevelVerified,
	}
}

// ── current_tenant equivalent ─────────────────────────────────────────────────

// requireTenantID extracts Identity.TenantID from ctx. If the identity is
// absent or TenantID is nil it returns codes.PermissionDenied with the exact
// detail string Python's current_tenant raises ("user has no tenant").
func requireTenantID(ctx context.Context) (int64, error) {
	id, ok := auth.IdentityFromContext(ctx)
	if !ok || id == nil {
		return 0, status.Error(codes.PermissionDenied, "user has no tenant")
	}
	if id.TenantID == nil {
		return 0, status.Error(codes.PermissionDenied, "user has no tenant")
	}
	return *id.TenantID, nil
}

// ── RPC handlers ──────────────────────────────────────────────────────────────

// GetCertificateStatus mirrors GET /api/ssl/status/{connection_id}.
func (s *Service) GetCertificateStatus(ctx context.Context, req *sslv1.ConnIdRequest) (*sslv1.StatusResponse, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	_, err = s.resolver.GetConnectionForTenant(ctx, req.ConnectionId, tenantID)
	if err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	tid := tenantID
	sr := s.manager.CheckStatus(req.ConnectionId, &tid)
	return statusResultToProto(sr), nil
}

// RequestCertificate mirrors POST /api/ssl/request/{connection_id}.
func (s *Service) RequestCertificate(ctx context.Context, req *sslv1.RequestCertRequest) (*sslv1.CertResponse, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := s.resolver.GetConnectionForTenant(ctx, req.ConnectionId, tenantID)
	if err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	// Mirrors Python: domains = request.domains or [conn.domain]
	domains := req.Domains
	if len(domains) == 0 {
		domains = []string{conn.Domain}
	}

	tid := tenantID
	result := s.manager.TriggerACME(req.ConnectionId, domains, &tid)
	return resultToProto(result), nil
}

// RegenerateCertificate mirrors POST /api/ssl/regenerate/{connection_id}.
func (s *Service) RegenerateCertificate(ctx context.Context, req *sslv1.ConnIdRequest) (*sslv1.CertResponse, error) {
	tenantID, err := requireTenantID(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := s.resolver.GetConnectionForTenant(ctx, req.ConnectionId, tenantID)
	if err != nil {
		if isNotFound(err) {
			return nil, status.Error(codes.NotFound, "Connection not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	tid := tenantID
	result := s.manager.Regenerate(req.ConnectionId, []string{conn.Domain}, &tid)
	return resultToProto(result), nil
}

// ── mapping helpers ───────────────────────────────────────────────────────────

func resultToProto(r certs.Result) *sslv1.CertResponse {
	return &sslv1.CertResponse{
		Success:         r.Success,
		Message:         r.Message,
		CertificatePath: r.CertificatePath,
		KeyPath:         r.KeyPath,
		BackendCertPath: r.BackendCertPath,
		BackendKeyPath:  r.BackendKeyPath,
	}
}

func statusResultToProto(sr certs.StatusResult) *sslv1.StatusResponse {
	resp := &sslv1.StatusResponse{
		CertificateExists: sr.CertificateExists,
		KeyExists:         sr.KeyExists,
	}
	if sr.CertificatePath != nil {
		resp.CertificatePath = *sr.CertificatePath
	}
	if sr.KeyPath != nil {
		resp.KeyPath = *sr.KeyPath
	}
	if sr.BackendCertPath != nil {
		resp.BackendCertPath = *sr.BackendCertPath
	}
	if sr.BackendKeyPath != nil {
		resp.BackendKeyPath = *sr.BackendKeyPath
	}
	return resp
}

func isNotFound(err error) bool {
	var nf *store.NotFoundError
	return errors.As(err, &nf)
}
