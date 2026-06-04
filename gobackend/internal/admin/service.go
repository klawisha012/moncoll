// Package admin implements the AdminService gRPC server.
// Operation order mirrors backend/src/admin/router.py exactly:
//   - suspend/unsuspend: fs rename → reload → DB update
//   - delete:            load tenant (404 gate) → confirm check (400 gate) → fs delete → reload → DB delete
package admin

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/zwarder/waf/gobackend/gen/admin/v1"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// Reader is the store surface the admin service needs.
type Reader interface {
	ListTenantSummaries(ctx context.Context) ([]store.TenantSummary, error)
	GetTenantDetail(ctx context.Context, id int64) (*store.TenantDetail, error)
	GetTenantByID(ctx context.Context, id int64) (*store.Tenant, error)
	SuspendTenant(ctx context.Context, id int64) (*store.Tenant, error)
	UnsuspendTenant(ctx context.Context, id int64) (*store.Tenant, error)
	DeleteTenant(ctx context.Context, id int64) error
}

// FSOps manipulates the per-tenant compose tree on disk.
type FSOps interface {
	Suspend(id int64) error
	Unsuspend(id int64) error
	Delete(id int64) error
}

// Reloader triggers an Angie config reload (best-effort; never returns an error).
type Reloader interface{ Reload(ctx context.Context) }

// Service implements adminv1.AdminServiceServer.
type Service struct {
	adminv1.UnimplementedAdminServiceServer
	store    Reader
	fs       FSOps
	reloader Reloader
}

// NewService constructs a ready-to-register Service.
func NewService(s Reader, fs FSOps, r Reloader) *Service {
	return &Service{store: s, fs: fs, reloader: r}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// tsToProto converts a nullable *time.Time to a proto Timestamp (nil-safe).
func tsToProto(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

// strDeref dereferences a nullable string pointer (nil → "").
func strDeref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// ---------------------------------------------------------------------------
// RPC implementations — order matches Python router.py
// ---------------------------------------------------------------------------

// ListTenants returns a summary list of all tenants.
func (s *Service) ListTenants(ctx context.Context, _ *adminv1.ListTenantsRequest) (*adminv1.ListTenantsResponse, error) {
	rows, err := s.store.ListTenantSummaries(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := make([]*adminv1.TenantSummary, len(rows))
	for i, r := range rows {
		out[i] = &adminv1.TenantSummary{
			Id:              r.ID,
			Name:            r.Name,
			DisplayName:     r.DisplayName,
			OwnerEmail:      strDeref(r.OwnerEmail),
			UserCount:       r.UserCount,
			ConnectionCount: r.ConnectionCount,
			CreatedAt:       tsToProto(&r.CreatedAt),
			SuspendedAt:     tsToProto(r.SuspendedAt),
			LastActivity:    tsToProto(r.LastActivity),
		}
	}
	return &adminv1.ListTenantsResponse{Tenants: out}, nil
}

// GetTenant returns the full detail for a single tenant (404 when not found).
func (s *Service) GetTenant(ctx context.Context, req *adminv1.GetTenantRequest) (*adminv1.TenantDetail, error) {
	d, err := s.store.GetTenantDetail(ctx, req.TenantId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if d == nil {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}

	users := make([]*adminv1.TenantUser, len(d.Users))
	for i, u := range d.Users {
		users[i] = &adminv1.TenantUser{
			Id:            u.ID,
			Email:         u.Email,
			TenantRole:    strDeref(u.TenantRole),
			LastLoginAt:   tsToProto(u.LastLoginAt),
			EmailVerified: u.EmailVerified,
			TotpEnabled:   u.TotpEnabled,
		}
	}
	conns := make([]*adminv1.TenantConnection, len(d.Connections))
	for i, c := range d.Connections {
		conns[i] = &adminv1.TenantConnection{
			Id:     c.ID,
			Name:   c.Name,
			Domain: c.Domain,
			Status: c.Status,
		}
	}
	return &adminv1.TenantDetail{
		Tenant: &adminv1.TenantCore{
			Id:          d.Tenant.ID,
			Name:        d.Tenant.Name,
			DisplayName: d.Tenant.DisplayName,
			CreatedAt:   tsToProto(&d.Tenant.CreatedAt),
			SuspendedAt: tsToProto(d.Tenant.SuspendedAt),
		},
		Users:       users,
		Connections: conns,
	}, nil
}

// SuspendTenant mirrors Python order: fs rename → reload → DB update.
func (s *Service) SuspendTenant(ctx context.Context, req *adminv1.TenantIdRequest) (*adminv1.SuspendResponse, error) {
	if err := s.fs.Suspend(req.TenantId); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.reloader.Reload(ctx)

	t, err := s.store.SuspendTenant(ctx, req.TenantId)
	if err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, status.Error(codes.NotFound, "tenant not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &adminv1.SuspendResponse{SuspendedAt: tsToProto(t.SuspendedAt)}, nil
}

// UnsuspendTenant mirrors Python order: fs rename → reload → DB update.
func (s *Service) UnsuspendTenant(ctx context.Context, req *adminv1.TenantIdRequest) (*adminv1.SuspendResponse, error) {
	if err := s.fs.Unsuspend(req.TenantId); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.reloader.Reload(ctx)

	t, err := s.store.UnsuspendTenant(ctx, req.TenantId)
	if err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, status.Error(codes.NotFound, "tenant not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &adminv1.SuspendResponse{SuspendedAt: tsToProto(t.SuspendedAt)}, nil
}

// DeleteTenant mirrors Python order: existence check → confirm check → fs delete → reload → DB delete.
func (s *Service) DeleteTenant(ctx context.Context, req *adminv1.DeleteTenantRequest) (*emptypb.Empty, error) {
	t, err := s.store.GetTenantByID(ctx, req.TenantId)
	if err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, status.Error(codes.NotFound, "tenant not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	if req.Confirm != t.Name {
		return nil, status.Error(codes.InvalidArgument, "confirm value must equal tenant name")
	}

	if err := s.fs.Delete(req.TenantId); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.reloader.Reload(ctx)

	if err := s.store.DeleteTenant(ctx, req.TenantId); err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, status.Error(codes.NotFound, "tenant not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &emptypb.Empty{}, nil
}
