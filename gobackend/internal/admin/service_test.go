package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	adminv1 "github.com/zwarder/waf/gobackend/gen/admin/v1"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type fakeReader struct {
	// per-method configured returns
	listSummariesOut []store.TenantSummary
	listSummariesErr error

	detailOut *store.TenantDetail
	detailErr error

	tenantByIDOut *store.Tenant
	tenantByIDErr error

	suspendOut *store.Tenant
	suspendErr error

	unsuspendOut *store.Tenant
	unsuspendErr error

	deleteErr error

	// call-order log (shared with fs/reloader)
	log *[]string
}

func (f *fakeReader) ListTenantSummaries(_ context.Context) ([]store.TenantSummary, error) {
	return f.listSummariesOut, f.listSummariesErr
}
func (f *fakeReader) GetTenantDetail(_ context.Context, _ int64) (*store.TenantDetail, error) {
	return f.detailOut, f.detailErr
}
func (f *fakeReader) GetTenantByID(_ context.Context, _ int64) (*store.Tenant, error) {
	return f.tenantByIDOut, f.tenantByIDErr
}
func (f *fakeReader) SuspendTenant(_ context.Context, _ int64) (*store.Tenant, error) {
	*f.log = append(*f.log, "store.Suspend")
	return f.suspendOut, f.suspendErr
}
func (f *fakeReader) UnsuspendTenant(_ context.Context, _ int64) (*store.Tenant, error) {
	*f.log = append(*f.log, "store.Unsuspend")
	return f.unsuspendOut, f.unsuspendErr
}
func (f *fakeReader) DeleteTenant(_ context.Context, _ int64) error {
	*f.log = append(*f.log, "store.Delete")
	return f.deleteErr
}

type fakeFS struct {
	suspendErr   error
	unsuspendErr error
	deleteErr    error
	log          *[]string
}

func (f *fakeFS) Suspend(_ context.Context, _ int64) error {
	*f.log = append(*f.log, "fs.Suspend")
	return f.suspendErr
}
func (f *fakeFS) Unsuspend(_ context.Context, _ int64) error {
	*f.log = append(*f.log, "fs.Unsuspend")
	return f.unsuspendErr
}
func (f *fakeFS) Delete(_ context.Context, _ int64) error {
	*f.log = append(*f.log, "fs.Delete")
	return f.deleteErr
}

type fakeReloader struct{ log *[]string }

func (r *fakeReloader) Reload(_ context.Context) { *r.log = append(*r.log, "reload") }

// ---------------------------------------------------------------------------
// Helper: build a Service with a shared order log
// ---------------------------------------------------------------------------

func newSvc(log *[]string, r *fakeReader, fs *fakeFS) *Service {
	r.log = log
	fs.log = log
	rl := &fakeReloader{log: log}
	return NewService(r, fs, rl)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestGetTenantNotFound(t *testing.T) {
	log := &[]string{}
	r := &fakeReader{detailOut: nil, detailErr: nil}
	svc := newSvc(log, r, &fakeFS{})

	_, err := svc.GetTenant(context.Background(), &adminv1.GetTenantRequest{TenantId: 99})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSuspendOrder(t *testing.T) {
	log := &[]string{}
	now := time.Now()
	r := &fakeReader{
		suspendOut: &store.Tenant{ID: 1, Name: "acme", SuspendedAt: &now},
	}
	svc := newSvc(log, r, &fakeFS{})

	resp, err := svc.SuspendTenant(context.Background(), &adminv1.TenantIdRequest{TenantId: 1})
	require.NoError(t, err)

	// Full order must be: fs first, reload second, store third.
	assert.Equal(t, []string{"fs.Suspend", "reload", "store.Suspend"}, *log)
	assert.NotNil(t, resp.SuspendedAt)
}

func TestSuspendNotFound(t *testing.T) {
	log := &[]string{}
	r := &fakeReader{
		suspendErr: &store.NotFoundError{Entity: "tenant"},
	}
	svc := newSvc(log, r, &fakeFS{})

	_, err := svc.SuspendTenant(context.Background(), &adminv1.TenantIdRequest{TenantId: 99})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestUnsuspendOrder(t *testing.T) {
	log := &[]string{}
	r := &fakeReader{
		// SuspendedAt nil: unsuspend clears it.
		unsuspendOut: &store.Tenant{ID: 1, Name: "acme", SuspendedAt: nil},
	}
	svc := newSvc(log, r, &fakeFS{})

	resp, err := svc.UnsuspendTenant(context.Background(), &adminv1.TenantIdRequest{TenantId: 1})
	require.NoError(t, err)

	assert.Equal(t, []string{"fs.Unsuspend", "reload", "store.Unsuspend"}, *log)
	assert.Nil(t, resp.SuspendedAt) // cleared
}

func TestDeleteWrongConfirm(t *testing.T) {
	log := &[]string{}
	r := &fakeReader{
		tenantByIDOut: &store.Tenant{ID: 1, Name: "acme"},
	}
	svc := newSvc(log, r, &fakeFS{})

	_, err := svc.DeleteTenant(context.Background(), &adminv1.DeleteTenantRequest{
		TenantId: 1,
		Confirm:  "wrong",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// No side-effects must have been triggered.
	assert.Empty(t, *log, "fs.Delete, reload, and store.Delete must NOT be called")
}

func TestDeleteMissing(t *testing.T) {
	log := &[]string{}
	r := &fakeReader{
		tenantByIDErr: &store.NotFoundError{Entity: "tenant"},
	}
	svc := newSvc(log, r, &fakeFS{})

	_, err := svc.DeleteTenant(context.Background(), &adminv1.DeleteTenantRequest{
		TenantId: 99,
		Confirm:  "anything",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Empty(t, *log, "no side effects on missing tenant")
}

func TestDeleteHappy(t *testing.T) {
	log := &[]string{}
	r := &fakeReader{
		tenantByIDOut: &store.Tenant{ID: 1, Name: "acme"},
	}
	svc := newSvc(log, r, &fakeFS{})

	resp, err := svc.DeleteTenant(context.Background(), &adminv1.DeleteTenantRequest{
		TenantId: 1,
		Confirm:  "acme",
	})
	require.NoError(t, err)
	assert.IsType(t, &emptypb.Empty{}, resp)
	assert.Equal(t, []string{"fs.Delete", "reload", "store.Delete"}, *log)
}

// Compile-time guard: fakeReader implements Reader.
var _ Reader = (*fakeReader)(nil)

// Compile-time guard: fakeFS implements FSOps.
var _ FSOps = (*fakeFS)(nil)

// Compile-time guard: fakeReloader implements Reloader.
var _ Reloader = (*fakeReloader)(nil)

// Suppress unused import if emptypb is only used in one test.
var _ = errors.New
