package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zwarder/waf/gobackend/internal/store"
)

type fakeStore struct {
	users   map[int64]*store.User
	tenants map[int64]*store.Tenant
}

func (f *fakeStore) GetUserByID(_ context.Context, id int64) (*store.User, error) {
	u, ok := f.users[id]
	if !ok {
		return nil, &store.NotFoundError{Entity: "user"}
	}
	return u, nil
}
func (f *fakeStore) GetTenantByID(_ context.Context, id int64) (*store.Tenant, error) {
	t, ok := f.tenants[id]
	if !ok {
		return nil, &store.NotFoundError{Entity: "tenant"}
	}
	return t, nil
}

func ts(t time.Time) *time.Time { return &t }

func adminUser() *store.User {
	now := time.Now()
	return &store.User{ID: 7, PlatformRole: "admin", EmailVerifiedAt: ts(now), TotpEnabledAt: ts(now)}
}

func newPolicy(u *store.User, ten *store.Tenant) *Policy {
	fs := &fakeStore{users: map[int64]*store.User{}, tenants: map[int64]*store.Tenant{}}
	if u != nil {
		fs.users[u.ID] = u
	}
	if ten != nil {
		fs.tenants[ten.ID] = ten
	}
	return NewPolicy(fs)
}

func claims(sub, role string, tenantID *int64) *Claims {
	return &Claims{Sub: sub, PlatformRole: role, TenantID: tenantID, Exp: float64(time.Now().Add(time.Hour).Unix())}
}

func TestRequireAdminHappyPath(t *testing.T) {
	p := newPolicy(adminUser(), nil)
	id, err := p.RequireAdmin(context.Background(), claims("7", "admin", nil))
	require.NoError(t, err)
	require.Equal(t, int64(7), id.UserID)
}

func TestRequireAdminUserMissing(t *testing.T) {
	p := newPolicy(nil, nil)
	_, err := p.RequireAdmin(context.Background(), claims("7", "admin", nil))
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestRequireAdminEmailUnverified(t *testing.T) {
	u := adminUser()
	u.EmailVerifiedAt = nil
	p := newPolicy(u, nil)
	_, err := p.RequireAdmin(context.Background(), claims("7", "admin", nil))
	require.ErrorIs(t, err, ErrEmailNotVerified)
}

func TestRequireAdminTenantSuspended(t *testing.T) {
	tid := int64(3)
	u := adminUser()
	u.TenantID = &tid
	p := newPolicy(u, &store.Tenant{ID: 3, SuspendedAt: ts(time.Now())})
	_, err := p.RequireAdmin(context.Background(), claims("7", "admin", &tid))
	require.ErrorIs(t, err, ErrTenantSuspended)
}

func TestRequireAdminNotAdmin(t *testing.T) {
	u := adminUser()
	u.PlatformRole = "client"
	p := newPolicy(u, nil)
	_, err := p.RequireAdmin(context.Background(), claims("7", "client", nil))
	require.ErrorIs(t, err, ErrForbidden)
}

func TestRequireAdminNoTotp(t *testing.T) {
	u := adminUser()
	u.TotpEnabledAt = nil
	p := newPolicy(u, nil)
	_, err := p.RequireAdmin(context.Background(), claims("7", "admin", nil))
	require.ErrorIs(t, err, ErrForbidden)
}

func TestBadSubFails(t *testing.T) {
	p := newPolicy(adminUser(), nil)
	_, err := p.RequireAdmin(context.Background(), claims("notanint", "admin", nil))
	require.ErrorIs(t, err, ErrUnauthenticated)
}
