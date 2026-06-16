package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// systemTenantSlug is the reserved slug of the single platform "system" tenant
// that owns the self-connection and that every platform admin belongs to.
const systemTenantSlug = "system"

// systemTenantDisplayName is the human-facing name shown for the platform's
// own (system) tenant.
const systemTenantDisplayName = "Moncoll"

// ErrSystemTenantProtected is returned when an admin tries to suspend or delete
// the system tenant. Suspending it would set suspended_at on the tenant every
// admin is a member of; combined with the interceptor scope override that could
// degrade the admin client tabs. The system tenant is therefore immutable to
// the suspend/delete admin actions.
var ErrSystemTenantProtected = errors.New("the system tenant is protected")

// EnsureSystemTenant returns the system tenant, creating it on first call.
// Idempotent: concurrent/repeat calls converge on the one row (INSERT ON
// CONFLICT DO NOTHING + SELECT). Bypasses ValidateTenantName on purpose — the
// slug is reserved there so clients cannot take it.
func (s *Store) EnsureSystemTenant(ctx context.Context) (*Tenant, error) {
	const q = `
		INSERT INTO tenants (name, display_name)
		VALUES ($1, $2)
		ON CONFLICT (name) DO NOTHING`
	if _, err := s.pool.Exec(ctx, q, systemTenantSlug, systemTenantDisplayName); err != nil {
		return nil, fmt.Errorf("EnsureSystemTenant insert: %w", err)
	}
	return s.GetTenantByName(ctx, systemTenantSlug)
}

// isSystemTenant reports whether id is the reserved system tenant. Used by the
// suspend/delete guards (admin.go) in a later task.
func (s *Store) isSystemTenant(ctx context.Context, id int64) (bool, error) {
	var name string
	err := s.pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id=$1`, id).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, &NotFoundError{Entity: "tenant"}
	}
	if err != nil {
		return false, fmt.Errorf("isSystemTenant: %w", err)
	}
	return name == systemTenantSlug, nil
}

// BackfillAdminsIntoSystemTenant makes every platform admin an OWNER member of
// the system tenant. It deliberately does NOT touch users.tenant_id: the
// users_platform_tenant_consistency CHECK requires admins to have tenant_id
// IS NULL, and an admin's effective client scope is applied at request time in
// the auth interceptor (see auth.NewInterceptor), not in the DB. Idempotent via
// ON CONFLICT DO NOTHING; the admin's platform_role is untouched.
func (s *Store) BackfillAdminsIntoSystemTenant(ctx context.Context, systemTenantID int64) error {
	const q = `
		INSERT INTO memberships (tenant_id, user_id, role)
		SELECT $1, u.id, 'owner' FROM users u WHERE u.platform_role = 'admin'
		ON CONFLICT (tenant_id, user_id) DO NOTHING`
	if _, err := s.pool.Exec(ctx, q, systemTenantID); err != nil {
		return fmt.Errorf("BackfillAdminsIntoSystemTenant: %w", err)
	}
	return nil
}
