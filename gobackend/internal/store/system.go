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

// EnsureSystemTenant returns the system tenant, creating it on first call.
// Idempotent: concurrent/repeat calls converge on the one row (INSERT ON
// CONFLICT DO NOTHING + SELECT). Bypasses ValidateTenantName on purpose — the
// slug is reserved there so clients cannot take it.
func (s *Store) EnsureSystemTenant(ctx context.Context) (*Tenant, error) {
	const q = `
		INSERT INTO tenants (name, display_name)
		VALUES ($1, 'Moncoll')
		ON CONFLICT (name) DO NOTHING`
	if _, err := s.pool.Exec(ctx, q, systemTenantSlug); err != nil {
		return nil, fmt.Errorf("EnsureSystemTenant insert: %w", err)
	}
	t := &Tenant{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, suspended_at FROM tenants WHERE name=$1`, systemTenantSlug).
		Scan(&t.ID, &t.Name, &t.SuspendedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "tenant"}
	}
	if err != nil {
		return nil, fmt.Errorf("EnsureSystemTenant select: %w", err)
	}
	return t, nil
}

// ErrSystemTenantProtected is returned when an admin tries to suspend or delete
// the system tenant. Doing so would set suspended_at on the tenant every admin
// now belongs to, and resolveVerified would then reject ALL admins
// (ErrTenantSuspended) — locking them out of the very page needed to undo it.
var ErrSystemTenantProtected = errors.New("the system tenant is protected")

// isSystemTenant reports whether id is the reserved system tenant.
func (s *Store) isSystemTenant(ctx context.Context, id int64) (bool, error) {
	var name string
	err := s.pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id=$1`, id).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, &NotFoundError{Entity: "tenant"}
	}
	if err != nil {
		return false, err
	}
	return name == systemTenantSlug, nil
}

// BackfillAdminsIntoSystemTenant makes every platform admin an owner member of
// the system tenant and points admins with no active tenant at it. Idempotent:
// membership inserts use ON CONFLICT DO NOTHING, and tenant_id is set ONLY when
// currently NULL so an admin who deliberately switched their active team is not
// clobbered. The admin's platform_role is untouched.
func (s *Store) BackfillAdminsIntoSystemTenant(ctx context.Context, systemTenantID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("BackfillAdmins begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO memberships (tenant_id, user_id, role)
		 SELECT $1, u.id, 'owner' FROM users u WHERE u.platform_role = 'admin'
		 ON CONFLICT (tenant_id, user_id) DO NOTHING`, systemTenantID); err != nil {
		return fmt.Errorf("BackfillAdmins memberships: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE users SET tenant_id = $1
		 WHERE platform_role = 'admin' AND tenant_id IS NULL`, systemTenantID); err != nil {
		return fmt.Errorf("BackfillAdmins tenant_id: %w", err)
	}
	return tx.Commit(ctx)
}
