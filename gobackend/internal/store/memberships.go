package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// CreateMembership inserts a (tenant, user, role) membership. It is idempotent:
// an existing (tenant_id, user_id) row is left unchanged and no error is
// returned, so it is safe to call from signup paths that may race a backfill.
func (s *Store) CreateMembership(ctx context.Context, tenantID, userID int64, role string) error {
	const q = `
		INSERT INTO memberships (tenant_id, user_id, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, user_id) DO NOTHING`
	if _, err := s.pool.Exec(ctx, q, tenantID, userID, role); err != nil {
		return fmt.Errorf("CreateMembership: %w", err)
	}
	return nil
}

// GetMembership returns the membership of user in tenant, or a NotFoundError
// when the user is not a member. Used for team-permission checks.
func (s *Store) GetMembership(ctx context.Context, userID, tenantID int64) (*Membership, error) {
	const q = `
		SELECT id, tenant_id, user_id, role, created_at
		FROM memberships
		WHERE user_id = $1 AND tenant_id = $2`
	m := &Membership{}
	err := s.pool.QueryRow(ctx, q, userID, tenantID).Scan(
		&m.ID, &m.TenantID, &m.UserID, &m.Role, &m.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "membership"}
	}
	if err != nil {
		return nil, fmt.Errorf("GetMembership: %w", err)
	}
	return m, nil
}

// ListMyTeams returns every team the user belongs to (joined with their role),
// ordered by tenant display name for stable UI rendering.
func (s *Store) ListMyTeams(ctx context.Context, userID int64) ([]MyTeam, error) {
	const q = `
		SELECT t.id, t.name, t.display_name, m.role
		FROM memberships m
		JOIN tenants t ON t.id = m.tenant_id
		WHERE m.user_id = $1
		ORDER BY t.display_name`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("ListMyTeams: %w", err)
	}
	defer rows.Close()

	out := []MyTeam{}
	for rows.Next() {
		var mt MyTeam
		if err := rows.Scan(&mt.TenantID, &mt.Slug, &mt.DisplayName, &mt.Role); err != nil {
			return nil, fmt.Errorf("ListMyTeams scan: %w", err)
		}
		out = append(out, mt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListMyTeams rows: %w", err)
	}
	return out, nil
}

// SetActiveTenant points users.tenant_id at tenantID. The caller MUST have
// already verified membership (e.g. via GetMembership); this method only
// persists the pointer and bumps updated_at.
func (s *Store) SetActiveTenant(ctx context.Context, userID, tenantID int64) error {
	const q = `UPDATE users SET tenant_id = $2, updated_at = now() WHERE id = $1`
	ct, err := s.pool.Exec(ctx, q, userID, tenantID)
	if err != nil {
		return fmt.Errorf("SetActiveTenant: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return &NotFoundError{Entity: "user"}
	}
	return nil
}
