package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// GetConnectionForTenant returns the connection with the given connID only if
// it belongs to tenantID. If the row does not exist or belongs to a different
// tenant, *NotFoundError is returned.
//
// Mirrors connection_service.get_connection(session, tenant, connection_id)
// in the Python backend which raises 404 when the tenant does not match.
func (s *Store) GetConnectionForTenant(ctx context.Context, connID, tenantID int64) (*Connection, error) {
	const q = `SELECT id, tenant_id, name, domain, enabled, status
	           FROM connections
	           WHERE id = $1 AND tenant_id = $2`
	var c Connection
	err := s.pool.QueryRow(ctx, q, connID, tenantID).Scan(
		&c.ID, &c.TenantID, &c.Name, &c.Domain, &c.Enabled, &c.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "connection"}
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
