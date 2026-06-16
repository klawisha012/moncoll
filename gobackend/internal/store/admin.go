package store

import (
	"context"
	"time"
)

type TenantSummary struct {
	ID              int64
	Name            string
	DisplayName     string
	OwnerEmail      *string
	UserCount       int64
	ConnectionCount int64
	CreatedAt       time.Time
	SuspendedAt     *time.Time
	LastActivity    *time.Time
}

type TenantUser struct {
	ID            int64
	Email         string
	TenantRole    *string
	LastLoginAt   *time.Time
	EmailVerified bool
	TotpEnabled   bool
}

type TenantConnection struct {
	ID     int64
	Name   string
	Domain string
	Status string
}

type TenantCore struct {
	ID          int64
	Name        string
	DisplayName string
	CreatedAt   time.Time
	SuspendedAt *time.Time
}

type TenantDetail struct {
	Tenant      TenantCore
	Users       []TenantUser
	Connections []TenantConnection
}

func (s *Store) ListTenantSummaries(ctx context.Context) ([]TenantSummary, error) {
	const q = `
SELECT t.id, t.name, t.display_name, t.created_at, t.suspended_at,
       (SELECT count(*) FROM users u WHERE u.tenant_id = t.id) AS user_count,
       (SELECT count(*) FROM connections c WHERE c.tenant_id = t.id) AS connection_count,
       (SELECT max(u.last_login_at) FROM users u WHERE u.tenant_id = t.id) AS last_activity,
       (SELECT u.email FROM users u WHERE u.tenant_id = t.id AND u.tenant_role = 'owner' LIMIT 1) AS owner_email
FROM tenants t
ORDER BY t.id`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantSummary
	for rows.Next() {
		var ts TenantSummary
		if err := rows.Scan(&ts.ID, &ts.Name, &ts.DisplayName, &ts.CreatedAt, &ts.SuspendedAt,
			&ts.UserCount, &ts.ConnectionCount, &ts.LastActivity, &ts.OwnerEmail); err != nil {
			return nil, err
		}
		out = append(out, ts)
	}
	return out, rows.Err()
}

func (s *Store) SuspendTenant(ctx context.Context, id int64) (*Tenant, error) {
	if sys, err := s.isSystemTenant(ctx, id); err != nil {
		return nil, err
	} else if sys {
		return nil, ErrSystemTenantProtected
	}
	const q = `UPDATE tenants SET suspended_at = now() WHERE id=$1 RETURNING id, name, suspended_at`
	var t Tenant
	err := s.pool.QueryRow(ctx, q, id).Scan(&t.ID, &t.Name, &t.SuspendedAt)
	if errorsIsNoRows(err) {
		return nil, &NotFoundError{Entity: "tenant"}
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) UnsuspendTenant(ctx context.Context, id int64) (*Tenant, error) {
	const q = `UPDATE tenants SET suspended_at = NULL WHERE id=$1 RETURNING id, name, suspended_at`
	var t Tenant
	err := s.pool.QueryRow(ctx, q, id).Scan(&t.ID, &t.Name, &t.SuspendedAt)
	if errorsIsNoRows(err) {
		return nil, &NotFoundError{Entity: "tenant"}
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) DeleteTenant(ctx context.Context, id int64) error {
	if sys, err := s.isSystemTenant(ctx, id); err != nil {
		return err
	} else if sys {
		return ErrSystemTenantProtected
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return &NotFoundError{Entity: "tenant"}
	}
	return nil
}

func (s *Store) GetTenantDetail(ctx context.Context, id int64) (*TenantDetail, error) {
	var d TenantDetail
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, display_name, created_at, suspended_at FROM tenants WHERE id=$1`, id).
		Scan(&d.Tenant.ID, &d.Tenant.Name, &d.Tenant.DisplayName, &d.Tenant.CreatedAt, &d.Tenant.SuspendedAt)
	if errorsIsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	urows, err := s.pool.Query(ctx,
		`SELECT id, email, tenant_role, last_login_at,
		        (email_verified_at IS NOT NULL), (totp_enabled_at IS NOT NULL)
		 FROM users WHERE tenant_id=$1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer urows.Close()
	for urows.Next() {
		var u TenantUser
		if err := urows.Scan(&u.ID, &u.Email, &u.TenantRole, &u.LastLoginAt, &u.EmailVerified, &u.TotpEnabled); err != nil {
			return nil, err
		}
		d.Users = append(d.Users, u)
	}
	if err := urows.Err(); err != nil {
		return nil, err
	}

	crows, err := s.pool.Query(ctx,
		`SELECT id, name, domain, status FROM connections WHERE tenant_id=$1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var c TenantConnection
		if err := crows.Scan(&c.ID, &c.Name, &c.Domain, &c.Status); err != nil {
			return nil, err
		}
		d.Connections = append(d.Connections, c)
	}
	return &d, crows.Err()
}
