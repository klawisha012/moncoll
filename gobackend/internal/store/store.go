package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func errorsIsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	const q = `SELECT id, platform_role, email_verified_at, totp_enabled_at, tenant_id
	           FROM users WHERE id = $1`
	var u User
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&u.ID, &u.PlatformRole, &u.EmailVerifiedAt, &u.TotpEnabledAt, &u.TenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "user"}
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetTenantByID(ctx context.Context, id int64) (*Tenant, error) {
	const q = `SELECT id, name, suspended_at FROM tenants WHERE id = $1`
	var t Tenant
	err := s.pool.QueryRow(ctx, q, id).Scan(&t.ID, &t.Name, &t.SuspendedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "tenant"}
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}
