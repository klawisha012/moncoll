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

// New opens a pgx pool against dsn. An optional Observer instruments every
// pooled query (Query/QueryRow/Exec) with duration + error metrics via a
// pgx.QueryTracer; pass nil/omit it to run uninstrumented (e.g. in tests).
func New(ctx context.Context, dsn string, obs ...Observer) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if len(obs) > 0 && obs[0] != nil {
		cfg.ConnConfig.Tracer = queryTracer{obs: obs[0]}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Ping verifies that the database connection is alive.  Used by test helpers
// and health-check callers that are outside the store package.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func errorsIsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func (s *Store) GetUserByID(ctx context.Context, id int64) (*AuthGateUser, error) {
	const q = `SELECT id, platform_role, email_verified_at, totp_enabled_at, tenant_id, token_version
	           FROM users WHERE id = $1`
	var u AuthGateUser
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&u.ID, &u.PlatformRole, &u.EmailVerifiedAt, &u.TotpEnabledAt, &u.TenantID, &u.TokenVersion)
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
