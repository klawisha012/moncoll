package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// multiQueryTracer fans a pgx query trace out to several tracers. pgx allows a
// single ConnConfig.Tracer, but we want BOTH the RED-metrics tracer and the
// OpenTelemetry tracer on every query — so we multiplex them.
type multiQueryTracer []pgx.QueryTracer

func (m multiQueryTracer) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	for _, t := range m {
		ctx = t.TraceQueryStart(ctx, c, d)
	}
	return ctx
}

func (m multiQueryTracer) TraceQueryEnd(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryEndData) {
	for _, t := range m {
		t.TraceQueryEnd(ctx, c, d)
	}
}

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
	// Production wiring (obs passed) gets BOTH RED metrics and OTel query
	// spans. Tests pass no obs and stay uninstrumented. otelpgx uses the global
	// tracer provider, so when no OTLP endpoint is configured its spans are
	// non-recording — near-zero cost, same off-by-default story as InitTracer.
	if len(obs) > 0 && obs[0] != nil {
		cfg.ConnConfig.Tracer = multiQueryTracer{queryTracer{obs: obs[0]}, otelpgx.NewTracer()}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// manifestPublishLockKey is a fixed Postgres advisory-lock key serialising
// manifest publishers cluster-wide. NB: the manifest is a SINGLE shared object,
// so a per-tenant lock would not prevent two tenants' publishers from colliding
// on it — only one global lock actually reduces CAS contention (T025/FR-013).
// Arbitrary stable value; pick a distinctive one to avoid clashing with any
// other advisory lock the app might add.
const manifestPublishLockKey int64 = 0x7761665F7075626C // "waf_publ"

// WithLock runs fn while holding a session-level advisory lock on a fixed key,
// serialising the manifest read-modify-publish across backend replicas so they
// rarely race on the CAS. Structurally satisfies storage.Locker. The lock only
// reduces contention — storage CAS remains the correctness floor (R6).
func (s *Store) WithLock(ctx context.Context, fn func() error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", manifestPublishLockKey); err != nil {
		return err
	}
	defer func() {
		// Unlock on a fresh context so a cancelled ctx still releases the lock
		// (the session ends on Release anyway, but be explicit).
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", manifestPublishLockKey)
	}()
	return fn()
}

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

// SetTenantDisplayName updates a tenant's human-readable name. The slug
// (tenants.name) is identity and is deliberately never touched here.
func (s *Store) SetTenantDisplayName(ctx context.Context, tenantID int64, displayName string) error {
	const q = `UPDATE tenants SET display_name = $2, updated_at = now() WHERE id = $1`
	ct, err := s.pool.Exec(ctx, q, tenantID, displayName)
	if err != nil {
		return fmt.Errorf("SetTenantDisplayName: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return &NotFoundError{Entity: "tenant"}
	}
	return nil
}
