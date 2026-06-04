// Package migrate runs embedded SQL migrations against the WAF Postgres DB
// using golang-migrate. The single baseline migration (0001_init) contains the
// full schema as idempotent DDL so it is safe to run against both a fresh DB
// and an already-alembic-migrated production DB (IF NOT EXISTS makes it a
// no-op on existing tables).
package migrate

import (
	"embed"
	"errors"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // pgx/v5 postgres driver
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Run applies all pending migrations to the database at dsn.
// It treats migrate.ErrNoChange as success (migrations already up to date).
// The dsn must be a postgres:// or postgresql:// URL understood by pgx.
func Run(dsn string, log *slog.Logger) error {
	log.Info("running DB migrations")

	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return err
	}

	// The golang-migrate pgx/v5 driver is registered under the "pgx5" scheme.
	// We normalise any "postgres://" or "postgresql://" prefix so the driver
	// receives a bare "pgx5://user:pass@host/db?..." URL.
	m, err := migrate.NewWithSourceInstance("iofs", src, "pgx5://"+normaliseURL(dsn))
	if err != nil {
		return err
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			log.Info("DB migrations up to date")
			return nil
		}
		return err
	}

	log.Info("DB migrations applied successfully")
	return nil
}

// normaliseURL strips common postgres URL scheme prefixes so the caller can
// pass either a bare "host=..." DSN or a "postgres://..." URL without needing
// to know which scheme the migrate driver expects.
func normaliseURL(dsn string) string {
	for _, prefix := range []string{"postgres://", "postgresql://"} {
		if len(dsn) > len(prefix) && dsn[:len(prefix)] == prefix {
			return dsn[len(prefix):]
		}
	}
	return dsn
}
