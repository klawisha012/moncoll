package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// RunInTenantTx runs fn inside a transaction with the GUC app.tenant_id set
// (SET LOCAL semantics) so the connections Row-Level Security policy scopes
// every statement to tenantID — a defense-in-depth backstop beneath the
// explicit WHERE tenant_id filters.
//
// This is the activation mechanism for the 0007 RLS policy: client request
// paths should run their tenant-scoped connection access through here. It only
// takes effect when the app connects as a non-superuser, non-BYPASSRLS role
// (a Postgres superuser always bypasses RLS); see 0007_connections_rls.up.sql.
func (s *Store) RunInTenantTx(ctx context.Context, tenantID int64, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	// set_config(name, value, is_local=true) == SET LOCAL: scoped to this tx.
	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.tenant_id', $1, true)`,
		strconv.FormatInt(tenantID, 10),
	); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// pgUniqueViolation is the Postgres SQLSTATE for unique_violation.
const pgUniqueViolation = "23505"

// connFullColumns is the canonical ordered column list for a full Connection
// row.  All query SELECTs and INSERTs ... RETURNING use this order so that
// scanConnectionFull can be shared across all callers.
const connFullColumns = `id, tenant_id, name, domain, enabled, status,
	origin_hosts, origin_port, origin_tls_mode,
	verify_token, verified_at,
	status_detail, acme_retry_count, acme_next_retry_at,
	next_poll_at, dns_ttl_seconds, last_checked_at,
	http_versions, compression_algo,
	modsec_state, geoip_denied_countries, crowdsec_active, ddos_protection,
	ssl_cert_path, ssl_key_path,
	created_at, updated_at`

// scanConnectionFull scans a row (pgx.Row or pgx.Rows) into *Connection.
// originHostsJSON and geoipJSON are intermediary []byte values for the JSON
// columns; the caller passes pointers allocated on the stack.
func scanConnectionFull(scan func(...any) error, c *Connection) error {
	var originHostsJSON, geoipJSON []byte
	err := scan(
		&c.ID, &c.TenantID, &c.Name, &c.Domain, &c.Enabled, &c.Status,
		&originHostsJSON, &c.OriginPort, &c.OriginTLSMode,
		&c.VerifyToken, &c.VerifiedAt,
		&c.StatusDetail, &c.AcmeRetryCount, &c.AcmeNextRetryAt,
		&c.NextPollAt, &c.DNSTTLSeconds, &c.LastCheckedAt,
		&c.HTTPVersions, &c.CompressionAlgo,
		&c.ModsecState, &geoipJSON, &c.CrowdsecActive, &c.DdosProtection,
		&c.SSLCertPath, &c.SSLKeyPath,
		&c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(originHostsJSON, &c.OriginHosts); err != nil {
		return fmt.Errorf("unmarshal origin_hosts: %w", err)
	}
	if len(geoipJSON) == 0 || string(geoipJSON) == "null" {
		c.GeoipDeniedCountries = []string{}
	} else {
		if err := json.Unmarshal(geoipJSON, &c.GeoipDeniedCountries); err != nil {
			return fmt.Errorf("unmarshal geoip_denied_countries: %w", err)
		}
	}
	if c.OriginHosts == nil {
		c.OriginHosts = []string{}
	}
	return nil
}

// isUniqueViolation returns true when err is a Postgres unique_violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}

// ─────────────────────────────────────────────────────────────────────────────
// Lean list — used by the crowdsec sync and dashboard (unchanged contract).
// ─────────────────────────────────────────────────────────────────────────────

// ListConnections returns all rows from the connections table with the six
// columns the crowdsec sync requires: id, tenant_id, name, domain, enabled,
// status.  The remaining Connection fields are left at zero values.
//
// This is intentionally kept lean; callers that need the full row use
// GetConnectionFull or GetConnectionInternal.
func (s *Store) ListConnections(ctx context.Context) ([]Connection, error) {
	const q = `SELECT id, tenant_id, name, domain, enabled, status
	           FROM connections
	           ORDER BY id`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.Domain, &c.Enabled, &c.Status); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// Full row reads (tenant-scoped and internal).
// ─────────────────────────────────────────────────────────────────────────────

// ListConnectionsFull returns full rows for all connections belonging to
// tenantID, ordered by id.
//
// Mirrors service.list_connections(session, tenant) in Python.
func (s *Store) ListConnectionsFull(ctx context.Context, tenantID int64) ([]Connection, error) {
	q := `SELECT ` + connFullColumns + `
	      FROM connections
	      WHERE tenant_id = $1
	      ORDER BY id`
	rows, err := s.pool.Query(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		var c Connection
		if err := scanConnectionFull(rows.Scan, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetConnectionFull returns the full row for a connection that belongs to
// tenantID.  Returns *NotFoundError when the row does not exist OR when it
// belongs to a different tenant (no existence leak).
//
// Mirrors service.get_connection(session, tenant, conn_id).
func (s *Store) GetConnectionFull(ctx context.Context, tenantID, connID int64) (*Connection, error) {
	q := `SELECT ` + connFullColumns + `
	      FROM connections
	      WHERE id = $1 AND tenant_id = $2`
	var c Connection
	err := scanConnectionFull(s.pool.QueryRow(ctx, q, connID, tenantID).Scan, &c)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "connection"}
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// GetConnectionForTenant is the lean variant used by the certs service.  It
// returns only the six lean columns (ID, TenantID, Name, Domain, Enabled,
// Status).  Tenant scoping is enforced.
//
// Mirrors service.get_connection / cert_connections.GetConnectionForTenant.
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

// GetConnectionInternal fetches the full row without tenant scoping.  For
// platform-internal use only (background poller, cert issuer).
//
// Mirrors service.get_connection_internal(session, conn_id).
func (s *Store) GetConnectionInternal(ctx context.Context, connID int64) (*Connection, error) {
	q := `SELECT ` + connFullColumns + `
	      FROM connections
	      WHERE id = $1`
	var c Connection
	err := scanConnectionFull(s.pool.QueryRow(ctx, q, connID).Scan, &c)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "connection"}
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Write methods (create / update / delete).
// ─────────────────────────────────────────────────────────────────────────────

// CreateConnection inserts a new connection row and returns the created row
// (populated by RETURNING *).
//
// The caller is responsible for setting the fields it wants; this method does
// not apply defaults — the caller should set Status, VerifyToken, etc. before
// calling (mirroring what service.create_connection does in Python).
//
// Returns *ConflictError on unique-domain violation so the caller can map it
// to HTTP 409.
func (s *Store) CreateConnection(ctx context.Context, c *Connection) (*Connection, error) {
	originHostsJSON, err := json.Marshal(c.OriginHosts)
	if err != nil {
		return nil, fmt.Errorf("marshal origin_hosts: %w", err)
	}
	geoipJSON, err := json.Marshal(c.GeoipDeniedCountries)
	if err != nil {
		return nil, fmt.Errorf("marshal geoip_denied_countries: %w", err)
	}

	q := `INSERT INTO connections (
		tenant_id, name, domain,
		origin_hosts, origin_port, origin_tls_mode,
		verify_token, verified_at,
		status, status_detail,
		acme_retry_count, acme_next_retry_at,
		next_poll_at, dns_ttl_seconds, last_checked_at,
		http_versions, compression_algo,
		enabled,
		modsec_state, geoip_denied_countries, crowdsec_active,
		ssl_cert_path, ssl_key_path,
		created_at, updated_at
	) VALUES (
		$1, $2, $3,
		$4, $5, $6,
		$7, $8,
		$9, $10,
		$11, $12,
		$13, $14, $15,
		$16, $17,
		$18,
		$19, $20, $21,
		$22, $23,
		$24, $25
	) RETURNING ` + connFullColumns

	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}

	var out Connection
	err = scanConnectionFull(
		s.pool.QueryRow(ctx, q,
			c.TenantID, c.Name, c.Domain,
			originHostsJSON, c.OriginPort, c.OriginTLSMode,
			c.VerifyToken, c.VerifiedAt,
			c.Status, c.StatusDetail,
			c.AcmeRetryCount, c.AcmeNextRetryAt,
			c.NextPollAt, c.DNSTTLSeconds, c.LastCheckedAt,
			c.HTTPVersions, c.CompressionAlgo,
			c.Enabled,
			c.ModsecState, geoipJSON, c.CrowdsecActive,
			c.SSLCertPath, c.SSLKeyPath,
			c.CreatedAt, c.UpdatedAt,
		).Scan,
		&out,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, &ConflictError{Detail: fmt.Sprintf("domain %q is already onboarded", c.Domain)}
		}
		return nil, err
	}
	return &out, nil
}

// UpdateConnection applies a partial update to the mutable fields that
// service.update_connection may change.  Only non-nil fields in upd are
// written.  The row must belong to tenantID; otherwise *NotFoundError is
// returned.
//
// updated_at is bumped to now() on every call.
func (s *Store) UpdateConnection(ctx context.Context, tenantID, connID int64, upd ConnectionUpdate) (*Connection, error) {
	// Verify ownership first.
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM connections WHERE id=$1 AND tenant_id=$2)`,
		connID, tenantID,
	).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, &NotFoundError{Entity: "connection"}
	}

	// Build dynamic SET list.
	setClauses := []string{"updated_at = now()"}
	args := []any{}
	argIdx := 1

	addArg := func(clause string, val any) {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", clause, argIdx))
		args = append(args, val)
		argIdx++
	}

	if upd.Name != nil {
		addArg("name", *upd.Name)
	}
	if upd.OriginHosts != nil {
		b, jerr := json.Marshal(upd.OriginHosts)
		if jerr != nil {
			return nil, fmt.Errorf("marshal origin_hosts: %w", jerr)
		}
		addArg("origin_hosts", b)
	}
	if upd.OriginPort != nil {
		addArg("origin_port", *upd.OriginPort)
	}
	if upd.OriginTLSMode != nil {
		addArg("origin_tls_mode", *upd.OriginTLSMode)
	}
	if upd.HTTPVersions != nil {
		addArg("http_versions", *upd.HTTPVersions)
	}
	if upd.CompressionAlgo != nil {
		addArg("compression_algo", *upd.CompressionAlgo)
	}
	if upd.Enabled != nil {
		addArg("enabled", *upd.Enabled)
	}

	// Build SET clause string.
	setStr := ""
	for i, s := range setClauses {
		if i > 0 {
			setStr += ", "
		}
		setStr += s
	}

	// WHERE clause args come after SET args.
	args = append(args, connID, tenantID)
	whereArgIdx := argIdx
	q := fmt.Sprintf(`UPDATE connections SET %s WHERE id = $%d AND tenant_id = $%d RETURNING `+connFullColumns,
		setStr, whereArgIdx, whereArgIdx+1)

	var out Connection
	err = scanConnectionFull(s.pool.QueryRow(ctx, q, args...).Scan, &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "connection"}
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteConnection removes the connection row that belongs to tenantID.
// Returns *NotFoundError if the row does not exist or is owned by another
// tenant.
//
// Mirrors service.delete_connection(session, tenant, conn_id).
func (s *Store) DeleteConnection(ctx context.Context, tenantID, connID int64) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM connections WHERE id = $1 AND tenant_id = $2`,
		connID, tenantID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return &NotFoundError{Entity: "connection"}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Security update.
// ─────────────────────────────────────────────────────────────────────────────

// UpdateSecurity applies a security-settings update (modsec_state,
// geoip_denied_countries, crowdsec_active, ddos_protection) to a tenant-scoped
// connection.
//
// Mirrors service.update_security(session, tenant, conn_id, ...).
func (s *Store) UpdateSecurity(ctx context.Context, tenantID, connID int64,
	modsecState string, geoipDeniedCountries []string, crowdsecActive bool, ddosProtection bool,
) (*Connection, error) {
	geoipJSON, err := json.Marshal(geoipDeniedCountries)
	if err != nil {
		return nil, fmt.Errorf("marshal geoip_denied_countries: %w", err)
	}
	q := `UPDATE connections
	      SET modsec_state = $1, geoip_denied_countries = $2, crowdsec_active = $3, ddos_protection = $4, updated_at = now()
	      WHERE id = $5 AND tenant_id = $6
	      RETURNING ` + connFullColumns
	var out Connection
	err = scanConnectionFull(
		s.pool.QueryRow(ctx, q, modsecState, geoipJSON, crowdsecActive, ddosProtection, connID, tenantID).Scan,
		&out,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "connection"}
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Poller queries.
// ─────────────────────────────────────────────────────────────────────────────

// ListConnectionsForPoll returns all enabled connections whose status is in
// the set that the poller drives (pending_verification, pending_dns,
// provisioning_cert, error) AND whose next_poll_at is NULL or <= now.
//
// Mirrors _select_due_rows() in backend/src/connections/poller.py.
func (s *Store) ListConnectionsForPoll(ctx context.Context) ([]Connection, error) {
	q := `SELECT ` + connFullColumns + `
	      FROM connections
	      WHERE enabled = true
	        AND status IN ('pending_verification','pending_dns','provisioning_cert','error')
	        AND (next_poll_at IS NULL OR next_poll_at <= now())
	      ORDER BY id`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		var c Connection
		if err := scanConnectionFull(rows.Scan, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdatePollerState writes back the mutable fields the poller modifies after a
// tick: status, status_detail, verified_at, acme_retry_count,
// acme_next_retry_at, next_poll_at, dns_ttl_seconds, last_checked_at,
// ssl_cert_path, ssl_key_path.  No tenant scope — poller runs platform-wide.
//
// Mirrors the attribute mutations in _tick_verification / _tick_pending_dns /
// _tick_provisioning + _bump_poll in backend/src/connections/poller.py.
func (s *Store) UpdatePollerState(ctx context.Context, connID int64, p PollerState) (*Connection, error) {
	geoipJSON := []byte("[]") // not modified by poller; placeholder for RETURNING scan
	_ = geoipJSON             // used only in scanConnectionFull output
	q := `UPDATE connections
	      SET status            = $1,
	          status_detail     = $2,
	          verified_at       = $3,
	          acme_retry_count  = $4,
	          acme_next_retry_at= $5,
	          next_poll_at      = $6,
	          dns_ttl_seconds   = $7,
	          last_checked_at   = $8,
	          ssl_cert_path     = $9,
	          ssl_key_path      = $10,
	          updated_at        = now()
	      WHERE id = $11
	      RETURNING ` + connFullColumns
	var out Connection
	err := scanConnectionFull(
		s.pool.QueryRow(ctx, q,
			p.Status, p.StatusDetail, p.VerifiedAt,
			p.AcmeRetryCount, p.AcmeNextRetryAt,
			p.NextPollAt, p.DNSTTLSeconds, p.LastCheckedAt,
			p.SSLCertPath, p.SSLKeyPath,
			connID,
		).Scan,
		&out,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "connection"}
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// PollerState is the set of fields the background poller may write after each
// tick.  Mirrors the attributes mutated by _tick_* + _bump_poll in poller.py.
type PollerState struct {
	Status          string
	StatusDetail    *string
	VerifiedAt      *time.Time
	AcmeRetryCount  int
	AcmeNextRetryAt *time.Time
	NextPollAt      *time.Time
	DNSTTLSeconds   int
	LastCheckedAt   *time.Time
	SSLCertPath     *string
	SSLKeyPath      *string
}

// UpdateProbeState writes back the fields mutated by the probe_connection
// wizard endpoint: status, status_detail, verified_at, next_poll_at,
// acme_next_retry_at, last_checked_at, dns_ttl_seconds.
// Tenant-scoped so the probe endpoint cannot accidentally poke a foreign row.
func (s *Store) UpdateProbeState(ctx context.Context, tenantID, connID int64, p PollerState) (*Connection, error) {
	q := `UPDATE connections
	      SET status            = $1,
	          status_detail     = $2,
	          verified_at       = $3,
	          acme_next_retry_at= $4,
	          next_poll_at      = $5,
	          dns_ttl_seconds   = $6,
	          last_checked_at   = $7,
	          updated_at        = now()
	      WHERE id = $8 AND tenant_id = $9
	      RETURNING ` + connFullColumns
	var out Connection
	err := scanConnectionFull(
		s.pool.QueryRow(ctx, q,
			p.Status, p.StatusDetail, p.VerifiedAt,
			p.AcmeNextRetryAt, p.NextPollAt, p.DNSTTLSeconds, p.LastCheckedAt,
			connID, tenantID,
		).Scan,
		&out,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "connection"}
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// TenantHasVerifiedZone reports whether the tenant has any connection in the
// given registrable zone whose ownership was already verified (status moved
// past pending_verification). Matches the zone apex and any subdomain.
func (s *Store) TenantHasVerifiedZone(ctx context.Context, tenantID int64, zone string) (bool, error) {
	const q = `
		SELECT EXISTS(
			SELECT 1 FROM connections
			WHERE tenant_id = $1
			  AND (domain = $2 OR domain LIKE '%.' || $2)
			  AND status <> 'pending_verification'
		)`
	var ok bool
	if err := s.pool.QueryRow(ctx, q, tenantID, zone).Scan(&ok); err != nil {
		return false, fmt.Errorf("TenantHasVerifiedZone: %w", err)
	}
	return ok, nil
}
