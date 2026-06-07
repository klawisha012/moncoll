package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const invitationColumns = `
	id, tenant_id, email, role, token_hash, invited_by_user_id,
	status, expires_at, accepted_at, created_at`

func scanInvitation(row pgx.Row, inv *Invitation) error {
	return row.Scan(
		&inv.ID, &inv.TenantID, &inv.Email, &inv.Role, &inv.TokenHash,
		&inv.InvitedByUserID, &inv.Status, &inv.ExpiresAt, &inv.AcceptedAt,
		&inv.CreatedAt,
	)
}

func (s *Store) CreateInvitation(ctx context.Context, inv *Invitation) (*Invitation, error) {
	const q = `
		INSERT INTO invitations (tenant_id, email, role, token_hash, invited_by_user_id, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING ` + invitationColumns
	out := &Invitation{}
	err := scanInvitation(
		s.pool.QueryRow(ctx, q, inv.TenantID, inv.Email, inv.Role, inv.TokenHash, inv.InvitedByUserID, inv.ExpiresAt),
		out,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, &ConflictError{Detail: "pending invitation already exists"}
		}
		return nil, fmt.Errorf("CreateInvitation: %w", err)
	}
	return out, nil
}

func (s *Store) GetPendingInvitationForEmail(ctx context.Context, tenantID int64, email string) (*Invitation, error) {
	const q = `SELECT ` + invitationColumns + `
		FROM invitations WHERE tenant_id=$1 AND email=$2 AND status='pending'`
	out := &Invitation{}
	err := scanInvitation(s.pool.QueryRow(ctx, q, tenantID, email), out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "invitation"}
	}
	if err != nil {
		return nil, fmt.Errorf("GetPendingInvitationForEmail: %w", err)
	}
	return out, nil
}

func (s *Store) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*Invitation, error) {
	const q = `SELECT ` + invitationColumns + `
		FROM invitations WHERE token_hash=$1 AND status='pending' AND expires_at > now()`
	out := &Invitation{}
	err := scanInvitation(s.pool.QueryRow(ctx, q, tokenHash), out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "invitation"}
	}
	if err != nil {
		return nil, fmt.Errorf("GetInvitationByTokenHash: %w", err)
	}
	return out, nil
}

func (s *Store) GetInvitationByID(ctx context.Context, id int64) (*Invitation, error) {
	const q = `SELECT ` + invitationColumns + ` FROM invitations WHERE id=$1`
	out := &Invitation{}
	err := scanInvitation(s.pool.QueryRow(ctx, q, id), out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "invitation"}
	}
	if err != nil {
		return nil, fmt.Errorf("GetInvitationByID: %w", err)
	}
	return out, nil
}

func (s *Store) ListInvitationsForTenant(ctx context.Context, tenantID int64) ([]Invitation, error) {
	const q = `SELECT ` + invitationColumns + `
		FROM invitations WHERE tenant_id=$1 ORDER BY created_at DESC`
	return s.queryInvitations(ctx, q, tenantID)
}

func (s *Store) ListPendingInvitationsForEmail(ctx context.Context, email string) ([]Invitation, error) {
	const q = `SELECT ` + invitationColumns + `
		FROM invitations WHERE email=$1 AND status='pending' AND expires_at > now()
		ORDER BY created_at DESC`
	return s.queryInvitations(ctx, q, email)
}

func (s *Store) queryInvitations(ctx context.Context, q string, arg any) ([]Invitation, error) {
	rows, err := s.pool.Query(ctx, q, arg)
	if err != nil {
		return nil, fmt.Errorf("queryInvitations: %w", err)
	}
	defer rows.Close()
	out := []Invitation{}
	for rows.Next() {
		var inv Invitation
		if err := scanInvitation(rows, &inv); err != nil {
			return nil, fmt.Errorf("queryInvitations scan: %w", err)
		}
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("queryInvitations rows: %w", err)
	}
	return out, nil
}

func (s *Store) ResendInvitation(ctx context.Context, id int64, tokenHash string, expiresAt time.Time) error {
	const q = `UPDATE invitations SET token_hash=$2, expires_at=$3
		WHERE id=$1 AND status='pending'`
	ct, err := s.pool.Exec(ctx, q, id, tokenHash, expiresAt)
	if err != nil {
		return fmt.Errorf("ResendInvitation: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return &NotFoundError{Entity: "invitation"}
	}
	return nil
}

func (s *Store) SetInvitationStatus(ctx context.Context, id int64, status string) error {
	const q = `UPDATE invitations SET status=$2 WHERE id=$1 AND status='pending'`
	ct, err := s.pool.Exec(ctx, q, id, status)
	if err != nil {
		return fmt.Errorf("SetInvitationStatus: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return &NotFoundError{Entity: "invitation"}
	}
	return nil
}

func (s *Store) AcceptInvitation(ctx context.Context, inv *Invitation, userID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("AcceptInvitation begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO memberships (tenant_id, user_id, role)
		 VALUES ($1,$2,$3) ON CONFLICT (tenant_id, user_id) DO NOTHING`,
		inv.TenantID, userID, inv.Role,
	); err != nil {
		return fmt.Errorf("AcceptInvitation membership: %w", err)
	}

	ct, err := tx.Exec(ctx,
		`UPDATE invitations SET status='accepted', accepted_at=now()
		 WHERE id=$1 AND status='pending'`, inv.ID)
	if err != nil {
		return fmt.Errorf("AcceptInvitation update: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return &NotFoundError{Entity: "invitation"}
	}
	return tx.Commit(ctx)
}

func (s *Store) GetTenantDisplayName(ctx context.Context, tenantID int64) (string, error) {
	var name string
	err := s.pool.QueryRow(ctx, `SELECT display_name FROM tenants WHERE id=$1`, tenantID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", &NotFoundError{Entity: "tenant"}
	}
	if err != nil {
		return "", fmt.Errorf("GetTenantDisplayName: %w", err)
	}
	return name, nil
}
