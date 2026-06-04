package store

// email_verification.go — CreateEmailVerification, GetEmailVerification,
// MarkEmailVerificationUsed.
// Mirrors the email_verifications table from models.py.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CreateEmailVerification inserts a new email_verifications row.
// tokenHash is a hex-encoded SHA-256 of the raw token shown to the user.
// purpose must be "verify_email" or "reset_password" (enforced by DB enum).
func (s *Store) CreateEmailVerification(
	ctx context.Context,
	userID int64,
	tokenHash, purpose string,
	expiresAt time.Time,
) error {
	const q = `
		INSERT INTO email_verifications (user_id, purpose, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)`
	_, err := s.pool.Exec(ctx, q, userID, purpose, tokenHash, expiresAt)
	if err != nil {
		return fmt.Errorf("CreateEmailVerification: %w", err)
	}
	return nil
}

// GetEmailVerification returns the verification row matching tokenHash and
// purpose that is unused (used_at IS NULL) and not yet expired.
// Returns *NotFoundError if no valid row exists.
func (s *Store) GetEmailVerification(
	ctx context.Context,
	tokenHash, purpose string,
) (*EmailVerification, error) {
	const q = `
		SELECT id, user_id, purpose, token_hash, expires_at, used_at, created_at
		FROM email_verifications
		WHERE token_hash = $1
		  AND purpose    = $2
		  AND used_at    IS NULL
		  AND expires_at > now()
		LIMIT 1`

	v := &EmailVerification{}
	err := s.pool.QueryRow(ctx, q, tokenHash, purpose).Scan(
		&v.ID, &v.UserID, &v.Purpose, &v.TokenHash,
		&v.ExpiresAt, &v.UsedAt, &v.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "email_verification"}
	}
	if err != nil {
		return nil, fmt.Errorf("GetEmailVerification: %w", err)
	}
	return v, nil
}

// MarkEmailVerificationUsed sets used_at = now() on the row with the given id.
func (s *Store) MarkEmailVerificationUsed(ctx context.Context, id int64) error {
	const q = `UPDATE email_verifications SET used_at = now() WHERE id = $1`
	ct, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("MarkEmailVerificationUsed: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return &NotFoundError{Entity: "email_verification"}
	}
	return nil
}
