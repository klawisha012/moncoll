package store

// oauth.go — GetOAuthAccount, CreateOAuthAccount.
// Mirrors the oauth_accounts table from models.py.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// GetOAuthAccount returns the oauth_accounts row for (provider, providerAccountID).
// Returns *NotFoundError when no row exists.
func (s *Store) GetOAuthAccount(
	ctx context.Context,
	provider, providerAccountID string,
) (*OAuthAccount, error) {
	const q = `
		SELECT id, user_id, provider, provider_account_id, email_at_provider, created_at
		FROM oauth_accounts
		WHERE provider = $1 AND provider_account_id = $2`

	o := &OAuthAccount{}
	err := s.pool.QueryRow(ctx, q, provider, providerAccountID).Scan(
		&o.ID, &o.UserID, &o.Provider, &o.ProviderAccountID,
		&o.EmailAtProvider, &o.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "oauth_account"}
	}
	if err != nil {
		return nil, fmt.Errorf("GetOAuthAccount: %w", err)
	}
	return o, nil
}

// CreateOAuthAccount inserts a new oauth_accounts row and returns it.
// Returns *ConflictError if (provider, provider_account_id) already exists.
func (s *Store) CreateOAuthAccount(
	ctx context.Context,
	userID int64,
	provider, providerAccountID, emailAtProvider string,
) (*OAuthAccount, error) {
	const q = `
		INSERT INTO oauth_accounts (user_id, provider, provider_account_id, email_at_provider)
		VALUES ($1, $2, $3, $4)
		RETURNING id, user_id, provider, provider_account_id, email_at_provider, created_at`

	o := &OAuthAccount{}
	err := s.pool.QueryRow(ctx, q, userID, provider, providerAccountID, emailAtProvider).Scan(
		&o.ID, &o.UserID, &o.Provider, &o.ProviderAccountID,
		&o.EmailAtProvider, &o.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, &ConflictError{Detail: "oauth account already linked"}
		}
		return nil, fmt.Errorf("CreateOAuthAccount: %w", err)
	}
	return o, nil
}
