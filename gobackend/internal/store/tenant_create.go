package store

// tenant_create.go — CreateTenant + slug derivation, mirroring
// backend/src/tenants/service.py (create_tenant, _slugify, _validate_name,
// auto_create_tenant_for_user). Used by the auth service's signup + oauth
// flows to provision a tenant for a new client user.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// tenantNameRE mirrors TENANT_NAME_RE in tenants/service.py:
//
//	^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$
//
// lowercase alphanumeric + hyphens, 3–32 chars, no leading/trailing hyphen.
var tenantNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

// slugNonAlnumRE matches runs of non-[a-z0-9] characters for _slugify.
var slugNonAlnumRE = regexp.MustCompile(`[^a-z0-9]+`)

// slugMultiHyphenRE collapses runs of 2+ hyphens.
var slugMultiHyphenRE = regexp.MustCompile(`-{2,}`)

// ErrInvalidTenantName mirrors tenants.service.InvalidTenantName.
var ErrInvalidTenantName = errors.New("invalid tenant name")

// ValidateTenantName returns ErrInvalidTenantName when name does not match the
// Python TENANT_NAME_RE. Exported so the auth service can validate a
// user-supplied tenant_name before insertion (signup flow).
func ValidateTenantName(name string) error {
	if !tenantNameRE.MatchString(name) {
		return ErrInvalidTenantName
	}
	return nil
}

// CreateTenant inserts a new tenant row and returns it. Validates name against
// TENANT_NAME_RE first (→ ErrInvalidTenantName) and returns *ConflictError when
// the name is already taken (UNIQUE violation or pre-check). displayName falls
// back to name when empty (mirrors create_tenant).
func (s *Store) CreateTenant(ctx context.Context, name, displayName string) (*Tenant, error) {
	if err := ValidateTenantName(name); err != nil {
		return nil, err
	}
	if displayName == "" {
		displayName = name
	}
	const q = `
		INSERT INTO tenants (name, display_name)
		VALUES ($1, $2)
		RETURNING id, name, suspended_at`
	t := &Tenant{}
	err := s.pool.QueryRow(ctx, q, name, displayName).Scan(&t.ID, &t.Name, &t.SuspendedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, &ConflictError{Detail: "tenant name taken"}
		}
		return nil, fmt.Errorf("CreateTenant: %w", err)
	}
	return t, nil
}

// GetTenantByName returns the tenant with the given name, or *NotFoundError.
func (s *Store) GetTenantByName(ctx context.Context, name string) (*Tenant, error) {
	const q = `SELECT id, name, suspended_at FROM tenants WHERE name = $1`
	t := &Tenant{}
	err := s.pool.QueryRow(ctx, q, name).Scan(&t.ID, &t.Name, &t.SuspendedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "tenant"}
	}
	if err != nil {
		return nil, fmt.Errorf("GetTenantByName: %w", err)
	}
	return t, nil
}

// slugify mirrors _slugify in tenants/service.py: lowercase, replace non-[a-z0-9]
// runs with hyphens, strip leading/trailing hyphens, collapse multi-hyphens,
// clamp to 32 chars respecting "must end on [a-z0-9]". May return "".
func slugify(raw string) string {
	lowered := strings.ToLower(raw)
	out := strings.Trim(slugNonAlnumRE.ReplaceAllString(lowered, "-"), "-")
	out = slugMultiHyphenRE.ReplaceAllString(out, "-")
	if len(out) > 32 {
		out = strings.TrimRight(out[:32], "-")
	}
	return out
}

// defaultTeamDisplayName builds the default display name for an auto-created
// personal team from the email local-part: "zw4rder@gmail.com" -> "zw4rder's
// team". Strips a "+tag" sub-address and clamps to display_name's 64-char
// column. Returns "" when there is no usable local-part, so the caller falls
// back to the slug.
func defaultTeamDisplayName(email string) string {
	local := email
	if i := strings.Index(local, "@"); i >= 0 {
		local = local[:i]
	}
	if i := strings.Index(local, "+"); i >= 0 {
		local = local[:i]
	}
	local = strings.TrimSpace(local)
	if local == "" {
		return ""
	}
	const suffix = "'s team"
	if r := []rune(local); len(r)+len(suffix) > 64 {
		local = strings.TrimSpace(string(r[:64-len(suffix)]))
		if local == "" {
			return ""
		}
	}
	return local + suffix
}

// AutoCreateTenantForUser derives a unique tenant slug from displayName or the
// email local-part, then creates the tenant (appending -2, -3, … to the slug on
// collision). The display name is always derived from the email local-part
// ("<local>'s team") so personal teams get a stable default that does not
// repeat the user's full name.
func (s *Store) AutoCreateTenantForUser(ctx context.Context, email, displayName string) (*Tenant, error) {
	display := defaultTeamDisplayName(email)
	base := slugify(displayName)
	if base == "" {
		localPart := email
		if i := strings.Index(email, "@"); i >= 0 {
			localPart = email[:i]
		}
		base = slugify(localPart)
	}
	if base == "" {
		base = "ws"
	}
	// Ensure minimum length of 3 (regex requirement).
	if len(base) < 3 {
		base = strings.TrimRight((base + "-ws"), "-")
		if len(base) > 32 {
			base = strings.TrimRight(base[:32], "-")
		}
	}

	// Try base first, then base-2 … base-99.
	suffixes := make([]string, 0, 99)
	suffixes = append(suffixes, "")
	for i := 2; i < 100; i++ {
		suffixes = append(suffixes, fmt.Sprintf("-%d", i))
	}

	for _, suffix := range suffixes {
		candidate := base + suffix
		if len(candidate) > 32 {
			keep := 32 - len(suffix)
			if keep < 0 {
				keep = 0
			}
			candidate = strings.TrimRight(base[:keep], "-") + suffix
		}
		if !tenantNameRE.MatchString(candidate) {
			continue
		}
		// Check availability; create on first free candidate.
		_, err := s.GetTenantByName(ctx, candidate)
		var nf *NotFoundError
		if errors.As(err, &nf) {
			return s.CreateTenant(ctx, candidate, display)
		}
		if err != nil {
			return nil, err
		}
		// taken → next candidate
	}
	return nil, fmt.Errorf("%w: cannot derive a unique tenant slug from email=%q display=%q",
		ErrInvalidTenantName, email, displayName)
}
