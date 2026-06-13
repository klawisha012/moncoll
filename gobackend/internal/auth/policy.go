package auth

import (
	"context"
	"errors"
	"strconv"

	"github.com/zwarder/waf/gobackend/internal/store"
)

// Sentinel errors map to the same HTTP statuses + detail strings as the Python
// dependencies. The interceptor (later task) translates these to gRPC codes.
var (
	ErrUnauthenticated  = errors.New("not authenticated")  // 401
	ErrEmailNotVerified = errors.New("email not verified") // 403
	ErrTenantSuspended  = errors.New("tenant suspended")   // 403
	ErrForbidden        = errors.New("forbidden")          // 403 (role/totp)
)

type Policy struct {
	store store.Reader
}

func NewPolicy(r store.Reader) *Policy { return &Policy{store: r} }

// resolveVerified reproduces get_current_user + require_verified.
func (p *Policy) resolveVerified(ctx context.Context, c *Claims) (*Identity, error) {
	uid, err := strconv.ParseInt(c.Sub, 10, 64)
	if err != nil {
		return nil, ErrUnauthenticated // "invalid session" 401
	}
	u, err := p.store.GetUserByID(ctx, uid)
	if err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, ErrUnauthenticated // "user no longer exists" 401
		}
		return nil, err // real DB error -> 500 upstream
	}
	// Session revocation: a token is valid only while its embedded tv matches
	// the user's current token_version. Logout-everywhere and password change
	// bump the column, so any token minted earlier (lower tv) is rejected here.
	// Legacy tokens carry no tv → 0, matching the column default for users that
	// have never revoked, so existing sessions survive a deploy.
	if c.TokenVersion != u.TokenVersion {
		return nil, ErrUnauthenticated // "session expired" 401
	}
	if u.EmailVerifiedAt == nil {
		return nil, ErrEmailNotVerified
	}
	if u.TenantID != nil {
		ten, err := p.store.GetTenantByID(ctx, *u.TenantID)
		if err != nil {
			var nf *store.NotFoundError
			if errors.As(err, &nf) {
				// Python: `if tenant and tenant.suspended_at` — missing tenant
				// is NOT a suspension, so we allow it.
				ten = nil
			} else {
				return nil, err
			}
		}
		if ten != nil && ten.SuspendedAt != nil {
			return nil, ErrTenantSuspended
		}
	}
	return &Identity{UserID: u.ID, PlatformRole: u.PlatformRole, TenantID: u.TenantID}, nil
}

// RequireVerified reproduces require_verified (verified email + non-suspended
// tenant) without the admin/TOTP checks. For client-accessible routes.
func (p *Policy) RequireVerified(ctx context.Context, c *Claims) (*Identity, error) {
	return p.resolveVerified(ctx, c)
}

// RequireAdmin reproduces require_admin (which chains require_verified).
func (p *Policy) RequireAdmin(ctx context.Context, c *Claims) (*Identity, error) {
	id, err := p.resolveVerified(ctx, c)
	if err != nil {
		return nil, err
	}
	if id.PlatformRole != "admin" {
		return nil, ErrForbidden // "admin role required"
	}
	// TOTP enrolment check needs the user row; reload to read totp state.
	u, err := p.store.GetUserByID(ctx, id.UserID)
	if err != nil {
		return nil, err
	}
	if u.TotpEnabledAt == nil {
		return nil, ErrForbidden // "TOTP enrolment required for admin access"
	}
	return id, nil
}
