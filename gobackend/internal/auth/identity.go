package auth

import "context"

// Identity is the authenticated, DB-verified principal attached to a request.
type Identity struct {
	UserID       int64
	PlatformRole string
	TenantID     *int64
}

type ctxKey struct{}

func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(*Identity)
	return id, ok
}
