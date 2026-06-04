package auth

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// cookieMDKey is the metadata key grpc-gateway uses to forward the Cookie
// header (default matcher prefixes permanent headers with "grpcgateway-").
const cookieMDKey = "grpcgateway-cookie"

// sessionCookie matches SESSION_COOKIE in backend/src/auth/dependencies.py.
const sessionCookie = "waf_session"

// Level is the authorization required for an RPC.
type Level int

const (
	LevelAdmin    Level = iota // default (zero value): require_admin — fail closed
	LevelVerified              // require_verified (any verified, non-suspended user)
)

// NewInterceptor builds a unary interceptor. levels maps a gRPC full method
// name (e.g. "/modsecurity.v1.ModSecurityService/GetConfig") to its required
// Level. Methods absent from the map default to LevelAdmin (fail closed).
func NewInterceptor(dec *Decoder, policy *Policy, levels map[string]Level) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		token := extractSessionCookie(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "not authenticated")
		}
		claims, err := dec.Decode(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, ErrInvalidToken.Error())
		}
		var id *Identity
		switch levels[info.FullMethod] {
		case LevelVerified:
			id, err = policy.RequireVerified(ctx, claims)
		default: // LevelAdmin
			id, err = policy.RequireAdmin(ctx, claims)
		}
		if err != nil {
			return nil, toStatus(err)
		}
		return handler(WithIdentity(ctx, id), req)
	}
}

func toStatus(err error) error {
	switch err {
	case ErrUnauthenticated:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrEmailNotVerified, ErrTenantSuspended, ErrForbidden:
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// extractSessionCookie pulls waf_session out of the forwarded Cookie header.
func extractSessionCookie(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, raw := range md.Get(cookieMDKey) {
		for _, part := range strings.Split(raw, ";") {
			name, val, found := strings.Cut(strings.TrimSpace(part), "=")
			if found && name == sessionCookie {
				return val
			}
		}
	}
	return ""
}
