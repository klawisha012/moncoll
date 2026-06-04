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

// AdminInterceptor enforces RequireAdmin on every unary RPC. The pilot exposes
// only admin routes; per-method policy can be added when mixed-policy modules
// arrive.
func AdminInterceptor(dec *Decoder, policy *Policy) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		token := extractSessionCookie(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "not authenticated")
		}
		claims, err := dec.Decode(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, ErrInvalidToken.Error())
		}
		id, err := policy.RequireAdmin(ctx, claims)
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
