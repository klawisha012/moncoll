package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zwarder/waf/gobackend/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func ctxWithCookie(cookie string) context.Context {
	md := metadata.New(map[string]string{"grpcgateway-cookie": cookie})
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestExtractSessionCookie(t *testing.T) {
	ctx := ctxWithCookie("foo=1; waf_session=TOKEN123; bar=2")
	require.Equal(t, "TOKEN123", extractSessionCookie(ctx))

	require.Equal(t, "", extractSessionCookie(context.Background()))
	require.Equal(t, "", extractSessionCookie(ctxWithCookie("foo=1; bar=2")))
}

func validToken(t *testing.T) string {
	return mintLocal(t, testKey(), `{"sub":"7","pr":"admin","tn":null,"tr":null,"iat":1.0,"exp":`+
		itoa(time.Now().Add(time.Hour).Unix())+`.0}`)
}

func okHandler(ctx context.Context, _ any) (any, error) {
	if _, ok := IdentityFromContext(ctx); !ok {
		return nil, status.Error(codes.Internal, "no identity in ctx")
	}
	return "ok", nil
}

func TestAdminInterceptorHappyPath(t *testing.T) {
	dec := NewDecoder(testKey())
	p := newPolicy(adminUser(), nil)
	ic := NewInterceptor(dec, p, nil, 0)
	resp, err := ic(ctxWithCookie("waf_session="+validToken(t)), nil,
		&grpc.UnaryServerInfo{}, okHandler)
	require.NoError(t, err)
	require.Equal(t, "ok", resp)
}

func TestAdminInterceptorNoCookie(t *testing.T) {
	ic := NewInterceptor(NewDecoder(testKey()), newPolicy(adminUser(), nil), nil, 0)
	_, err := ic(context.Background(), nil, &grpc.UnaryServerInfo{}, okHandler)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAdminInterceptorNonAdmin(t *testing.T) {
	u := adminUser()
	u.PlatformRole = "client"
	ic := NewInterceptor(NewDecoder(testKey()), newPolicy(u, nil), nil, 0)
	tok := mintLocal(t, testKey(), `{"sub":"7","pr":"client","exp":`+
		itoa(time.Now().Add(time.Hour).Unix())+`.0}`)
	_, err := ic(ctxWithCookie("waf_session="+tok), nil, &grpc.UnaryServerInfo{}, okHandler)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestInterceptorVerifiedLevelAllowsClient(t *testing.T) {
	u := adminUser()
	u.PlatformRole = "client" // a verified client, NOT admin
	p := newPolicy(u, nil)
	levels := map[string]Level{"/svc/Method": LevelVerified}
	ic := NewInterceptor(NewDecoder(testKey()), p, levels, 0)
	tok := mintLocal(t, testKey(), `{"sub":"7","pr":"client","exp":`+
		itoa(time.Now().Add(time.Hour).Unix())+`.0}`)
	resp, err := ic(ctxWithCookie("waf_session="+tok), nil,
		&grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, okHandler)
	require.NoError(t, err)
	require.Equal(t, "ok", resp)
}

// TestInterceptorPublicReachableWithoutCookie verifies a LevelPublic method is
// reachable with NO cookie at all and that NO identity is attached (the handler
// must not assume IdentityFromContext succeeds).
func TestInterceptorPublicReachableWithoutCookie(t *testing.T) {
	p := newPolicy(adminUser(), nil)
	levels := map[string]Level{"/auth.v1.AuthService/Login": LevelPublic}
	ic := NewInterceptor(NewDecoder(testKey()), p, levels, 0)

	publicHandler := func(ctx context.Context, _ any) (any, error) {
		if _, ok := IdentityFromContext(ctx); ok {
			return nil, status.Error(codes.Internal, "public method should have no identity")
		}
		return "public-ok", nil
	}

	// No cookie whatsoever.
	resp, err := ic(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/auth.v1.AuthService/Login"}, publicHandler)
	require.NoError(t, err)
	require.Equal(t, "public-ok", resp)
}

func TestInterceptorAdminDefaultRejectsClient(t *testing.T) {
	u := adminUser()
	u.PlatformRole = "client"
	p := newPolicy(u, nil)
	ic := NewInterceptor(NewDecoder(testKey()), p, nil, 0) // no entry -> admin default
	tok := mintLocal(t, testKey(), `{"sub":"7","pr":"client","exp":`+
		itoa(time.Now().Add(time.Hour).Unix())+`.0}`)
	_, err := ic(ctxWithCookie("waf_session="+tok), nil,
		&grpc.UnaryServerInfo{FullMethod: "/svc/Unlisted"}, okHandler)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

// captureIdentity returns a handler that records the Identity attached by the
// interceptor, so tests can assert the effective tenant scope.
func captureIdentity(dst **Identity) grpc.UnaryHandler {
	return func(ctx context.Context, _ any) (any, error) {
		id, ok := IdentityFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Internal, "no identity in ctx")
		}
		*dst = id
		return "ok", nil
	}
}

func TestInterceptorAdminVerifiedScopedToSystemTenant(t *testing.T) {
	const systemTenantID int64 = 99
	p := newPolicy(adminUser(), nil) // admin, tenant_id nil
	levels := map[string]Level{"/svc/ClientMethod": LevelVerified}
	ic := NewInterceptor(NewDecoder(testKey()), p, levels, systemTenantID)

	var got *Identity
	_, err := ic(ctxWithCookie("waf_session="+validToken(t)), nil,
		&grpc.UnaryServerInfo{FullMethod: "/svc/ClientMethod"}, captureIdentity(&got))
	require.NoError(t, err)
	require.NotNil(t, got.TenantID, "admin on a client method must be scoped to the system tenant")
	require.Equal(t, systemTenantID, *got.TenantID)
}

func TestInterceptorAdminLevelAdminKeepsPlatformScope(t *testing.T) {
	const systemTenantID int64 = 99
	p := newPolicy(adminUser(), nil)
	levels := map[string]Level{"/svc/AdminMethod": LevelAdmin}
	ic := NewInterceptor(NewDecoder(testKey()), p, levels, systemTenantID)

	var got *Identity
	_, err := ic(ctxWithCookie("waf_session="+validToken(t)), nil,
		&grpc.UnaryServerInfo{FullMethod: "/svc/AdminMethod"}, captureIdentity(&got))
	require.NoError(t, err)
	require.Nil(t, got.TenantID, "admin on an admin method must keep platform scope (nil tenant)")
}

func TestInterceptorClientVerifiedKeepsOwnTenant(t *testing.T) {
	const systemTenantID int64 = 99
	tid := int64(5)
	u := verifiedUser(0) // client, tenant_id nil by default
	u.TenantID = &tid
	p := newPolicy(u, &store.Tenant{ID: 5}) // tenant present, not suspended
	levels := map[string]Level{"/svc/ClientMethod": LevelVerified}
	ic := NewInterceptor(NewDecoder(testKey()), p, levels, systemTenantID)

	tok := mintLocal(t, testKey(), `{"sub":"7","pr":"client","exp":`+
		itoa(time.Now().Add(time.Hour).Unix())+`.0}`)
	var got *Identity
	_, err := ic(ctxWithCookie("waf_session="+tok), nil,
		&grpc.UnaryServerInfo{FullMethod: "/svc/ClientMethod"}, captureIdentity(&got))
	require.NoError(t, err)
	require.NotNil(t, got.TenantID)
	require.Equal(t, tid, *got.TenantID, "a non-admin must NOT be re-scoped to the system tenant")
}
