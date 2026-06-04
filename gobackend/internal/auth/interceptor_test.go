package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
	ic := NewInterceptor(dec, p, nil)
	resp, err := ic(ctxWithCookie("waf_session="+validToken(t)), nil,
		&grpc.UnaryServerInfo{}, okHandler)
	require.NoError(t, err)
	require.Equal(t, "ok", resp)
}

func TestAdminInterceptorNoCookie(t *testing.T) {
	ic := NewInterceptor(NewDecoder(testKey()), newPolicy(adminUser(), nil), nil)
	_, err := ic(context.Background(), nil, &grpc.UnaryServerInfo{}, okHandler)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAdminInterceptorNonAdmin(t *testing.T) {
	u := adminUser()
	u.PlatformRole = "client"
	ic := NewInterceptor(NewDecoder(testKey()), newPolicy(u, nil), nil)
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
	ic := NewInterceptor(NewDecoder(testKey()), p, levels)
	tok := mintLocal(t, testKey(), `{"sub":"7","pr":"client","exp":`+
		itoa(time.Now().Add(time.Hour).Unix())+`.0}`)
	resp, err := ic(ctxWithCookie("waf_session="+tok), nil,
		&grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, okHandler)
	require.NoError(t, err)
	require.Equal(t, "ok", resp)
}

func TestInterceptorAdminDefaultRejectsClient(t *testing.T) {
	u := adminUser()
	u.PlatformRole = "client"
	p := newPolicy(u, nil)
	ic := NewInterceptor(NewDecoder(testKey()), p, nil) // no entry -> admin default
	tok := mintLocal(t, testKey(), `{"sub":"7","pr":"client","exp":`+
		itoa(time.Now().Add(time.Hour).Unix())+`.0}`)
	_, err := ic(ctxWithCookie("waf_session="+tok), nil,
		&grpc.UnaryServerInfo{FullMethod: "/svc/Unlisted"}, okHandler)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}
