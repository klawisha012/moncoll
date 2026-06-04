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
	ic := AdminInterceptor(dec, p)
	resp, err := ic(ctxWithCookie("waf_session="+validToken(t)), nil,
		&grpc.UnaryServerInfo{}, okHandler)
	require.NoError(t, err)
	require.Equal(t, "ok", resp)
}

func TestAdminInterceptorNoCookie(t *testing.T) {
	ic := AdminInterceptor(NewDecoder(testKey()), newPolicy(adminUser(), nil))
	_, err := ic(context.Background(), nil, &grpc.UnaryServerInfo{}, okHandler)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAdminInterceptorNonAdmin(t *testing.T) {
	u := adminUser()
	u.PlatformRole = "client"
	ic := AdminInterceptor(NewDecoder(testKey()), newPolicy(u, nil))
	tok := mintLocal(t, testKey(), `{"sub":"7","pr":"client","exp":`+
		itoa(time.Now().Add(time.Hour).Unix())+`.0}`)
	_, err := ic(ctxWithCookie("waf_session="+tok), nil, &grpc.UnaryServerInfo{}, okHandler)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}
