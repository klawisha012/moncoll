// Package server wires the gRPC server and the grpc-gateway REST mux.
package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	adminv1 "github.com/zwarder/waf/gobackend/gen/admin/v1"
	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	connectionsv1 "github.com/zwarder/waf/gobackend/gen/connections/v1"
	crowdsecv1 "github.com/zwarder/waf/gobackend/gen/crowdsec/v1"
	dashboardv1 "github.com/zwarder/waf/gobackend/gen/dashboard/v1"
	modsecurityv1 "github.com/zwarder/waf/gobackend/gen/modsecurity/v1"
	monitoringv1 "github.com/zwarder/waf/gobackend/gen/monitoring/v1"
	notificationsv1 "github.com/zwarder/waf/gobackend/gen/notifications/v1"
	realtimev1 "github.com/zwarder/waf/gobackend/gen/realtime/v1"
	sslv1 "github.com/zwarder/waf/gobackend/gen/ssl/v1"
	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	testsv1 "github.com/zwarder/waf/gobackend/gen/tests/v1"
)

// Response-metadata keys the auth service emits (must match
// internal/authapi/cookies.go). grpc lowercases metadata keys; ServerMetadata
// surfaces them under "x-set-cookie" / "x-redirect" (custom prefix, NOT
// grpcgateway-).
const (
	mdSetCookie = "x-set-cookie"
	mdRedirect  = "x-redirect"
)

// NewGatewayMux builds the REST mux that talks to the in-process gRPC server at
// grpcAddr. JSON uses proto field names (snake_case) and emits zero values so
// the contract matches FastAPI's pydantic output. The default incoming-header
// matcher forwards the Cookie header to gRPC metadata as "grpcgateway-cookie".
func NewGatewayMux(ctx context.Context, grpcAddr string) (*runtime.ServeMux, error) {
	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions: protoJSONMarshal(),
		}),
		runtime.WithErrorHandler(detailErrorHandler),
		runtime.WithForwardResponseOption(cookieRedirectForwarder),
		runtime.WithForwardResponseOption(func(_ context.Context, w http.ResponseWriter, resp proto.Message) error {
			// Authenticated, dynamic API: never let a browser/proxy cache it.
			// Prevents stale GETs (e.g. an empty catalog fetched before its data
			// existed) from sticking around across reloads.
			w.Header().Set("Cache-Control", "no-store")
			if _, ok := resp.(*emptypb.Empty); ok {
				w.WriteHeader(http.StatusNoContent)
			}
			return nil
		}),
	)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if err := monitoringv1.RegisterMonitoringServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := adminv1.RegisterAdminServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := modsecurityv1.RegisterModSecurityServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := crowdsecv1.RegisterCrowdSecServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := dashboardv1.RegisterDashboardServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := sslv1.RegisterSSLServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := connectionsv1.RegisterConnectionsServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := authv1.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := realtimev1.RegisterRealtimeServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := testsv1.RegisterTestsServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := teamsv1.RegisterTeamsServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := notificationsv1.RegisterNotificationsServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	return mux, nil
}

// cookieRedirectForwarder translates the auth service's response metadata into
// real HTTP Set-Cookie / 302 Location. gRPC handlers can't set HTTP headers
// directly, so they emit metadata via grpc.SetHeader (see
// internal/authapi/cookies.go); this reads ServerMetadata and writes the
// headers. Multiple x-set-cookie values accumulate into multiple Set-Cookie
// headers (login + clear, totp confirm clears 2 + sets 1, etc.).
func cookieRedirectForwarder(ctx context.Context, w http.ResponseWriter, _ proto.Message) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		return nil
	}
	for _, c := range md.HeaderMD.Get(mdSetCookie) {
		w.Header().Add("Set-Cookie", c)
	}
	if loc := md.HeaderMD.Get(mdRedirect); len(loc) > 0 && loc[0] != "" {
		w.Header().Set("Location", loc[0])
		w.WriteHeader(http.StatusFound) // 302
	}
	return nil
}

// detailErrorHandler renders errors as {"detail": "..."} to match FastAPI's
// HTTPException body, with the same status codes the Python deps produced.
func detailErrorHandler(_ context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, _ *http.Request, err error) {
	st := status.Convert(err)
	httpStatus := runtime.HTTPStatusFromCode(st.Code())
	if st.Code() == codes.PermissionDenied {
		httpStatus = http.StatusForbidden
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": st.Message()})
}
