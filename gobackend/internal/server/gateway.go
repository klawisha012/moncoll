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

	monitoringv1 "github.com/zwarder/waf/gobackend/gen/monitoring/v1"
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
	)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if err := monitoringv1.RegisterMonitoringServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	return mux, nil
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
