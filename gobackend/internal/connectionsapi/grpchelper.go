package connectionsapi

import (
	"context"
	"fmt"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// grpcSetHeader injects an x-http-code gRPC header so that grpc-gateway
// returns the given HTTP status code for the current RPC.
//
// grpc-gateway v2 reads the "x-http-code" key from the gRPC response header
// metadata and uses it to override the HTTP response status.
func grpcSetHeader(ctx context.Context, code int) error {
	md := metadata.Pairs("x-http-code", strconv.Itoa(code))
	return grpc.SetHeader(ctx, md)
}

// ptrString is a small helper that returns a pointer to a string value.
func ptrString(s string) *string { return &s }

// ptrTime is a small helper (unused externally but kept for symmetry).
func ptrStringOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

var _ = fmt.Sprintf // keep fmt import used
