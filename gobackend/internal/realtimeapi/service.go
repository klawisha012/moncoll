// Package realtimeapi implements the RealtimeService gRPC server, faithfully
// porting backend/src/realtime/router.py into Go.
//
// Security: GetToken is gated at LevelVerified (require_verified in Python).
// The interceptor enforces this; the handler only needs to read the identity
// and mint a Centrifugo JWT for that user.
package realtimeapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	realtimev1 "github.com/zwarder/waf/gobackend/gen/realtime/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
)

const tokenTTL = time.Hour // matches Python ttl=3600

// TokenMinter abstracts the centrifugo.MintConnectionToken function.
// Allows injecting a fake in tests.
type TokenMinter func(userID string, ttl time.Duration) (string, error)

// Service implements realtimev1.RealtimeServiceServer.
type Service struct {
	realtimev1.UnimplementedRealtimeServiceServer
	mint TokenMinter
}

// New constructs a Service with the given token minter.
// In production, pass centrifugo.MintConnectionToken.
func New(mint TokenMinter) *Service {
	return &Service{mint: mint}
}

func (s *Service) AuthLevels() map[string]auth.Level {
	return map[string]auth.Level{
		realtimev1.RealtimeService_GetToken_FullMethodName: auth.LevelVerified,
	}
}

// GetToken mints a Centrifugo connection JWT for the authenticated user.
// Mirrors router.py issue_token (POST /api/realtime/token, require_verified).
func (s *Service) GetToken(ctx context.Context, _ *emptypb.Empty) (*realtimev1.TokenResponse, error) {
	id, ok := auth.IdentityFromContext(ctx)
	if !ok || id == nil {
		return nil, status.Error(codes.Unauthenticated, "not authenticated")
	}

	userID := formatUserID(id.UserID)
	tokenStr, err := s.mint(userID, tokenTTL)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "token mint failed: %v", err)
	}

	return &realtimev1.TokenResponse{
		Token:      tokenStr,
		TtlSeconds: int32(tokenTTL.Seconds()), //nolint:gosec
	}, nil
}

// formatUserID converts the int64 user ID to the string form Centrifugo expects
// as the JWT sub claim. Mirrors Python's str(user.id).
func formatUserID(id int64) string {
	// Use strconv for zero-allocation formatting.
	return formatInt64(id)
}

func formatInt64(n int64) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := 20
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte(n%10) + '0'
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
