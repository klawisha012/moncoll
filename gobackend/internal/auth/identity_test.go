package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentityRoundTripsThroughContext(t *testing.T) {
	id := &Identity{UserID: 7, PlatformRole: "admin"}
	ctx := WithIdentity(context.Background(), id)
	got, ok := IdentityFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, int64(7), got.UserID)
	require.Equal(t, "admin", got.PlatformRole)
}

func TestIdentityMissingFromContext(t *testing.T) {
	_, ok := IdentityFromContext(context.Background())
	require.False(t, ok)
}
