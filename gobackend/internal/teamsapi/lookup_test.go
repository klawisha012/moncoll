package teamsapi

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	"github.com/zwarder/waf/gobackend/internal/store"
)

func TestLookupUserByEmail(t *testing.T) {
	// found, already a member — memberRoles path: user 1 is owner, user 2 is member
	t.Run("found and already member", func(t *testing.T) {
		f := adminStore()
		f.users["known@y.test"] = &store.User{ID: 2, Email: "known@y.test", DisplayName: "Known User"}
		f.memberships = nil
		f.memberRoles = map[int64]string{1: "owner", 2: "member"}
		svc, _ := svcWithMailer(f)

		out, err := svc.LookupUserByEmail(ctxWithUser(1, 1), &teamsv1.LookupUserByEmailRequest{Email: " Known@Y.Test "})
		require.NoError(t, err)
		require.True(t, out.Found)
		require.Equal(t, "known@y.test", out.Email)
		require.Equal(t, "Known User", out.DisplayName)
		require.Equal(t, int64(2), out.UserId)
		require.True(t, out.AlreadyMember)
	})

	// found, NOT already a member — user 2 absent from memberRoles
	t.Run("found and not already member", func(t *testing.T) {
		f := adminStore()
		f.users["known@y.test"] = &store.User{ID: 2, Email: "known@y.test", DisplayName: "Known User"}
		f.memberships = nil
		f.memberRoles = map[int64]string{1: "owner"} // user 2 not present
		svc, _ := svcWithMailer(f)

		out, err := svc.LookupUserByEmail(ctxWithUser(1, 1), &teamsv1.LookupUserByEmailRequest{Email: "known@y.test"})
		require.NoError(t, err)
		require.True(t, out.Found)
		require.False(t, out.AlreadyMember)
	})

	// not found → found=false, no error
	t.Run("not found returns false no error", func(t *testing.T) {
		f := adminStore()
		svc, _ := svcWithMailer(f)
		miss, err := svc.LookupUserByEmail(ctxWithUser(1, 1), &teamsv1.LookupUserByEmailRequest{Email: "nobody@y.test"})
		require.NoError(t, err)
		require.False(t, miss.Found)
	})

	// non-admin caller → PermissionDenied
	t.Run("non-admin denied", func(t *testing.T) {
		f := adminStore()
		f.memberships = map[int64]string{1: "member"}
		svc, _ := svcWithMailer(f)
		_, err := svc.LookupUserByEmail(ctxWithUser(1, 1), &teamsv1.LookupUserByEmailRequest{Email: "x@y.test"})
		require.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	// email normalization (whitespace + case folding)
	t.Run("normalizes email", func(t *testing.T) {
		f := adminStore()
		f.users["trimmed@y.test"] = &store.User{ID: 3, Email: "trimmed@y.test", DisplayName: "Trimmed"}
		svc, _ := svcWithMailer(f)
		out, err := svc.LookupUserByEmail(ctxWithUser(1, 1), &teamsv1.LookupUserByEmailRequest{Email: "  TRIMMED@Y.TEST  "})
		require.NoError(t, err)
		require.True(t, out.Found)
		require.Equal(t, "trimmed@y.test", out.Email)
	})

	// blank email after trim → InvalidArgument
	t.Run("empty email invalid", func(t *testing.T) {
		f := adminStore()
		svc, _ := svcWithMailer(f)
		_, err := svc.LookupUserByEmail(ctxWithUser(1, 1), &teamsv1.LookupUserByEmailRequest{Email: "   "})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}
