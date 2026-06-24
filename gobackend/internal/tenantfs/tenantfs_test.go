package tenantfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zwarder/waf/gobackend/internal/storage"
)

// newFS builds a local-mode FS rooted at base (store + publisher + localBase).
func newFS(base string) *FS {
	st := storage.NewLocalFS(base, "test")
	return New(st, storage.NewPublisher(st), base)
}

func mkComposeWithFile(t *testing.T, base string, id int64) {
	t.Helper()
	dir := filepath.Join(base, "3", "compose")
	_ = id
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.conf"), []byte("x"), 0o644))
}

func TestSuspendUnsuspend(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	mkComposeWithFile(t, base, 3)
	fs := newFS(base)

	require.NoError(t, fs.Suspend(ctx, 3))
	require.NoDirExists(t, filepath.Join(base, "3", "compose"))
	require.DirExists(t, filepath.Join(base, "3", "compose.suspended"))

	// idempotent: target exists, source gone -> no-op, no error
	require.NoError(t, fs.Suspend(ctx, 3))
	require.DirExists(t, filepath.Join(base, "3", "compose.suspended"))

	require.NoError(t, fs.Unsuspend(ctx, 3))
	require.DirExists(t, filepath.Join(base, "3", "compose"))
	require.NoDirExists(t, filepath.Join(base, "3", "compose.suspended"))
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	mkComposeWithFile(t, base, 3)
	fs := newFS(base)
	require.NoError(t, fs.Delete(ctx, 3))
	require.NoDirExists(t, filepath.Join(base, "3"))
}

func TestBestEffortOnMissing(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	fs := newFS(base)
	require.NoError(t, fs.Suspend(ctx, 999))
	require.NoError(t, fs.Unsuspend(ctx, 999))
	require.NoError(t, fs.Delete(ctx, 999))
}
