package tenantfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func mkComposeWithFile(t *testing.T, base string, id int64) {
	t.Helper()
	dir := filepath.Join(base, "3", "compose")
	_ = id
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.conf"), []byte("x"), 0o644))
}

func TestSuspendUnsuspend(t *testing.T) {
	base := t.TempDir()
	mkComposeWithFile(t, base, 3)
	fs := New(base)

	require.NoError(t, fs.Suspend(3))
	require.NoDirExists(t, filepath.Join(base, "3", "compose"))
	require.DirExists(t, filepath.Join(base, "3", "compose.suspended"))

	// idempotent: target exists, source gone -> no-op, no error
	require.NoError(t, fs.Suspend(3))
	require.DirExists(t, filepath.Join(base, "3", "compose.suspended"))

	require.NoError(t, fs.Unsuspend(3))
	require.DirExists(t, filepath.Join(base, "3", "compose"))
	require.NoDirExists(t, filepath.Join(base, "3", "compose.suspended"))
}

func TestDelete(t *testing.T) {
	base := t.TempDir()
	mkComposeWithFile(t, base, 3)
	fs := New(base)
	require.NoError(t, fs.Delete(3))
	require.NoDirExists(t, filepath.Join(base, "3"))
}

func TestBestEffortOnMissing(t *testing.T) {
	base := t.TempDir()
	fs := New(base)
	require.NoError(t, fs.Suspend(999))
	require.NoError(t, fs.Unsuspend(999))
	require.NoError(t, fs.Delete(999))
}
