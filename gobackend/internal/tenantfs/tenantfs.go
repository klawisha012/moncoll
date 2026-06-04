// Package tenantfs manipulates the per-tenant compose tree under a base dir
// (default /var/lib/waf/tenants), mirroring backend/src/admin/router.py.
package tenantfs

import (
	"os"
	"path/filepath"
	"strconv"
)

type FS struct{ base string }

func New(base string) *FS { return &FS{base: base} }

func (f *FS) dir(id int64, leaf string) string {
	return filepath.Join(f.base, strconv.FormatInt(id, 10), leaf)
}

// Suspend renames compose -> compose.suspended (only if source exists and the
// target doesn't), so the Angie include-glob stops picking up the configs.
func (f *FS) Suspend(id int64) error {
	src, dst := f.dir(id, "compose"), f.dir(id, "compose.suspended")
	if exists(src) && !exists(dst) {
		return os.Rename(src, dst)
	}
	return nil
}

func (f *FS) Unsuspend(id int64) error {
	src, dst := f.dir(id, "compose.suspended"), f.dir(id, "compose")
	if exists(src) && !exists(dst) {
		return os.Rename(src, dst)
	}
	return nil
}

// Delete removes the whole tenant tree, ignoring "not exist" (best-effort,
// matching shutil.rmtree(..., ignore_errors=True)).
func (f *FS) Delete(id int64) error {
	err := os.RemoveAll(filepath.Join(f.base, strconv.FormatInt(id, 10)))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }
