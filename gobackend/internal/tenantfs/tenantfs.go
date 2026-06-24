// Package tenantfs manipulates the per-tenant compose tree, mirroring
// backend/src/admin/router.py. In local mode it renames/removes the live
// compose dirs so Angie's include-glob picks up the change; in both modes it
// records suspend/delete in the shared manifest so edge sidecars converge.
package tenantfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/zwarder/waf/gobackend/internal/storage"
)

type FS struct {
	store     storage.Store
	pub       *storage.Publisher
	localBase string // non-empty in local mode (live tenants dir); "" in s3 mode
}

// New returns an FS. localBase is the live per-tenant root in local mode (so
// suspend/delete also touch the filesystem Angie reads); pass "" in s3 mode.
func New(store storage.Store, pub *storage.Publisher, localBase string) *FS {
	return &FS{store: store, pub: pub, localBase: localBase}
}

func (f *FS) localDir(id int64, leaf string) string {
	return filepath.Join(f.localBase, strconv.FormatInt(id, 10), leaf)
}

// Suspend marks the tenant suspended in the manifest. In local mode it also
// renames compose -> compose.suspended so Angie's glob stops including the
// configs (only if source exists and target doesn't — idempotent).
func (f *FS) Suspend(ctx context.Context, id int64) error {
	if f.localBase != "" {
		src, dst := f.localDir(id, "compose"), f.localDir(id, "compose.suspended")
		if exists(src) && !exists(dst) {
			if err := os.Rename(src, dst); err != nil {
				return fmt.Errorf("tenantfs: suspend rename: %w", err)
			}
		}
	}
	return f.pub.Publish(ctx, storage.ChangeSet{SuspendAdd: []int64{id}})
}

// Unsuspend reverses Suspend.
func (f *FS) Unsuspend(ctx context.Context, id int64) error {
	if f.localBase != "" {
		src, dst := f.localDir(id, "compose.suspended"), f.localDir(id, "compose")
		if exists(src) && !exists(dst) {
			if err := os.Rename(src, dst); err != nil {
				return fmt.Errorf("tenantfs: unsuspend rename: %w", err)
			}
		}
	}
	return f.pub.Publish(ctx, storage.ChangeSet{SuspendRemove: []int64{id}})
}

// Delete removes the whole tenant tree and its manifest entries (best-effort).
func (f *FS) Delete(ctx context.Context, id int64) error {
	if f.localBase != "" {
		if err := os.RemoveAll(filepath.Join(f.localBase, strconv.FormatInt(id, 10))); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else if err := f.store.DeletePrefix(ctx, fmt.Sprintf("tenants/%d/", id)); err != nil {
		return err
	}
	return f.pub.Publish(ctx, storage.ChangeSet{
		RemovedPrefixes: []string{fmt.Sprintf("tenants/%d/", id)},
		SuspendRemove:   []int64{id},
	})
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }
