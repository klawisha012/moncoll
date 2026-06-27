package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// localStore keeps the current single-node behaviour: state lives under a local
// directory (a bind-mounted volume). Default backend; zero behaviour change for
// single-node deploys (FR backward-compat).
type localStore struct {
	root   string
	scope  string
	layout *LocalLayout // when set, keys map to live Angie paths (WAF local mode)
	mu     sync.Mutex   // serialises manifest CAS within a process
}

// NewLocalFS returns a Store rooted at dir (generic; keys join under root).
func NewLocalFS(dir, scope string) Store {
	return &localStore{root: dir, scope: scope}
}

// NewLocalFSMapped returns a Store that writes canonical keys to the live local
// paths defined by layout — preserving the single-node volume layout so Angie
// reads exactly as before (FR backward-compat).
func NewLocalFSMapped(layout LocalLayout, scope string) Store {
	return &localStore{layout: &layout, scope: scope}
}

func (l *localStore) path(key string) (string, error) {
	if l.layout != nil {
		return l.layout.Path(key)
	}
	if _, err := canonicalKeyParts(strings.TrimSuffix(key, "/")); err != nil {
		return "", err
	}
	return filepath.Join(l.root, filepath.FromSlash(key)), nil
}

func (l *localStore) Put(_ context.Context, key string, r io.Reader, opts PutOptions) (ObjectInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return ObjectInfo{}, err
	}
	mode := opts.Mode
	if mode == 0 {
		mode = defaultMode(opts.Sensitive)
	}
	p, err := l.path(key)
	if err != nil {
		return ObjectInfo{}, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return ObjectInfo{}, err
	}
	if err := os.WriteFile(p, data, os.FileMode(mode)); err != nil {
		return ObjectInfo{}, err
	}
	return ObjectInfo{Key: key, ETag: contentETag(data), Size: int64(len(data)), Mode: mode, Sensitive: opts.Sensitive, ModTime: time.Now()}, nil
}

func (l *localStore) Get(_ context.Context, key string) (io.ReadCloser, ObjectInfo, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ObjectInfo{}, ErrNotFound
	}
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	info := ObjectInfo{Key: key, ETag: contentETag(data), Size: int64(len(data))}
	if fi, statErr := os.Stat(p); statErr == nil {
		info.Mode = uint32(fi.Mode().Perm())
		info.ModTime = fi.ModTime()
	}
	return io.NopCloser(bytes.NewReader(data)), info, nil
}

func (l *localStore) Delete(_ context.Context, key string) error {
	p, pathErr := l.path(key)
	if pathErr != nil {
		return pathErr
	}
	err := os.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (l *localStore) DeletePrefix(_ context.Context, prefix string) error {
	p, pathErr := l.path(prefix)
	if pathErr != nil {
		return pathErr
	}
	err := os.RemoveAll(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (l *localStore) List(_ context.Context, prefix string) ([]ObjectInfo, error) {
	if l.layout != nil {
		// Local (single-node) mode writes through to live paths and never
		// enumerates; the sidecar (s3 mode) is the only List caller.
		return nil, errors.New("storage: List unsupported on mapped localFS")
	}
	base, err := l.path(prefix)
	if err != nil {
		return nil, err
	}
	var out []ObjectInfo
	err = filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil // empty prefix → empty result
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(l.root, p)
		if rerr != nil {
			return rerr
		}
		fi, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		out = append(out, ObjectInfo{Key: filepath.ToSlash(rel), Size: fi.Size(), Mode: uint32(fi.Mode().Perm()), ModTime: fi.ModTime()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (l *localStore) Stat(_ context.Context, key string) (ObjectInfo, error) {
	p, err := l.path(key)
	if err != nil {
		return ObjectInfo{}, err
	}
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return ObjectInfo{}, ErrNotFound
	}
	if err != nil {
		return ObjectInfo{}, err
	}
	return ObjectInfo{Key: key, Size: fi.Size(), Mode: uint32(fi.Mode().Perm()), ModTime: fi.ModTime()}, nil
}

func (l *localStore) ReadManifest(_ context.Context) (Manifest, string, error) {
	return l.readManifestLocked()
}

func (l *localStore) readManifestLocked() (Manifest, string, error) {
	p, pathErr := l.path(ManifestKey)
	if pathErr != nil {
		return Manifest{}, "", pathErr
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return NewManifest(l.scope), "", nil
	}
	if err != nil {
		return Manifest{}, "", err
	}
	m, err := unmarshalManifest(data)
	if err != nil {
		return Manifest{}, "", err
	}
	return m, contentETag(data), nil
}

func (l *localStore) PublishManifest(_ context.Context, m Manifest, ifMatchETag string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, cur, err := l.readManifestLocked()
	if err != nil {
		return "", err
	}
	if cur != ifMatchETag {
		return "", ErrConflict
	}
	data, err := marshalManifest(m)
	if err != nil {
		return "", err
	}
	p, err := l.path(ManifestKey)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return "", err
	}
	return contentETag(data), nil
}
