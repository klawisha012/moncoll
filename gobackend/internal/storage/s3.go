package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

// s3Store is the shared backend (MinIO / any S3-compatible). Enables horizontal
// scaling: many backend replicas write here, every edge sidecar reads from here.
type s3Store struct {
	client *minio.Client
	bucket string
	scope  string
}

// S3Options configures the s3 backend.
type S3Options struct {
	Endpoint, AccessKey, SecretKey, Bucket, Region, Scope string
	UseTLS                                                bool
}

// NewS3 builds an s3-backed Store.
func NewS3(o S3Options) (Store, error) {
	cl, err := minio.New(o.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(o.AccessKey, o.SecretKey, ""),
		Secure: o.UseTLS,
		Region: o.Region,
	})
	if err != nil {
		return nil, err
	}
	scope := o.Scope
	if scope == "" {
		scope = "default"
	}
	return &s3Store{client: cl, bucket: o.Bucket, scope: scope}, nil
}

func isNoSuchKey(err error) bool {
	return minio.ToErrorResponse(err).Code == "NoSuchKey"
}

func infoFromObj(key string, oi minio.ObjectInfo) ObjectInfo {
	return ObjectInfo{Key: key, ETag: strings.Trim(oi.ETag, `"`), Size: oi.Size, ModTime: oi.LastModified}
}

func (s *s3Store) Put(ctx context.Context, key string, r io.Reader, opts PutOptions) (ObjectInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return ObjectInfo{}, err
	}
	putOpts := minio.PutObjectOptions{ContentType: "application/octet-stream"}
	if opts.Sensitive {
		putOpts.ServerSideEncryption = encrypt.NewSSE() // SSE-S3 at rest (FR-010)
	}
	ui, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), putOpts)
	if err != nil {
		return ObjectInfo{}, err
	}
	mode := opts.Mode
	if mode == 0 {
		mode = defaultMode(opts.Sensitive)
	}
	// Mode/Sensitive are carried authoritatively in the manifest Entry; the
	// returned info mirrors the requested write so callers don't re-Stat.
	return ObjectInfo{Key: key, ETag: strings.Trim(ui.ETag, `"`), Size: int64(len(data)), Mode: mode, Sensitive: opts.Sensitive, ModTime: ui.LastModified}, nil
}

func (s *s3Store) Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	st, err := obj.Stat()
	if err != nil {
		_ = obj.Close()
		if isNoSuchKey(err) {
			return nil, ObjectInfo{}, ErrNotFound
		}
		return nil, ObjectInfo{}, err
	}
	return obj, infoFromObj(key, st), nil
}

func (s *s3Store) Delete(ctx context.Context, key string) error {
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}

func (s *s3Store) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var out []ObjectInfo
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		out = append(out, infoFromObj(obj.Key, obj))
	}
	return out, nil
}

func (s *s3Store) Stat(ctx context.Context, key string) (ObjectInfo, error) {
	st, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if isNoSuchKey(err) {
			return ObjectInfo{}, ErrNotFound
		}
		return ObjectInfo{}, err
	}
	return infoFromObj(key, st), nil
}

func (s *s3Store) ReadManifest(ctx context.Context) (Manifest, string, error) {
	rc, info, err := s.Get(ctx, ManifestKey)
	if errors.Is(err, ErrNotFound) {
		return NewManifest(s.scope), "", nil
	}
	if err != nil {
		return Manifest{}, "", err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return Manifest{}, "", err
	}
	m, err := unmarshalManifest(data)
	if err != nil {
		return Manifest{}, "", err
	}
	return m, info.ETag, nil
}

func (s *s3Store) PublishManifest(ctx context.Context, m Manifest, ifMatchETag string) (string, error) {
	// ponytail: optimistic check-then-put CAS. A small window exists between the
	// read and the put; US2 (T024/T025) serialises publishers with a Postgres
	// advisory lock to close it. Adequate for tens of nodes + infrequent
	// operator writes; upgrade to native S3 If-Match PUT when relied on hotter.
	_, cur, err := s.ReadManifest(ctx)
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
	ui, err := s.client.PutObject(ctx, s.bucket, ManifestKey, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{ContentType: "application/json"})
	if err != nil {
		return "", err
	}
	return strings.Trim(ui.ETag, `"`), nil
}
