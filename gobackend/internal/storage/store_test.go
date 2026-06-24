package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

// backends returns the Store implementations under test. localFS always runs;
// s3 runs only when WAF_TEST_S3_ENDPOINT is set (CI brings up MinIO).
func backends(t *testing.T) map[string]func() Store {
	out := map[string]func() Store{
		"localfs": func() Store { return NewLocalFS(t.TempDir(), "test") },
	}
	if ep := os.Getenv("WAF_TEST_S3_ENDPOINT"); ep != "" {
		out["s3"] = func() Store {
			s, err := NewS3(S3Options{
				Endpoint:  ep,
				AccessKey: os.Getenv("WAF_TEST_S3_ACCESS_KEY"),
				SecretKey: os.Getenv("WAF_TEST_S3_SECRET_KEY"),
				Bucket:    os.Getenv("WAF_TEST_S3_BUCKET"),
				Scope:     "test",
			})
			if err != nil {
				t.Fatalf("NewS3: %v", err)
			}
			return s
		}
	}
	return out
}

func TestStoreContract(t *testing.T) {
	ctx := context.Background()
	for name, mk := range backends(t) {
		t.Run(name, func(t *testing.T) {
			s := mk()
			const k = "tenants/1/conn_1/1.conf"

			// 1. Put → Get round-trip, non-empty etag.
			info, err := s.Put(ctx, k, bytes.NewReader([]byte("server{}")), PutOptions{})
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			if info.ETag == "" {
				t.Fatal("Put returned empty ETag")
			}
			rc, _, err := s.Get(ctx, k)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			got, _ := io.ReadAll(rc)
			_ = rc.Close()
			if string(got) != "server{}" {
				t.Fatalf("Get round-trip = %q", got)
			}

			// 2. Different content → different etag.
			info2, err := s.Put(ctx, k, bytes.NewReader([]byte("server{x}")), PutOptions{})
			if err != nil {
				t.Fatalf("Put#2: %v", err)
			}
			if info2.ETag == info.ETag {
				t.Fatal("ETag did not change for new content")
			}

			// 3. Delete → ErrNotFound.
			if err := s.Delete(ctx, k); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, _, err := s.Get(ctx, k); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
			}

			// 4. List by prefix.
			_, _ = s.Put(ctx, "state/a.json", bytes.NewReader([]byte("1")), PutOptions{})
			_, _ = s.Put(ctx, "state/b.json", bytes.NewReader([]byte("2")), PutOptions{})
			lst, err := s.List(ctx, "state/")
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(lst) < 2 {
				t.Fatalf("List(state/) = %d items, want >=2", len(lst))
			}

			// 5. Manifest CAS: correct ifMatch succeeds, stale ifMatch → ErrConflict.
			m, etag, err := s.ReadManifest(ctx)
			if err != nil {
				t.Fatalf("ReadManifest: %v", err)
			}
			m.Generation++
			if _, err := s.PublishManifest(ctx, m, etag); err != nil {
				t.Fatalf("PublishManifest (fresh): %v", err)
			}
			m.Generation++
			if _, err := s.PublishManifest(ctx, m, etag); !errors.Is(err, ErrConflict) {
				t.Fatalf("PublishManifest (stale) = %v, want ErrConflict", err)
			}

			// 6. Sensitive write → mode 0600.
			si, err := s.Put(ctx, "tenants/1/conn_1/1.key", bytes.NewReader([]byte("KEY")), PutOptions{Sensitive: true})
			if err != nil {
				t.Fatalf("Put sensitive: %v", err)
			}
			if si.Mode != 0o600 {
				t.Fatalf("sensitive mode = %o, want 600", si.Mode)
			}
		})
	}
}
