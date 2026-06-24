package storage

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPublishManifest_CASConflict pins the correctness floor: a publish built on
// a stale etag loses (ErrConflict), which is what drives the retry in Publisher.
func TestPublishManifest_CASConflict(t *testing.T) {
	ctx := context.Background()
	st := NewLocalFS(t.TempDir(), "default")

	_, e0, err := st.ReadManifest(ctx)
	require.NoError(t, err)

	m := NewManifest("default")
	m.Generation = 1
	e1, err := st.PublishManifest(ctx, m, e0)
	require.NoError(t, err)
	require.NotEqual(t, e0, e1)

	// A second publisher still holding the original etag must lose.
	m2 := NewManifest("default")
	m2.Generation = 1
	_, err = st.PublishManifest(ctx, m2, e0)
	require.ErrorIs(t, err, ErrConflict)
}

// TestPublisher_ConcurrentConverge runs N publishers concurrently against one
// manifest. With at most N−1 conflicts possible (< publishMaxAttempts for N=8),
// every publish converges via retry — no generation skipped, no entry lost.
func TestPublisher_ConcurrentConverge(t *testing.T) {
	ctx := context.Background()
	st := NewLocalFS(t.TempDir(), "default")
	pub := NewPublisher(st)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			oi := ObjectInfo{Key: fmt.Sprintf("state/obj_%d", i), ETag: fmt.Sprintf("etag-%d", i), Size: int64(i)}
			errs[i] = pub.Publish(ctx, ChangeSet{Changed: []ObjectInfo{oi}})
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		require.NoErrorf(t, e, "publish %d", i)
	}
	final, _, err := st.ReadManifest(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(n), final.Generation, "every publish advanced the generation exactly once")
	require.Len(t, final.Entries, n, "no publish was lost to a conflict")
}
