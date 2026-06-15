package chdash_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zwarder/waf/gobackend/internal/chdash"
)

// blockingExec counts QueryCached invocations and holds the first one open on
// `release` so concurrent callers pile up behind the singleflight leader.
type blockingExec struct {
	calls   int32
	started chan struct{}
	release chan struct{}
	once    sync.Once
	rows    [][]interface{}
}

func (e *blockingExec) QueryCached(_ context.Context, _ string) ([][]interface{}, error) {
	atomic.AddInt32(&e.calls, 1)
	e.once.Do(func() { close(e.started) })
	<-e.release
	return e.rows, nil
}

func (e *blockingExec) Query(_ context.Context, _ string) ([][]interface{}, error) {
	atomic.AddInt32(&e.calls, 1)
	return e.rows, nil
}

// TestQueryCached_CoalescesConcurrentMisses asserts that N concurrent
// QueryCached calls for the same key on a cache miss execute the underlying
// query exactly once (stampede protection).
func TestQueryCached_CoalescesConcurrentMisses(t *testing.T) {
	ex := &blockingExec{
		started: make(chan struct{}),
		release: make(chan struct{}),
		rows:    [][]interface{}{{int64(42)}},
	}
	c := chdash.NewClientWithExecutor(ex)

	const n = 50
	var wg sync.WaitGroup
	results := make([][][]interface{}, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, _ := c.QueryCached(context.Background(), "SELECT count() FROM logs.x")
			results[i] = r
		}(i)
	}

	// Wait until the leader is in-flight, then give stragglers time to pile up
	// behind the singleflight key before releasing the leader.
	<-ex.started
	time.Sleep(200 * time.Millisecond)
	close(ex.release)
	wg.Wait()

	if got := atomic.LoadInt32(&ex.calls); got != 1 {
		t.Fatalf("expected exactly 1 underlying execution, got %d", got)
	}
	// Every caller must still receive the shared result.
	for i, r := range results {
		if len(r) != 1 || len(r[0]) != 1 {
			t.Fatalf("caller %d got unexpected result %v", i, r)
		}
	}
}

// TestQueryCached_SequentialCallsEachExecute confirms coalescing is in-flight
// only: once the leader returns, a later call runs again (no result caching by
// singleflight itself).
func TestQueryCached_SequentialCallsEachExecute(t *testing.T) {
	ex := &blockingExec{
		started: make(chan struct{}),
		release: make(chan struct{}),
		rows:    [][]interface{}{{int64(1)}},
	}
	close(ex.release) // never block
	c := chdash.NewClientWithExecutor(ex)

	for i := 0; i < 3; i++ {
		if _, err := c.QueryCached(context.Background(), "SELECT 1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(&ex.calls); got != 3 {
		t.Fatalf("expected 3 sequential executions, got %d", got)
	}
}
