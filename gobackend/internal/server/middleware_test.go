package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// TestWithRequestTimeout_PropagatesDeadlineAndUnblocks asserts that a handler
// whose downstream I/O blocks on the context is released with
// context.DeadlineExceeded once the budget elapses, rather than hanging — and
// that it does not leak a goroutine.
func TestWithRequestTimeout_PropagatesDeadlineAndUnblocks(t *testing.T) {
	var gotErr error
	h := withRequestTimeout(40*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a context-aware dependency call that blocks indefinitely.
		<-r.Context().Done()
		gotErr = r.Context().Err()
		w.WriteHeader(http.StatusGatewayTimeout)
	}))

	g0 := runtime.NumGoroutine()
	start := time.Now()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/x", nil))
	elapsed := time.Since(start)

	if !errors.Is(gotErr, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", gotErr)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("handler hung for %v; deadline should have released it near 40ms", elapsed)
	}
	// The handler ran synchronously in the caller's goroutine and returned, so
	// nothing should be left running.
	time.Sleep(20 * time.Millisecond)
	if g1 := runtime.NumGoroutine(); g1 > g0+2 {
		t.Errorf("possible goroutine leak: before=%d after=%d", g0, g1)
	}
}

// TestWithRequestTimeout_DisabledPassthrough asserts a non-positive duration is
// a transparent pass-through that sets no deadline.
func TestWithRequestTimeout_DisabledPassthrough(t *testing.T) {
	called := false
	h := withRequestTimeout(0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := r.Context().Deadline(); ok {
			t.Error("no deadline should be set when the middleware is disabled")
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Error("handler was not called")
	}
}
