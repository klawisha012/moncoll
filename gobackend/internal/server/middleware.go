package server

import (
	"context"
	"net/http"
	"time"
)

// withRequestTimeout sets an end-to-end deadline on the request context so every
// downstream hop (gRPC, Postgres, ClickHouse, Redis, Centrifugo, outbound HTTP)
// inherits the same budget. Downstream I/O is context-aware, so on expiry calls
// return context.DeadlineExceeded (surfaced as a 504 / gRPC DeadlineExceeded)
// instead of hanging and accumulating goroutines. The deadline is set once here
// and never reset deeper in the stack. A non-positive duration disables it.
func withRequestTimeout(d time.Duration, next http.Handler) http.Handler {
	if d <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
