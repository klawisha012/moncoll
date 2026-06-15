package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTraceHandler_ProducesConnectedSpanChain(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	h := TraceHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A downstream hop creates a child span off the request context.
		_, span := otel.Tracer("test").Start(r.Context(), "db.query")
		span.End()
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/foo", nil))

	spans := sr.Ended()
	if len(spans) < 2 {
		t.Fatalf("expected >=2 spans (server + child), got %d", len(spans))
	}

	var child, server sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.Name() == "db.query" {
			child = s
		} else {
			server = s
		}
	}
	if child == nil || server == nil {
		t.Fatalf("expected both a server span and a db.query child span")
	}
	if child.Parent().SpanID() != server.SpanContext().SpanID() {
		t.Errorf("child span is not parented to the server span (broken chain)")
	}
	if child.SpanContext().TraceID() != server.SpanContext().TraceID() {
		t.Errorf("child and server spans are not in the same trace")
	}
}

func TestInitTracer_DefaultsOffWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")

	prev := otel.GetTracerProvider()
	tp, err := InitTracer(context.Background(), "svc")
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	if err != nil {
		t.Fatalf("InitTracer should not error when off: %v", err)
	}
	_, span := tp.Tracer("t").Start(context.Background(), "s")
	defer span.End()
	if span.IsRecording() {
		t.Error("expected a non-recording span when no OTLP endpoint is configured (off by default)")
	}
}
