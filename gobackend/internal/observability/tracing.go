package observability

import (
	"context"
	"net/http"
	"os"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// InitTracer configures the global OpenTelemetry tracer provider and W3C
// propagator. Tracing is OFF by default: only when an OTLP endpoint is set
// (OTEL_EXPORTER_OTLP_TRACES_ENDPOINT or OTEL_EXPORTER_OTLP_ENDPOINT) is a
// batch exporter attached. Without an endpoint the provider never samples, so
// spans cost almost nothing and there is no mandatory external dependency.
func InitTracer(ctx context.Context, serviceName string) (*sdktrace.TracerProvider, error) {
	endpoint := firstNonEmpty(
		os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
	)

	res, err := resource.New(ctx, resource.WithAttributes(
		attribute.String("service.name", serviceName),
	))
	if err != nil {
		res = resource.Default()
	}

	opts := []sdktrace.TracerProviderOption{sdktrace.WithResource(res)}
	if endpoint == "" {
		// Off: spans are created but never recorded or exported.
		opts = append(opts, sdktrace.WithSampler(sdktrace.NeverSample()))
	} else {
		exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
		if err != nil {
			return nil, err
		}
		opts = append(opts,
			sdktrace.WithBatcher(exp),
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
		)
	}

	tp := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	return tp, nil
}

// TraceHandler wraps an HTTP handler with otelhttp server instrumentation: a
// server span per request (named by method + normalized route) plus trace
// context extraction/injection so spans connect across hops.
func TraceHandler(next http.Handler) http.Handler {
	return otelhttp.NewHandler(next, "waf.http",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + normalizePath(r.URL.Path)
		}),
	)
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
