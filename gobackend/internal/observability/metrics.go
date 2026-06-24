package observability

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the RED (rate/errors/duration) collectors plus outbound
// dependency timing, registered in a private registry so tests get a clean
// slate and there is no global-registry cross-talk.
type Metrics struct {
	reg          *prometheus.Registry
	httpRequests *prometheus.CounterVec
	httpErrors   *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec
	dbDuration   *prometheus.HistogramVec
	dbErrors     *prometheus.CounterVec
	queueLength  *prometheus.GaugeVec
	publishedGen prometheus.Gauge
}

// NewMetrics builds the collectors and registers them, along with the standard
// Go runtime and process collectors so /metrics keeps exposing them.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests handled, by route, method and status code.",
		}, []string{"handler", "method", "code"}),
		httpErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_request_errors_total",
			Help: "HTTP requests that resulted in a 5xx response.",
		}, []string{"handler", "method", "code"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"handler", "method", "code"}),
		dbDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Outbound dependency call duration in seconds, by subsystem and operation.",
			Buckets: prometheus.DefBuckets,
		}, []string{"subsystem", "operation"}),
		dbErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "db_query_errors_total",
			Help: "Outbound dependency calls that returned an error.",
		}, []string{"subsystem", "operation"}),
		queueLength: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "realtime_queue_length",
			Help: "Current length of a realtime Redis queue (e.g. the attacks ingest list and its in-flight processing list).",
		}, []string{"queue"}),
		publishedGen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "state_published_generation",
			Help: "Latest manifest generation this backend published to the shared store. Node lag = this − edge_sync_applied_generation (SC-007).",
		}),
	}
	reg.MustRegister(
		m.httpRequests, m.httpErrors, m.httpDuration, m.dbDuration, m.dbErrors,
		m.queueLength, m.publishedGen,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// SetPublishedGeneration records the latest manifest generation published to the
// shared store, so the operator can compute per-node convergence lag (SC-007).
func (m *Metrics) SetPublishedGeneration(generation int64) {
	m.publishedGen.Set(float64(generation))
}

// SetQueueLength publishes the current length of a named realtime queue so the
// attacks ingest backlog (and its in-flight processing list) is observable
// before it becomes a problem.
func (m *Metrics) SetQueueLength(queue string, n int64) {
	m.queueLength.WithLabelValues(queue).Set(float64(n))
}

// Handler serves the registry in Prometheus text exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Middleware records RED metrics for every request passing through it. It is
// meant to wrap the whole gateway mux — a single instrumentation point.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		handler := normalizePath(r.URL.Path)
		code := strconv.Itoa(rw.status)
		m.httpRequests.WithLabelValues(handler, r.Method, code).Inc()
		m.httpDuration.WithLabelValues(handler, r.Method, code).Observe(time.Since(start).Seconds())
		if rw.status >= 500 {
			m.httpErrors.WithLabelValues(handler, r.Method, code).Inc()
		}
	})
}

// ObserveDB records the duration and error outcome of an outbound dependency
// call (Postgres, ClickHouse, Redis, …). Call with the start time captured
// before the call: defer m.ObserveDB("clickhouse", "query", time.Now(), err).
func (m *Metrics) ObserveDB(subsystem, operation string, start time.Time, err error) {
	m.dbDuration.WithLabelValues(subsystem, operation).Observe(time.Since(start).Seconds())
	if err != nil {
		m.dbErrors.WithLabelValues(subsystem, operation).Inc()
	}
}

// statusRecorder captures the response status while preserving optional
// interfaces the gateway relies on (Flusher for streaming responses).
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *statusRecorder) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *statusRecorder) Write(b []byte) (int, error) {
	rw.wroteHeader = true
	return rw.ResponseWriter.Write(b)
}

func (rw *statusRecorder) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// normalizePath collapses id-like path segments (numeric or UUID) to ":id" so
// per-request identifiers do not explode metric label cardinality.
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if isIDSegment(s) {
			segs[i] = ":id"
		}
	}
	return strings.Join(segs, "/")
}

func isIDSegment(s string) bool {
	if s == "" {
		return false
	}
	allDigits := true
	for _, r := range s {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return true
	}
	// UUID-ish: long and hyphen-delimited.
	if len(s) >= 32 && strings.Count(s, "-") >= 4 {
		return true
	}
	return false
}
