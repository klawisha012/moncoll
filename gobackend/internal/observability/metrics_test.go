package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// scrape returns the text exposition of a Metrics registry.
func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics handler returned %d", rec.Code)
	}
	return rec.Body.String()
}

func TestMetricsMiddleware_RecordsREDSeries(t *testing.T) {
	m := NewMetrics()
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/bar" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	for _, p := range []string{"/v1/foo", "/v1/bar"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
	}

	body := scrape(t, m)
	// rate: total requests counter for both handlers
	if !strings.Contains(body, `http_requests_total{`) ||
		!strings.Contains(body, `handler="/v1/foo"`) ||
		!strings.Contains(body, `handler="/v1/bar"`) {
		t.Errorf("missing http_requests_total series:\n%s", body)
	}
	// errors: only the 500 path
	if !strings.Contains(body, `http_request_errors_total{`) ||
		!strings.Contains(body, `code="500"`) {
		t.Errorf("missing http_request_errors_total for 500:\n%s", body)
	}
	// duration histogram
	if !strings.Contains(body, `http_request_duration_seconds_bucket{`) {
		t.Errorf("missing http_request_duration_seconds histogram:\n%s", body)
	}
}

func TestMetricsMiddleware_NormalizesIDPaths(t *testing.T) {
	m := NewMetrics()
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Numeric id and a UUID should both collapse to :id, keeping cardinality bounded.
	for _, p := range []string{
		"/v1/connections/8/tests",
		"/v1/connections/123e4567-e89b-12d3-a456-426614174000",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
	}

	body := scrape(t, m)
	if !strings.Contains(body, `handler="/v1/connections/:id/tests"`) {
		t.Errorf("numeric id segment not normalized:\n%s", body)
	}
	if !strings.Contains(body, `handler="/v1/connections/:id"`) {
		t.Errorf("uuid segment not normalized:\n%s", body)
	}
	// The raw id must NOT appear as a label.
	if strings.Contains(body, `handler="/v1/connections/8/tests"`) {
		t.Errorf("raw numeric id leaked into label:\n%s", body)
	}
}

func TestObserveDB_RecordsDurationAndErrors(t *testing.T) {
	m := NewMetrics()
	start := time.Now().Add(-5 * time.Millisecond)
	m.ObserveDB("clickhouse", "query", start, nil)
	m.ObserveDB("postgres", "select", start, http.ErrAbortHandler)

	body := scrape(t, m)
	if !strings.Contains(body, `db_query_duration_seconds_bucket{`) ||
		!strings.Contains(body, `subsystem="clickhouse"`) {
		t.Errorf("missing db_query_duration_seconds for clickhouse:\n%s", body)
	}
	if !strings.Contains(body, `db_query_errors_total{`) ||
		!strings.Contains(body, `subsystem="postgres"`) {
		t.Errorf("missing db_query_errors_total for failed postgres call:\n%s", body)
	}
}
