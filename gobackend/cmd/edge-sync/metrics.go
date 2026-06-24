package main

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// edgeMetrics are the per-node convergence signals the operator watches
// (contracts/sync-protocol.md). Node lag = state_published_generation (backend) −
// edge_sync_applied_generation (here).
type edgeMetrics struct {
	reg         *prometheus.Registry
	appliedGen  prometheus.Gauge
	lagSeconds  prometheus.Gauge
	errorsTotal prometheus.Counter
	lastSuccess prometheus.Gauge

	lastSuccessAt time.Time
}

func newEdgeMetrics() *edgeMetrics {
	reg := prometheus.NewRegistry()
	m := &edgeMetrics{
		reg: reg,
		appliedGen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "edge_sync_applied_generation",
			Help: "Manifest generation successfully materialised and reloaded on this node.",
		}),
		lagSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "edge_sync_lag_seconds",
			Help: "Seconds since the last successful generation apply (now − last_success).",
		}),
		errorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "edge_sync_errors_total",
			Help: "Total read/validate/reload failures (node stayed on last-known-good).",
		}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "edge_sync_last_success_timestamp",
			Help: "Unix time of the last successful generation apply.",
		}),
	}
	reg.MustRegister(
		m.appliedGen, m.lagSeconds, m.errorsTotal, m.lastSuccess,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// applied records a successful generation apply: bumps the gauge, resets lag.
func (m *edgeMetrics) applied(gen int64, now time.Time) {
	m.appliedGen.Set(float64(gen))
	m.lastSuccessAt = now
	m.lastSuccess.Set(float64(now.Unix()))
	m.lagSeconds.Set(0)
}

// refreshLag updates the lag gauge between applies so a stalled node shows a
// growing lag even when no new generation arrives.
func (m *edgeMetrics) refreshLag(now time.Time) {
	if !m.lastSuccessAt.IsZero() {
		m.lagSeconds.Set(now.Sub(m.lastSuccessAt).Seconds())
	}
}

func (m *edgeMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
