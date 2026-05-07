import { useEffect, useState } from "react";
import { Metrics } from "../api/client";

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const fetchMetrics = async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8_000);

        const response = await fetch("/api/dashboard/metrics", {
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const data: Metrics = await response.json();

        if (!cancelled) {
          setMetrics(data);
          setError(null);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          if (err instanceof DOMException && err.name === "AbortError") {
            setError("Metrics endpoint is not reachable (ClickHouse may be offline)");
          } else {
            setError(err instanceof Error ? err.message : "Failed to load metrics");
          }
          setLoading(false);
        }
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 10_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const totalRequests = metrics?.total_requests ?? null;
  const blockedThreats = metrics?.blocked_threats ?? null;
  const avgLatency = metrics?.avg_latency_ms ?? null;
  const activeRules = metrics?.active_rules ?? null;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Dashboard</h1>
          <p>Real-time WAF monitoring and analytics powered by Grafana</p>
        </div>
        {error && (
          <div
            style={{
              padding: "8px 16px",
              background: "var(--danger-bg, rgba(239, 68, 68, 0.1))",
              borderRadius: "var(--radius-md, 8px)",
              color: "var(--danger, #ef4444)",
              fontSize: "13px",
            }}
          >
            {error}
          </div>
        )}
      </div>

      {/* Stat cards row */}
      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-icon indigo">
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M3 3v18h18" />
              <path d="m19 9-5 5-4-4-3 3" />
            </svg>
          </div>
          <div className="metric-label">Total Requests</div>
          <div className="metric-value">
            {loading ? "…" : totalRequests !== null ? formatNumber(totalRequests) : "—"}
          </div>
          <div className={`metric-change ${(metrics?.total_requests_change ?? 0) >= 0 ? "up" : "down"}`}>
            {loading
              ? "Loading…"
              : metrics
                ? `${metrics.total_requests_change >= 0 ? "+" : ""}${metrics.total_requests_change}% vs 24h ago`
                : "Live data via Grafana"}
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon rose">
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
            </svg>
          </div>
          <div className="metric-label">Blocked Threats</div>
          <div className="metric-value">
            {loading ? "…" : blockedThreats !== null ? formatNumber(blockedThreats) : "—"}
          </div>
          <div className="metric-change down">
            {loading
              ? "Loading…"
              : metrics
                ? `${metrics.high_severity_count} high severity`
                : "Monitored by WAF"}
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon violet">
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="12" cy="12" r="10" />
              <path d="M12 6v6l4 2" />
            </svg>
          </div>
          <div className="metric-label">Avg Latency</div>
          <div className="metric-value">
            {loading ? "…" : avgLatency !== null ? `${avgLatency.toFixed(1)} ms` : "—"}
          </div>
          <div className="metric-change up">
            {loading
              ? "Loading…"
              : metrics
                ? `Health ${metrics.system_health}%`
                : "Performance metrics"}
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon emerald">
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>
          <div className="metric-label">Active Rules</div>
          <div className="metric-value">
            {loading ? "…" : activeRules !== null ? activeRules.toLocaleString() : "—"}
          </div>
          <div className="metric-change up">
            {loading
              ? "Loading…"
              : metrics
                ? "CRS Protection"
                : "CRS Protection"}
          </div>
        </div>
      </div>

      {/* Embedded Grafana dashboard */}
      <div
        className="card"
        style={{ padding: "8px", overflow: "hidden", height: "calc(100vh - 320px)" }}
      >
        <iframe
          src="/grafana/d/waf-nginx-dashboard?orgId=1&refresh=10s&theme=dark&kiosk=tv"
          style={{
            border: "none",
            width: "100%",
            height: "100%",
            borderRadius: "var(--radius-md)",
          }}
          title="Grafana Dashboard"
          sandbox="allow-scripts allow-same-origin"
        />
      </div>
    </div>
  );
}
