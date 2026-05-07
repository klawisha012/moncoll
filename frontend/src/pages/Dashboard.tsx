export default function Dashboard() {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Dashboard</h1>
          <p>Real-time WAF monitoring and analytics powered by Grafana</p>
        </div>
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
          <div className="metric-value">—</div>
          <div className="metric-change up">Live data via Grafana</div>
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
          <div className="metric-value">—</div>
          <div className="metric-change down">Monitored by WAF</div>
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
          <div className="metric-value">—</div>
          <div className="metric-change up">Performance metrics</div>
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
          <div className="metric-value">—</div>
          <div className="metric-change up">CRS Protection</div>
        </div>
      </div>

      {/* Embedded Grafana dashboard */}
      <div
        className="card"
        style={{ padding: "8px", overflow: "hidden", height: "calc(100vh - 320px)" }}
      >
        <iframe
          src="/grafana/d/waf-nginx-dashboard?orgId=1&refresh=10s&theme=dark"
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
