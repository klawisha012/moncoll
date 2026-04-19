import { useState, useEffect } from "react";
import { api, Metrics, TrafficDataPoint, SecurityEvent } from "../api/client";
import {
  BarChart3,
  ShieldAlert,
  Activity,
  Clock,
  AlertTriangle,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [traffic, setTraffic] = useState<TrafficDataPoint[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      const [m, t, e] = await Promise.all([
        api.getMetrics(),
        api.getTraffic(),
        api.getEvents(),
      ]);
      setMetrics(m);
      setTraffic(t);
      setEvents(e);
    } catch (err) {
      console.error("Failed to load dashboard data:", err);
    } finally {
      setLoading(false);
    }
  }

  function formatNumber(n: number): string {
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
    if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
    return n.toString();
  }

  function getSeverityBadge(severity: string) {
    const map: Record<string, string> = {
      Critical: "badge-critical",
      Warning: "badge-warning",
      Info: "badge-info",
    };
    return map[severity] || "badge-info";
  }

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
        Loading dashboard...
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Dashboard</h1>
          <p>Real-time WAF monitoring and analytics</p>
        </div>
      </div>

      {metrics && (
        <div className="metrics-grid">
          <div className="metric-card">
            <div className="metric-label">
              <BarChart3
                size={14}
                style={{ display: "inline", marginRight: 4 }}
              />
              Total Requests
            </div>
            <div className="metric-value">
              {formatNumber(metrics.total_requests)}
            </div>
            <div
              className={`metric-change ${
                metrics.total_requests_change >= 0 ? "positive" : "negative"
              }`}
            >
              {metrics.total_requests_change >= 0 ? "+" : ""}
              {metrics.total_requests_change}% from last period
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-label">
              <ShieldAlert
                size={14}
                style={{ display: "inline", marginRight: 4 }}
              />
              Blocked Threats
            </div>
            <div className="metric-value">
              {formatNumber(metrics.blocked_threats)}
            </div>
            <div className="metric-change positive">
              WAF actively protecting
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-label">
              <AlertTriangle
                size={14}
                style={{ display: "inline", marginRight: 4 }}
              />
              High Severity
            </div>
            <div className="metric-value">{metrics.high_severity_count}</div>
            <div className="metric-change negative">Requires attention</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">
              <Activity
                size={14}
                style={{ display: "inline", marginRight: 4 }}
              />
              System Health
            </div>
            <div className="metric-value">{metrics.system_health}%</div>
            <div className="metric-change positive">All systems operational</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">
              <Clock
                size={14}
                style={{ display: "inline", marginRight: 4 }}
              />
              Avg Latency
            </div>
            <div className="metric-value">{metrics.avg_latency_ms}ms</div>
            <div className="metric-change positive">Within target</div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h2>Traffic Overview</h2>
        </div>
        <div style={{ height: 300 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={traffic}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="timestamp" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} />
              <Tooltip
                contentStyle={{
                  background: "#1e293b",
                  border: "1px solid #334155",
                  borderRadius: 8,
                  color: "#f1f5f9",
                }}
              />
              <Area
                type="monotone"
                dataKey="clean"
                stackId="1"
                stroke="#22c55e"
                fill="#22c55e"
                fillOpacity={0.3}
                name="Clean"
              />
              <Area
                type="monotone"
                dataKey="malicious"
                stackId="1"
                stroke="#ef4444"
                fill="#ef4444"
                fillOpacity={0.3}
                name="Malicious"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Recent Security Events</h2>
        </div>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>IP</th>
                <th>Country</th>
                <th>Path</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event, i) => (
                <tr key={i}>
                  <td style={{ whiteSpace: "nowrap" }}>{event.timestamp}</td>
                  <td>{event.type}</td>
                  <td>
                    <code>{event.ip}</code>
                  </td>
                  <td>{event.country}</td>
                  <td>
                    <code>{event.path}</code>
                  </td>
                  <td>
                    <span className={`badge ${getSeverityBadge(event.severity)}`}>
                      {event.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Embed full Grafana dashboard for comprehensive view */}
      <div className="card" style={{ marginTop: "2rem" }}>
        <div className="card-header">
          <h2>Full Grafana Dashboard</h2>
        </div>
        <div style={{ height: "800px", overflow: "hidden" }}>
          <iframe
            // Use the proxied Grafana path so the dashboard is served through Nginx
            src="/dashboard/d/waf-nginx-dashboard?orgId=1&refresh=10s"
            style={{ border: "none", width: "100%", height: "100%" }}
            title="Grafana Dashboard"
            sandbox="allow-scripts allow-same-origin"
          />
        </div>
      </div>
    </div>
  );
}
