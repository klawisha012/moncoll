import { useEffect, useState, useMemo } from "react";
import type { Metrics, TrafficDataPoint, ThreatOrigin, SecurityEvent, GeoipMapPoint } from "../api/client";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";

type Tab = "grafana" | "native";
type TimeUnit = "minutes" | "hours" | "days";

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

const UNITS: { value: TimeUnit; label: string; multiplier: number }[] = [
  { value: "minutes", label: "Minutes", multiplier: 1 / 60 },
  { value: "hours", label: "Hours", multiplier: 1 },
  { value: "days", label: "Days", multiplier: 24 },
];

// ─── Traffic Chart (SVG bar chart) ───────────────────────────────
function TrafficChart({ data, loading }: { data: TrafficDataPoint[] | null; loading: boolean }) {
  if (loading) {
    return (
      <div className="loading-spinner" style={{ padding: "40px 0", fontSize: "13px" }}>
        Loading traffic data…
      </div>
    );
  }
  if (!data || data.length === 0) {
    return <div style={{ padding: "40px 0", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>No traffic data available</div>;
  }

  const padding = { top: 10, right: 10, bottom: 30, left: 50 };
  const width = 800;
  const height = 250;
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const maxVal = Math.max(...data.map((d) => d.clean + d.malicious), 1);
  const barW = Math.max(2, Math.floor(chartW / data.length) - 2);
  const stepX = chartW / data.length;

  // Y-axis ticks
  const yTicks = 4;
  const tickVals: number[] = [];
  for (let i = 0; i <= yTicks; i++) {
    tickVals.push(Math.round((maxVal / yTicks) * i));
  }

  return (
    <svg viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height: "auto", display: "block" }}>
      {/* Y grid lines + labels */}
      {tickVals.map((v) => {
        const y = padding.top + chartH - (v / maxVal) * chartH;
        return (
          <g key={v}>
            <line x1={padding.left} y1={y} x2={width - padding.right} y2={y} stroke="var(--border-subtle)" strokeWidth="0.5" />
            <text x={padding.left - 8} y={y + 4} textAnchor="end" fill="var(--text-muted)" fontSize="10">
              {formatNumber(v)}
            </text>
          </g>
        );
      })}

      {/* Bars */}
      {data.map((d, i) => {
        const x = padding.left + i * stepX;
        const cleanH = (d.clean / maxVal) * chartH;
        const malH = (d.malicious / maxVal) * chartH;
        return (
          <g key={d.timestamp}>
            <rect
              x={x + 1}
              y={padding.top + chartH - cleanH - malH}
              width={barW}
              height={cleanH}
              fill="var(--accent-1)"
              opacity={0.85}
              rx="1"
            />
            <rect
              x={x + 1}
              y={padding.top + chartH - malH}
              width={barW}
              height={malH}
              fill="var(--danger)"
              opacity={0.85}
              rx="1"
            />
            {/* X label — show every Nth */}
            {i % Math.max(1, Math.floor(data.length / 8)) === 0 && (
              <text
                x={x + barW / 2}
                y={height - 6}
                textAnchor="middle"
                fill="var(--text-muted)"
                fontSize="9"
              >
                {new Date(d.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
              </text>
            )}
          </g>
        );
      })}

      {/* Legend */}
      <rect x={padding.left} y={4} width="10" height="10" rx="2" fill="var(--accent-1)" opacity={0.85} />
      <text x={padding.left + 14} y={13} fill="var(--text-secondary)" fontSize="10">Clean</text>
      <rect x={padding.left + 50} y={4} width="10" height="10" rx="2" fill="var(--danger)" opacity={0.85} />
      <text x={padding.left + 64} y={13} fill="var(--text-secondary)" fontSize="10">Malicious</text>
    </svg>
  );
}

// ─── Threat Origins Chart (horizontal bars) ──────────────────────
function ThreatOriginsChart({ data, loading }: { data: ThreatOrigin[] | null; loading: boolean }) {
  if (loading) {
    return (
      <div className="loading-spinner" style={{ padding: "40px 0", fontSize: "13px" }}>
        Loading threat origins…
      </div>
    );
  }
  if (!data || data.length === 0) {
    return <div style={{ padding: "40px 0", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>No threat data available</div>;
  }

  const barH = 22;
  const gap = 8;
  const height = data.length * (barH + gap) + 16;
  const maxPct = Math.max(...data.map((d) => d.blocks_percent), 1);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: `${gap}px` }}>
      {data.map((d) => (
        <div key={d.country_code} style={{ display: "flex", alignItems: "center", gap: "12px", height: `${barH}px` }}>
          <span style={{ width: "36px", fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)", textAlign: "right", flexShrink: 0 }}>
            {d.country_code}
          </span>
          <div
            style={{
              flex: 1,
              height: "100%",
              background: "var(--bg-elevated)",
              borderRadius: "3px",
              overflow: "hidden",
              position: "relative",
            }}
          >
            <div
              style={{
                height: "100%",
                width: `${(d.blocks_percent / maxPct) * 100}%`,
                background: "linear-gradient(90deg, var(--danger), var(--accent-2))",
                borderRadius: "3px",
                transition: "width 0.5s ease",
                display: "flex",
                alignItems: "center",
                paddingLeft: "8px",
                minWidth: "fit-content",
              }}
            >
              <span style={{ fontSize: "10px", fontWeight: 600, color: "#fff", whiteSpace: "nowrap" }}>
                {d.blocks_percent}%
              </span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Security Events Table ───────────────────────────────────────
function EventsTable({ data, loading }: { data: SecurityEvent[] | null; loading: boolean }) {
  if (loading) {
    return (
      <div className="loading-spinner" style={{ padding: "40px 0", fontSize: "13px" }}>
        Loading events…
      </div>
    );
  }
  if (!data || data.length === 0) {
    return <div style={{ padding: "40px 0", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>No recent security events</div>;
  }

  const severityColors: Record<string, string> = {
    critical: "var(--danger)",
    high: "var(--danger)",
    medium: "var(--warning)",
    low: "var(--info)",
    info: "var(--text-muted)",
  };

  return (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>IP</th>
            <th>Path</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {data.map((e, i) => (
            <tr key={i}>
              <td style={{ whiteSpace: "nowrap", fontSize: "11px" }}>
                {new Date(e.timestamp).toLocaleTimeString()}
              </td>
              <td style={{ fontSize: "12px", fontFamily: "monospace" }}>{e.type}</td>
              <td style={{ fontSize: "12px", fontFamily: "monospace" }}>{e.ip}</td>
              <td style={{ fontSize: "12px", fontFamily: "monospace", maxWidth: "250px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {e.path}
              </td>
              <td>
                <span
                  className="badge"
                  style={{
                    background: `${severityColors[e.severity] || "var(--text-muted)"}22`,
                    color: severityColors[e.severity] || "var(--text-muted)",
                    fontSize: "10px",
                  }}
                >
                  {e.severity}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── GeoIP World Map (Leaflet) ──────────────────────────────
function GeoipMap({ data, loading }: { data: GeoipMapPoint[] | null; loading: boolean }) {
  if (loading) {
    return (
      <div className="loading-spinner" style={{ padding: "40px 0", fontSize: "13px" }}>
        Loading geoip data…
      </div>
    );
  }
  if (!data || data.length === 0) {
    return <div style={{ padding: "40px 0", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>No geoip data available</div>;
  }

  const maxHits = Math.max(...data.map((d) => d.hits), 1);
  const minHits = Math.min(...data.map((d) => d.hits), 1);

  function dotRadius(hits: number) {
    const minR = 4;
    const maxR = 18;
    if (maxHits === minHits) return (minR + maxR) / 2;
    return minR + ((hits - minHits) / (maxHits - minHits)) * (maxR - minR);
  }

  function dotColor(hits: number) {
    const ratio = maxHits === minHits ? 0.5 : (hits - minHits) / (maxHits - minHits);
    if (ratio < 0.33) return "#f43f5e";
    if (ratio < 0.66) return "#f59e0b";
    return "#10b981";
  }

  return (
    <div className="world-map-container" style={{ height: "420px", width: "100%", borderRadius: "var(--radius-md)", overflow: "hidden" }}>
      <MapContainer
        center={[25, 0]}
        zoom={2}
        minZoom={2}
        maxZoom={6}
        scrollWheelZoom={true}
        dragging={true}
        touchZoom={true}
        doubleClickZoom={true}
        zoomControl={false}
        keyboard={false}
        worldCopyJump={true}
        maxBounds={[[-90, -180], [90, 180]]}
        maxBoundsViscosity={0.5}
        style={{ height: "100%", width: "100%", background: "#0b0f1e" }}
        attributionControl={false}
      >
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png"
          noWrap={false}
        />
        {data.map((d, i) => (
          <CircleMarker
            key={i}
            center={[d.latitude, d.longitude]}
            radius={dotRadius(d.hits)}
            pathOptions={{
              fillColor: dotColor(d.hits),
              color: dotColor(d.hits),
              weight: 1.5,
              opacity: 0.9,
              fillOpacity: 0.5,
            }}
          >
            <Popup>
              <div style={{ fontSize: "12px", color: "#111" }}>
                <strong>{d.city_name || d.country_code}</strong>
                <br />
                {d.hits.toLocaleString()} requests
                {d.country_code && d.city_name ? <><br />{d.country_code}</> : null}
              </div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>

      {/* Legend */}
      <div
        className="map-legend"
        style={{
          position: "absolute",
          bottom: "12px",
          left: "12px",
          zIndex: 1000,
          background: "rgba(11,15,30,0.85)",
          backdropFilter: "blur(6px)",
          borderRadius: "var(--radius-sm)",
          padding: "8px 12px",
          display: "flex",
          alignItems: "center",
          gap: "14px",
          fontSize: "11px",
          color: "var(--text-secondary)",
          border: "1px solid var(--border-subtle)",
        }}
      >
        <div className="map-legend-item">
          <div className="map-legend-dot" style={{ background: "#f43f5e" }} />
          High
        </div>
        <div className="map-legend-item">
          <div className="map-legend-dot" style={{ background: "#f59e0b" }} />
          Medium
        </div>
        <div className="map-legend-item">
          <div className="map-legend-dot" style={{ background: "#10b981" }} />
          Low
        </div>
      </div>
    </div>
  );
}

// ─── Main Dashboard Component ────────────────────────────────────
export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<Tab>("grafana");
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Time range state for native panels
  const [timeValue, setTimeValue] = useState<number>(24);
  const [timeUnit, setTimeUnit] = useState<TimeUnit>("hours");

  // Native panel extra data
  const [trafficData, setTrafficData] = useState<TrafficDataPoint[] | null>(null);
  const [trafficLoading, setTrafficLoading] = useState(false);
  const [threatOrigins, setThreatOrigins] = useState<ThreatOrigin[] | null>(null);
  const [threatLoading, setThreatLoading] = useState(false);
  const [events, setEvents] = useState<SecurityEvent[] | null>(null);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [geoipData, setGeoipData] = useState<GeoipMapPoint[] | null>(null);
  const [geoipLoading, setGeoipLoading] = useState(false);

  // Compute total hours from value + unit — round to integer for API
  const unitMultiplier = UNITS.find((u) => u.value === timeUnit)?.multiplier ?? 1;
  const selectedHours = Math.max(1, Math.round(timeValue * unitMultiplier));

  useEffect(() => {
    // Only fetch when on native tab
    if (activeTab !== "native") return;

    let cancelled = false;

    const fetchAll = async (hours: number) => {
      // Metrics
      try {
        setMetricsLoading(true);
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 8_000);
        const res = await fetch(`/api/dashboard/metrics?hours=${hours}`, { signal: ctrl.signal });
        clearTimeout(tid);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: Metrics = await res.json();
        if (!cancelled) { setMetrics(data); setError(null); setMetricsLoading(false); }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load metrics");
          setMetricsLoading(false);
        }
      }

      // Traffic
      try {
        setTrafficLoading(true);
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 8_000);
        const res = await fetch(`/api/dashboard/traffic?hours=${hours}`, { signal: ctrl.signal });
        clearTimeout(tid);
        if (res.ok) {
          const data: TrafficDataPoint[] = await res.json();
          if (!cancelled) { setTrafficData(data); setTrafficLoading(false); }
        } else {
          if (!cancelled) setTrafficLoading(false);
        }
      } catch {
        if (!cancelled) setTrafficLoading(false);
      }

      // Threat origins
      try {
        setThreatLoading(true);
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 8_000);
        const res = await fetch("/api/dashboard/threat-origins", { signal: ctrl.signal });
        clearTimeout(tid);
        if (res.ok) {
          const data: ThreatOrigin[] = await res.json();
          if (!cancelled) { setThreatOrigins(data); setThreatLoading(false); }
        } else {
          if (!cancelled) setThreatLoading(false);
        }
      } catch {
        if (!cancelled) setThreatLoading(false);
      }

      // Events
      try {
        setEventsLoading(true);
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 8_000);
        const res = await fetch("/api/dashboard/events?limit=20&severity=all", { signal: ctrl.signal });
        clearTimeout(tid);
        if (res.ok) {
          const data: SecurityEvent[] = await res.json();
          if (!cancelled) { setEvents(data); setEventsLoading(false); }
        } else {
          if (!cancelled) setEventsLoading(false);
        }
      } catch {
        if (!cancelled) setEventsLoading(false);
      }

      // GeoIP Map
      try {
        setGeoipLoading(true);
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 8_000);
        const res = await fetch(`/api/dashboard/geoip-map?hours=${hours}`, { signal: ctrl.signal });
        clearTimeout(tid);
        if (res.ok) {
          const data: GeoipMapPoint[] = await res.json();
          if (!cancelled) { setGeoipData(data); setGeoipLoading(false); }
        } else {
          if (!cancelled) setGeoipLoading(false);
        }
      } catch {
        if (!cancelled) setGeoipLoading(false);
      }
    };

    fetchAll(selectedHours);
    const interval = setInterval(() => fetchAll(selectedHours), 15_000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [activeTab, selectedHours]);

  const totalRequests = metrics?.total_requests ?? null;
  const blockedThreats = metrics?.blocked_threats ?? null;
  const avgLatency = metrics?.avg_latency_ms ?? null;
  const activeRules = metrics?.active_rules ?? null;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Dashboard</h1>
          <p>
            {activeTab === "grafana"
              ? "Real-time WAF monitoring and analytics powered by Grafana"
              : "Native WAF metrics and statistics"}
          </p>
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

      {/* Tab switcher */}
      <div
        style={{
          display: "flex",
          gap: 0,
          marginBottom: "20px",
          borderBottom: "2px solid var(--border-color, #2a2a2a)",
        }}
      >
        <button
          onClick={() => setActiveTab("grafana")}
          style={{
            padding: "10px 24px",
            fontSize: "14px",
            fontWeight: 500,
            border: "none",
            background: "transparent",
            color: activeTab === "grafana" ? "var(--accent, #6366f1)" : "var(--text-secondary, #888)",
            cursor: "pointer",
            borderBottom: activeTab === "grafana" ? "2px solid var(--accent, #6366f1)" : "2px solid transparent",
            marginBottom: "-2px",
            transition: "color 0.2s, border-color 0.2s",
          }}
        >
          Grafana Panels
        </button>
        <button
          onClick={() => setActiveTab("native")}
          style={{
            padding: "10px 24px",
            fontSize: "14px",
            fontWeight: 500,
            border: "none",
            background: "transparent",
            color: activeTab === "native" ? "var(--accent, #6366f1)" : "var(--text-secondary, #888)",
            cursor: "pointer",
            borderBottom: activeTab === "native" ? "2px solid var(--accent, #6366f1)" : "2px solid transparent",
            marginBottom: "-2px",
            transition: "color 0.2s, border-color 0.2s",
          }}
        >
          Native Panels
        </button>
      </div>

      {/* Native Panels content */}
      {activeTab === "native" && (
        <>
          {/* Time range selector */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              marginBottom: "16px",
              padding: "10px 16px",
              background: "var(--card-bg, #1a1a2e)",
              borderRadius: "var(--radius-md, 8px)",
              border: "1px solid var(--border-color, #2a2a2a)",
              flexWrap: "wrap",
            }}
          >
            <span style={{ fontSize: "13px", color: "var(--text-secondary, #888)", fontWeight: 500 }}>
              Time Range:
            </span>
            <input
              type="number"
              min={1}
              max={8760}
              value={timeValue}
              onChange={(e) => {
                const v = parseInt(e.target.value, 10);
                if (!isNaN(v) && v >= 1 && v <= 8760) setTimeValue(v);
              }}
              style={{
                width: "80px",
                padding: "6px 10px",
                fontSize: "13px",
                border: "1px solid var(--border-color, #2a2a2a)",
                borderRadius: "var(--radius-sm, 6px)",
                background: "var(--input-bg, #0d0d1a)",
                color: "var(--text-primary, #e0e0e0)",
                outline: "none",
              }}
            />
            <select
              value={timeUnit}
              onChange={(e) => setTimeUnit(e.target.value as TimeUnit)}
              style={{
                padding: "6px 10px",
                fontSize: "13px",
                border: "1px solid var(--border-color, #2a2a2a)",
                borderRadius: "var(--radius-sm, 6px)",
                background: "var(--input-bg, #0d0d1a)",
                color: "var(--text-primary, #e0e0e0)",
                outline: "none",
                cursor: "pointer",
              }}
            >
              {UNITS.map((unit) => (
                <option key={unit.value} value={unit.value}>
                  {unit.label}
                </option>
              ))}
            </select>
            <span style={{ fontSize: "12px", color: "var(--text-secondary, #666)" }}>
              (stats for the last {timeValue} {timeUnit === "minutes" ? "min" : timeUnit === "hours" ? "hr" : "day"}
              {timeValue !== 1 ? "s" : ""})
            </span>
          </div>

          {/* Stat cards row */}
          <div className="metrics-grid">
            <div className="metric-card">
              <div className="metric-icon indigo">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M3 3v18h18" /><path d="m19 9-5 5-4-4-3 3" />
                </svg>
              </div>
              <div className="metric-label">Total Requests</div>
              <div className="metric-value">
                {metricsLoading ? "…" : totalRequests !== null ? formatNumber(totalRequests) : "—"}
              </div>
              <div className={`metric-change ${(metrics?.total_requests_change ?? 0) >= 0 ? "up" : "down"}`}>
                {metricsLoading ? "Loading…" : metrics ? `${metrics.total_requests_change >= 0 ? "+" : ""}${metrics.total_requests_change}% vs previous` : "—"}
              </div>
            </div>

            <div className="metric-card">
              <div className="metric-icon rose">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
                </svg>
              </div>
              <div className="metric-label">Blocked Threats</div>
              <div className="metric-value">
                {metricsLoading ? "…" : blockedThreats !== null ? formatNumber(blockedThreats) : "—"}
              </div>
              <div className="metric-change down">
                {metricsLoading ? "Loading…" : metrics ? `${metrics.high_severity_count} high severity` : "Monitored by WAF"}
              </div>
            </div>

            <div className="metric-card">
              <div className="metric-icon violet">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10" /><path d="M12 6v6l4 2" />
                </svg>
              </div>
              <div className="metric-label">Avg Latency</div>
              <div className="metric-value">
                {metricsLoading ? "…" : avgLatency !== null ? `${avgLatency.toFixed(1)} ms` : "—"}
              </div>
              <div className="metric-change up">
                {metricsLoading ? "Loading…" : metrics ? `Health ${metrics.system_health}%` : "Performance metrics"}
              </div>
            </div>

            <div className="metric-card">
              <div className="metric-icon emerald">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect width="18" height="11" x="3" y="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              </div>
              <div className="metric-label">Active Rules</div>
              <div className="metric-value">
                {metricsLoading ? "…" : activeRules !== null ? activeRules.toLocaleString() : "—"}
              </div>
              <div className="metric-change up">{metricsLoading ? "Loading…" : "CRS Protection"}</div>
            </div>
          </div>

          {/* Traffic chart */}
          <div className="card" style={{ marginBottom: "16px" }}>
            <div className="card-header">
              <h2>Traffic Overview (Clean vs Malicious)</h2>
            </div>
            <TrafficChart data={trafficData} loading={trafficLoading} />
          </div>

          {/* Two-column: Threat Origins + Security Events */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
            <div className="card">
              <div className="card-header">
                <h2>Threat Origins by Country</h2>
              </div>
              <ThreatOriginsChart data={threatOrigins} loading={threatLoading} />
            </div>
            <div className="card">
              <div className="card-header">
                <h2>Recent Security Events</h2>
              </div>
              <EventsTable data={events} loading={eventsLoading} />
            </div>
          </div>

          {/* GeoIP World Map */}
          <div className="card" style={{ marginBottom: "16px" }}>
            <div className="card-header">
              <h2>GeoIP Attack Origins Map</h2>
            </div>
            <GeoipMap data={geoipData} loading={geoipLoading} />
          </div>
        </>
      )}

      {/* Grafana Panels content */}
      {activeTab === "grafana" && (
        <div className="card" style={{ padding: "8px", overflow: "hidden", height: "calc(100vh - 260px)" }}>
          <iframe
            src="/grafana/d/waf-nginx-dashboard/waf-and-nginx-security-dashboard-2?orgId=1&refresh=10s&theme=dark&kiosk=tv"
            style={{ border: "none", width: "100%", height: "100%", borderRadius: "var(--radius-md)" }}
            title="Grafana Dashboard"
            sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
          />
        </div>
      )}
    </div>
  );
}
