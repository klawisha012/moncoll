import { useEffect, useState, useMemo, useRef, useCallback } from "react";
import {
  Cog,
  BarChart3,
  Globe,
  ShieldAlert,
  Map,
  Gauge,
  ShieldOff,
  Clock,
  ScrollText,
  Activity,
  AlertTriangle,
  PieChart,
  Users,
  Tag,
  Link,
  FileCode,
  TrendingUp,
  HardDrive,
  Bot,
  Zap,
  Flag,
} from "lucide-react";
import { api } from "../api/client";
import type {
  Connection,
  Metrics,
  TrafficDataPoint,
  ThreatOrigin,
  SecurityEvent,
  GeoipMapPoint,
  UnresolvedIp,
  TimelinePoint,
  RuleHit,
  SeveritySlice,
  IpHit,
  AnomalyPoint,
  TagHit,
  UriHit,
  RuleFileHit,
  StatusCodePoint,
  UserAgentHit,
  BytesPoint,
  RpsPoint,
  CountryHit,
} from "../api/client";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import { useSettings } from "../context/SettingsContext";
import TrafficChart from "../components/charts/TrafficChart";
import {
  ChartTooltip,
  EmptyState,
  formatBytes,
  formatNumber,
  useSvgHover,
  type TooltipRow,
} from "../components/charts/chart-utils";
import { injectionLabel, ruleFileToFamily } from "../utils/ruleNames";

type Tab = "grafana" | "native";
type TimeUnit = "minutes" | "hours" | "days";

type PanelKey =
  | "metricTotalRequests"
  | "metricBlockedThreats"
  | "metricAvgLatency"
  | "metricActiveRules"
  | "trafficChart"
  | "wafEvents"
  | "topRules"
  | "severity"
  | "topAttackers"
  | "anomaly"
  | "threatOrigins"
  | "topTags"
  | "topUris"
  | "topRuleFiles"
  | "statusCodes"
  | "topClientIps"
  | "topUserAgents"
  | "byCountry"
  | "trafficVolume"
  | "rps"
  | "securityEvents"
  | "geoipMap";

const ALL_METRIC_KEYS: PanelKey[] = [
  "metricTotalRequests",
  "metricBlockedThreats",
  "metricAvgLatency",
  "metricActiveRules",
];

const ALL_PANEL_KEYS: PanelKey[] = [
  "trafficChart",
  "wafEvents",
  "topRules",
  "severity",
  "topAttackers",
  "anomaly",
  "threatOrigins",
  "topTags",
  "topUris",
  "topRuleFiles",
  "statusCodes",
  "topClientIps",
  "topUserAgents",
  "byCountry",
  "trafficVolume",
  "rps",
  "securityEvents",
  "geoipMap",
];

const METRIC_ITEMS: { key: PanelKey; icon: React.ReactNode; label: string }[] = [
  { key: "metricTotalRequests", icon: <Gauge size={14} />, label: "Total Requests" },
  { key: "metricBlockedThreats", icon: <ShieldOff size={14} />, label: "Blocked Threats" },
  { key: "metricAvgLatency", icon: <Clock size={14} />, label: "Avg Latency" },
  { key: "metricActiveRules", icon: <ScrollText size={14} />, label: "Active Rules" },
];

const PANEL_ITEMS: { key: PanelKey; icon: React.ReactNode; label: string }[] = [
  { key: "trafficChart", icon: <BarChart3 size={14} />, label: "Traffic Overview" },
  { key: "wafEvents", icon: <Activity size={14} />, label: "WAF Events Over Time" },
  { key: "topRules", icon: <ShieldAlert size={14} />, label: "Top Rules" },
  { key: "severity", icon: <PieChart size={14} />, label: "Severity Distribution" },
  { key: "topAttackers", icon: <Users size={14} />, label: "Top Attacking IPs" },
  { key: "anomaly", icon: <AlertTriangle size={14} />, label: "Anomaly Score" },
  { key: "threatOrigins", icon: <Globe size={14} />, label: "Threat Origins" },
  { key: "topTags", icon: <Tag size={14} />, label: "Top Tags" },
  { key: "topUris", icon: <Link size={14} />, label: "Top Blocked URIs" },
  { key: "topRuleFiles", icon: <FileCode size={14} />, label: "Top Attack Families" },
  { key: "statusCodes", icon: <TrendingUp size={14} />, label: "HTTP Status Codes" },
  { key: "topClientIps", icon: <HardDrive size={14} />, label: "Top Client IPs" },
  { key: "topUserAgents", icon: <Bot size={14} />, label: "Top User-Agents" },
  { key: "byCountry", icon: <Flag size={14} />, label: "Requests by Country" },
  { key: "trafficVolume", icon: <BarChart3 size={14} />, label: "Traffic Volume (Bytes)" },
  { key: "rps", icon: <Zap size={14} />, label: "Requests per Second" },
  { key: "securityEvents", icon: <ShieldAlert size={14} />, label: "Security Events Table" },
  { key: "geoipMap", icon: <Map size={14} />, label: "GeoIP World Map" },
];

const STORAGE_KEY = "waf:dashboardPanels:v2";

function loadVisible(): Set<PanelKey> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return new Set([...ALL_METRIC_KEYS, ...ALL_PANEL_KEYS]);
    const arr = JSON.parse(raw) as string[];
    return new Set(arr as PanelKey[]);
  } catch {
    return new Set([...ALL_METRIC_KEYS, ...ALL_PANEL_KEYS]);
  }
}

const UNITS: { value: TimeUnit; label: string; multiplier: number }[] = [
  { value: "minutes", label: "Minutes", multiplier: 1 / 60 },
  { value: "hours", label: "Hours", multiplier: 1 },
  { value: "days", label: "Days", multiplier: 24 },
];

// No-flicker fetch hook: only the very first fetch (or one triggered by a
// deps change while we have no cached data) shows a spinner. Background
// refreshes are silent — the previous data stays on screen.
function useDashboardPanel<T>(
  fetcher: () => Promise<T>,
  deps: ReadonlyArray<unknown>,
  intervalMs = 15_000,
  enabled = true,
): { data: T | null; initialLoading: boolean; error: string | null } {
  const [data, setData] = useState<T | null>(null);
  const [initialLoading, setInitialLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const depsKey = JSON.stringify(deps);

  useEffect(() => {
    if (!enabled) return;

    let cancelled = false;

    const run = async () => {
      try {
        const result = await fetcherRef.current();
        if (cancelled) return;
        setData(result);
        setError(null);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to load");
      } finally {
        if (!cancelled) setInitialLoading(false);
      }
    };

    run();
    const id = setInterval(run, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [depsKey, intervalMs, enabled]);

  return { data, initialLoading, error };
}

function PanelCard({
  title,
  icon,
  children,
  style,
}: {
  title: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
  style?: React.CSSProperties;
}) {
  return (
    <div className="card" style={{ marginBottom: "16px", ...style }}>
      <div className="card-header" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        {icon}
        <h2 style={{ fontSize: "15px", margin: 0 }}>{title}</h2>
      </div>
      <div style={{ padding: "8px 4px" }}>{children}</div>
    </div>
  );
}

function TimelineSeries({
  data,
  loading,
  valueOf,
  color,
  unit,
  valueLabel = "Value",
}: {
  data: { timestamp: string }[] | null;
  loading: boolean;
  valueOf: (d: { timestamp: string }) => number;
  color: string;
  unit?: "count" | "bytes" | "rps";
  valueLabel?: string;
}) {
  const padding = { top: 16, right: 16, bottom: 36, left: 64 };
  const width = 1200;
  const height = 280;
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const safeData = data ?? [];
  const values = safeData.map(valueOf);
  const maxVal = Math.max(...values, 1);
  const stepX = chartW / Math.max(safeData.length - 1, 1);

  const { hoverIdx, pos, wrapRef, svgRef, onMove, onLeave } = useSvgHover(
    width,
    padding.left,
    padding.right,
    stepX,
    safeData.length,
  );

  if (!data || data.length === 0) return <EmptyState loading={loading} message="No data available" />;

  const points = data.map((d, i) => {
    const x = padding.left + i * stepX;
    const y = padding.top + chartH - (valueOf(d) / maxVal) * chartH;
    return [x, y] as const;
  });
  const path = points.map(([x, y], i) => (i === 0 ? `M ${x},${y}` : `L ${x},${y}`)).join(" ");
  const areaPath = `${path} L ${points[points.length - 1][0]},${padding.top + chartH} L ${points[0][0]},${padding.top + chartH} Z`;

  const yTicks = 5;
  const tickVals: number[] = [];
  for (let i = 0; i <= yTicks; i++) tickVals.push((maxVal / yTicks) * i);

  const fmt = (v: number) => {
    if (unit === "bytes") return formatBytes(v);
    if (unit === "rps") return `${v.toFixed(1)} rps`;
    return formatNumber(Math.round(v));
  };

  const sum = values.reduce((a, b) => a + b, 0);
  const avg = values.length ? sum / values.length : 0;
  const peak = Math.max(...values, 0);

  return (
    <div ref={wrapRef} style={{ position: "relative" }} onMouseMove={onMove} onMouseLeave={onLeave}>
      <svg ref={svgRef} viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height: "auto", display: "block" }}>
        {tickVals.map((v, i) => {
          const y = padding.top + chartH - (v / maxVal) * chartH;
          return (
            <g key={i}>
              <line x1={padding.left} y1={y} x2={width - padding.right} y2={y} stroke="var(--border-subtle)" strokeWidth="0.5" />
              <text x={padding.left - 8} y={y + 4} textAnchor="end" fill="var(--text-muted)" fontSize="11">{fmt(v)}</text>
            </g>
          );
        })}
        <path d={areaPath} fill={color} opacity={0.18} />
        <path d={path} fill="none" stroke={color} strokeWidth={2.5} />
        {data.map((d, i) => {
          if (i % Math.max(1, Math.floor(data.length / 10)) !== 0) return null;
          const x = padding.left + i * stepX;
          return (
            <text key={i} x={x} y={height - 8} textAnchor="middle" fill="var(--text-muted)" fontSize="11">
              {new Date(d.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            </text>
          );
        })}
        {hoverIdx !== null && points[hoverIdx] && (
          <g pointerEvents="none">
            <line
              x1={points[hoverIdx][0]}
              y1={padding.top}
              x2={points[hoverIdx][0]}
              y2={padding.top + chartH}
              stroke="var(--ink)"
              strokeWidth="1"
              strokeDasharray="3 3"
              opacity={0.7}
            />
            <circle cx={points[hoverIdx][0]} cy={points[hoverIdx][1]} r={5} fill="var(--card-bg)" stroke={color} strokeWidth={2} />
          </g>
        )}
      </svg>
      {hoverIdx !== null && pos && (
        <ChartTooltip
          x={pos.x}
          y={pos.y}
          containerWidth={pos.containerW}
          title={new Date(data[hoverIdx].timestamp).toLocaleString([], {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          })}
          rows={[
            { label: valueLabel, value: fmt(values[hoverIdx]), color },
            { label: "Peak (range)", value: fmt(peak) },
            { label: "Avg (range)", value: fmt(avg) },
          ]}
        />
      )}
    </div>
  );
}

const STATUS_COLORS = {
  c2xx: "#10b981",
  c3xx: "#3b82f6",
  c4xx: "#f59e0b",
  c5xx: "#ef4444",
} as const;

function StatusCodesChart({ data, loading }: { data: StatusCodePoint[] | null; loading: boolean }) {
  const padding = { top: 16, right: 16, bottom: 36, left: 60 };
  const width = 1200;
  const height = 300;
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const safeData = data ?? [];
  const totals = safeData.map((d) => d.c2xx + d.c3xx + d.c4xx + d.c5xx);
  const maxVal = Math.max(...totals, 1);
  const barW = Math.max(3, Math.floor(chartW / Math.max(safeData.length, 1)) - 2);
  const stepX = chartW / Math.max(safeData.length, 1);

  const { hoverIdx, pos, wrapRef, svgRef, onMove, onLeave } = useSvgHover(
    width,
    padding.left,
    padding.right,
    stepX,
    safeData.length,
  );

  if (!data || data.length === 0) return <EmptyState loading={loading} message="No status code data" />;

  const hovered = hoverIdx !== null ? data[hoverIdx] : null;
  const hoveredTotal = hovered ? hovered.c2xx + hovered.c3xx + hovered.c4xx + hovered.c5xx : 0;

  return (
    <div ref={wrapRef} style={{ position: "relative" }} onMouseMove={onMove} onMouseLeave={onLeave}>
      <svg ref={svgRef} viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height: "auto", display: "block" }}>
        {[0, 0.25, 0.5, 0.75, 1].map((p) => {
          const y = padding.top + chartH - p * chartH;
          return (
            <g key={p}>
              <line x1={padding.left} y1={y} x2={width - padding.right} y2={y} stroke="var(--border-subtle)" strokeWidth="0.5" />
              <text x={padding.left - 8} y={y + 4} textAnchor="end" fill="var(--text-muted)" fontSize="11">
                {formatNumber(Math.round(maxVal * p))}
              </text>
            </g>
          );
        })}
        {data.map((d, i) => {
          const x = padding.left + i * stepX;
          let yCursor = padding.top + chartH;
          const isHover = hoverIdx === i;
          return (
            <g key={d.timestamp}>
              {(["c2xx", "c3xx", "c4xx", "c5xx"] as const).map((k) => {
                const h = (d[k] / maxVal) * chartH;
                yCursor -= h;
                return <rect key={k} x={x + 1} y={yCursor} width={barW} height={h} fill={STATUS_COLORS[k]} opacity={isHover ? 1 : 0.9} />;
              })}
              {i % Math.max(1, Math.floor(data.length / 10)) === 0 && (
                <text x={x + barW / 2} y={height - 8} textAnchor="middle" fill="var(--text-muted)" fontSize="11">
                  {new Date(d.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                </text>
              )}
            </g>
          );
        })}
        {hoverIdx !== null && (
          <line
            x1={padding.left + hoverIdx * stepX + barW / 2 + 1}
            y1={padding.top}
            x2={padding.left + hoverIdx * stepX + barW / 2 + 1}
            y2={padding.top + chartH}
            stroke="var(--ink)"
            strokeWidth="1"
            strokeDasharray="3 3"
            opacity={0.7}
            pointerEvents="none"
          />
        )}
        {(["c2xx", "c3xx", "c4xx", "c5xx"] as const).map((k, idx) => (
          <g key={k}>
            <rect x={padding.left + idx * 70} y={4} width="12" height="12" rx="2" fill={STATUS_COLORS[k]} />
            <text x={padding.left + idx * 70 + 16} y={14} fill="var(--text-secondary)" fontSize="12">
              {k.replace("c", "")}
            </text>
          </g>
        ))}
      </svg>
      {hovered && pos && (
        <ChartTooltip
          x={pos.x}
          y={pos.y}
          containerWidth={pos.containerW}
          title={new Date(hovered.timestamp).toLocaleString([], {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          })}
          rows={[
            ...(["c2xx", "c3xx", "c4xx", "c5xx"] as const).map<TooltipRow>((k) => ({
              label: k.replace("c", "") + " responses",
              value:
                hoveredTotal > 0
                  ? `${hovered[k].toLocaleString()} (${((hovered[k] / hoveredTotal) * 100).toFixed(1)}%)`
                  : hovered[k].toLocaleString(),
              color: STATUS_COLORS[k],
            })),
            { label: "Total", value: hoveredTotal.toLocaleString() },
          ]}
        />
      )}
    </div>
  );
}

function HorizontalBars({
  data,
  loading,
  labelOf,
  valueOf,
  gradient = "linear-gradient(90deg, var(--accent-1), var(--accent-2))",
  valueLabel = "Hits",
}: {
  data: unknown[] | null;
  loading: boolean;
  labelOf: (d: any) => string;
  valueOf: (d: any) => number;
  gradient?: string;
  valueLabel?: string;
}) {
  const [hoverRow, setHoverRow] = useState<number | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ x: number; y: number; containerW: number } | null>(null);

  if (!data || data.length === 0) return <EmptyState loading={loading} message="No data" />;
  const maxVal = Math.max(...data.map((d) => valueOf(d)), 1);
  const total: number = data.reduce<number>((a, d) => a + valueOf(d), 0);

  const onRowMove = (e: React.MouseEvent<HTMLDivElement>, idx: number) => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    setHoverRow(idx);
    setPos({ x: e.clientX - rect.left, y: e.clientY - rect.top, containerW: rect.width });
  };

  const hovered = hoverRow !== null ? data[hoverRow] : null;

  return (
    <div
      ref={wrapRef}
      style={{ display: "flex", flexDirection: "column", gap: "6px", padding: "4px 8px", position: "relative" }}
      onMouseLeave={() => {
        setHoverRow(null);
        setPos(null);
      }}
    >
      {data.map((d, i) => {
        const label = labelOf(d);
        const val = valueOf(d);
        const isHover = hoverRow === i;
        return (
          <div
            key={i}
            onMouseMove={(e) => onRowMove(e, i)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              minHeight: "26px",
              cursor: "default",
              filter: isHover ? "brightness(1.12)" : undefined,
              transition: "filter var(--duration-fast) var(--ease-out)",
            }}
          >
            <span
              style={{
                width: "180px",
                fontSize: "12px",
                fontFamily: "monospace",
                color: "var(--text-secondary)",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
                flexShrink: 0,
              }}
              title={label}
            >
              {label}
            </span>
            <div
              style={{
                flex: 1,
                height: "22px",
                background: "var(--bg-elevated)",
                borderRadius: "3px",
                overflow: "hidden",
                position: "relative",
                outline: isHover ? "1px solid var(--ink)" : undefined,
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${(val / maxVal) * 100}%`,
                  background: gradient,
                  borderRadius: "3px",
                  display: "flex",
                  alignItems: "center",
                  paddingLeft: "8px",
                }}
              >
                <span style={{ fontSize: "11px", fontWeight: 600, color: "#fff", whiteSpace: "nowrap" }}>
                  {formatNumber(val)}
                </span>
              </div>
            </div>
          </div>
        );
      })}
      {hovered !== null && hoverRow !== null && pos && (
        <ChartTooltip
          x={pos.x}
          y={pos.y}
          containerWidth={pos.containerW}
          title={labelOf(hovered)}
          rows={[
            { label: valueLabel, value: valueOf(hovered).toLocaleString() },
            {
              label: "Share of top",
              value: total > 0 ? `${((valueOf(hovered) / total) * 100).toFixed(1)}%` : "—",
            },
            { label: "Rank", value: `#${hoverRow + 1} of ${data.length}` },
          ]}
        />
      )}
    </div>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  EMERGENCY: "#7f1d1d",
  ALERT: "#dc2626",
  CRITICAL: "#f97316",
  ERROR: "#eab308",
  WARNING: "#fde047",
  NOTICE: "#3b82f6",
  INFO: "#10b981",
  DEBUG: "#16a34a",
};

function SeverityDonut({ data, loading }: { data: SeveritySlice[] | null; loading: boolean }) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ x: number; y: number; containerW: number } | null>(null);

  if (!data || data.length === 0) return <EmptyState loading={loading} message="No severity data" />;
  const total = data.reduce((a, b) => a + b.hits, 0);
  if (total === 0) return <EmptyState loading={false} message="No severity data" />;
  const size = 220;
  const cx = size / 2;
  const cy = size / 2;
  const r = 90;
  const inner = 55;
  let cursor = 0;

  const trackPos = (e: React.MouseEvent) => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    setPos({ x: e.clientX - rect.left, y: e.clientY - rect.top, containerW: rect.width });
  };

  const hovered = hoverIdx !== null ? data[hoverIdx] : null;

  return (
    <div
      ref={wrapRef}
      style={{ display: "flex", alignItems: "center", gap: "24px", padding: "8px", flexWrap: "wrap", position: "relative" }}
      onMouseMove={trackPos}
      onMouseLeave={() => {
        setHoverIdx(null);
        setPos(null);
      }}
    >
      <svg viewBox={`0 0 ${size} ${size}`} style={{ width: size, height: size, flexShrink: 0 }}>
        {data.map((slice, idx) => {
          const frac = slice.hits / total;
          const start = cursor * 2 * Math.PI;
          const end = (cursor + frac) * 2 * Math.PI;
          cursor += frac;
          const xs = cx + r * Math.sin(start);
          const ys = cy - r * Math.cos(start);
          const xe = cx + r * Math.sin(end);
          const ye = cy - r * Math.cos(end);
          const large = frac > 0.5 ? 1 : 0;
          const xsI = cx + inner * Math.sin(end);
          const ysI = cy - inner * Math.cos(end);
          const xeI = cx + inner * Math.sin(start);
          const yeI = cy - inner * Math.cos(start);
          const d = `M ${xs} ${ys} A ${r} ${r} 0 ${large} 1 ${xe} ${ye} L ${xsI} ${ysI} A ${inner} ${inner} 0 ${large} 0 ${xeI} ${yeI} Z`;
          const isHover = hoverIdx === idx;
          return (
            <path
              key={slice.severity}
              d={d}
              fill={SEVERITY_COLORS[slice.severity] || "#888"}
              opacity={hoverIdx === null || isHover ? 0.95 : 0.4}
              stroke={isHover ? "var(--ink)" : "transparent"}
              strokeWidth={isHover ? 2 : 0}
              onMouseEnter={() => setHoverIdx(idx)}
              style={{ cursor: "pointer", transition: "opacity var(--duration-fast) var(--ease-out)" }}
            />
          );
        })}
        <text x={cx} y={cy - 4} textAnchor="middle" fontSize="22" fontWeight={700} fill="var(--text-primary)">
          {hovered ? formatNumber(hovered.hits) : formatNumber(total)}
        </text>
        <text x={cx} y={cy + 14} textAnchor="middle" fontSize="10" fill="var(--text-muted)">
          {hovered ? hovered.severity : "TOTAL"}
        </text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: "6px", minWidth: "180px" }}>
        {data.map((s, idx) => {
          const isHover = hoverIdx === idx;
          return (
            <div
              key={s.severity}
              onMouseEnter={() => setHoverIdx(idx)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                fontSize: "13px",
                cursor: "default",
                opacity: hoverIdx === null || isHover ? 1 : 0.55,
                transition: "opacity var(--duration-fast) var(--ease-out)",
              }}
            >
              <div style={{ width: 14, height: 14, borderRadius: 3, background: SEVERITY_COLORS[s.severity] || "#888" }} />
              <span style={{ color: "var(--text-secondary)", flex: 1 }}>{s.severity}</span>
              <span style={{ fontWeight: 600, color: "var(--text-primary)", fontFamily: "var(--font-mono)" }}>
                {formatNumber(s.hits)} ({((s.hits / total) * 100).toFixed(1)}%)
              </span>
            </div>
          );
        })}
      </div>
      {hovered && pos && (
        <ChartTooltip
          x={pos.x}
          y={pos.y}
          containerWidth={pos.containerW}
          title={hovered.severity}
          rows={[
            { label: "Hits", value: hovered.hits.toLocaleString(), color: SEVERITY_COLORS[hovered.severity] || "#888" },
            { label: "Share", value: `${((hovered.hits / total) * 100).toFixed(2)}%` },
            { label: "Total (all)", value: total.toLocaleString() },
          ]}
        />
      )}
    </div>
  );
}

function ThreatOriginsChart({ data, loading }: { data: ThreatOrigin[] | null; loading: boolean }) {
  const [hoverRow, setHoverRow] = useState<number | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ x: number; y: number; containerW: number } | null>(null);

  if (!data || data.length === 0) return <EmptyState loading={loading} message="No threat data available" />;
  const maxPct = Math.max(...data.map((d) => d.blocks_percent), 1);
  const totalPct: number = data.reduce<number>((a, d) => a + d.blocks_percent, 0);

  const onMove = (e: React.MouseEvent, idx: number) => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    setHoverRow(idx);
    setPos({ x: e.clientX - rect.left, y: e.clientY - rect.top, containerW: rect.width });
  };

  const hovered = hoverRow !== null ? data[hoverRow] : null;

  return (
    <div
      ref={wrapRef}
      style={{ display: "flex", flexDirection: "column", gap: "8px", padding: "8px", position: "relative" }}
      onMouseLeave={() => {
        setHoverRow(null);
        setPos(null);
      }}
    >
      {data.map((d, i) => {
        const isHover = hoverRow === i;
        return (
          <div
            key={d.country_code}
            onMouseMove={(e) => onMove(e, i)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "12px",
              height: "26px",
              filter: isHover ? "brightness(1.12)" : undefined,
              transition: "filter var(--duration-fast) var(--ease-out)",
            }}
          >
            <span style={{ width: "44px", fontSize: "12px", fontWeight: 600, color: "var(--text-secondary)", textAlign: "right", flexShrink: 0 }}>
              {d.country_code}
            </span>
            <div
              style={{
                flex: 1,
                height: "100%",
                background: "var(--bg-elevated)",
                borderRadius: "3px",
                overflow: "hidden",
                outline: isHover ? "1px solid var(--ink)" : undefined,
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${(d.blocks_percent / maxPct) * 100}%`,
                  background: "linear-gradient(90deg, var(--danger), var(--accent-2))",
                  borderRadius: "3px",
                  display: "flex",
                  alignItems: "center",
                  paddingLeft: "10px",
                }}
              >
                <span style={{ fontSize: "11px", fontWeight: 600, color: "#fff", whiteSpace: "nowrap" }}>
                  {d.blocks_percent}%
                </span>
              </div>
            </div>
          </div>
        );
      })}
      {hovered && hoverRow !== null && pos && (
        <ChartTooltip
          x={pos.x}
          y={pos.y}
          containerWidth={pos.containerW}
          title={hovered.country || hovered.country_code}
          rows={[
            { label: "Country code", value: hovered.country_code },
            { label: "Block share", value: `${hovered.blocks_percent}%` },
            {
              label: "Of top-N total",
              value: totalPct > 0 ? `${((hovered.blocks_percent / totalPct) * 100).toFixed(1)}%` : "—",
            },
            { label: "Rank", value: `#${hoverRow + 1} of ${data.length}` },
          ]}
        />
      )}
    </div>
  );
}

function EventsTable({ data, loading }: { data: SecurityEvent[] | null; loading: boolean }) {
  if (!data || data.length === 0) return <EmptyState loading={loading} message="No recent security events" />;

  const severityColors: Record<string, string> = {
    critical: "var(--danger)",
    high: "var(--danger)",
    medium: "var(--warning)",
    low: "var(--info)",
    info: "var(--text-muted)",
  };

  return (
    <div className="table-wrapper" style={{ maxHeight: "360px", overflowY: "auto" }}>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Rule</th>
            <th>IP</th>
            <th>Path</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {data.map((e, i) => (
            <tr key={i}>
              <td style={{ whiteSpace: "nowrap", fontSize: "12px" }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
              <td style={{ fontSize: "12px", fontFamily: "monospace" }}>{injectionLabel(e.type)}</td>
              <td style={{ fontSize: "12px", fontFamily: "monospace" }}>{e.ip}</td>
              <td style={{ fontSize: "12px", fontFamily: "monospace", maxWidth: "320px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {e.path}
              </td>
              <td>
                <span
                  className="badge"
                  style={{
                    background: `${severityColors[e.severity] || "var(--text-muted)"}22`,
                    color: severityColors[e.severity] || "var(--text-muted)",
                    fontSize: "11px",
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

// Classify a non-private IP that failed GeoIP enrichment. The MaxMind
// GeoLite2 database deliberately excludes RFC 5737 documentation ranges,
// RFC 6598 CGNAT, and a few other special-use blocks. Everything else is
// a real public IP that just isn't in the DB (rare — usually means the
// DB is stale or the IP is brand-new).
function classifyUnresolvedIp(ip: string): { kind: string; reason: string } {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return { kind: "Other", reason: "Unparseable IPv4 address" };
  }
  const [a, b] = parts;
  if (a === 192 && b === 0 && parts[2] === 2) return { kind: "TEST-NET-1", reason: "RFC 5737 — reserved for documentation. Not in MaxMind." };
  if (a === 198 && b === 51 && parts[2] === 100) return { kind: "TEST-NET-2", reason: "RFC 5737 — reserved for documentation. Not in MaxMind." };
  if (a === 203 && b === 0 && parts[2] === 113) return { kind: "TEST-NET-3", reason: "RFC 5737 — reserved for documentation. Not in MaxMind." };
  if (a === 100 && b >= 64 && b <= 127) return { kind: "CGNAT", reason: "RFC 6598 — carrier-grade NAT. No public location." };
  if (a >= 224 && a <= 239) return { kind: "Multicast", reason: "224.0.0.0/4 — multicast, not a host address." };
  if (a >= 240) return { kind: "Reserved", reason: "240.0.0.0/4 — IANA reserved." };
  return { kind: "Public", reason: "Real public IP missing from this MaxMind GeoLite2 build. Consider updating the .mmdb." };
}

function UnresolvedIpsList({ data, compact = false }: { data: UnresolvedIp[]; compact?: boolean }) {
  if (data.length === 0) return null;
  const total = data.reduce((a, d) => a + d.hits, 0);
  return (
    <div
      style={{
        marginTop: compact ? "10px" : "14px",
        paddingTop: compact ? "10px" : "12px",
        borderTop: "1px dashed var(--border-subtle)",
      }}
    >
      <div
        style={{
          fontFamily: "var(--font-cond)",
          fontSize: "10.5px",
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: "var(--text-secondary)",
          marginBottom: "8px",
        }}
      >
        {data.length} external IP{data.length === 1 ? "" : "s"} unresolved · {total.toLocaleString()} hit{total === 1 ? "" : "s"}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "5px", maxHeight: compact ? "180px" : "260px", overflowY: "auto" }}>
        {data.map((d) => {
          const cls = classifyUnresolvedIp(d.ip);
          return (
            <div
              key={d.ip}
              title={cls.reason}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                fontSize: "12px",
                padding: "4px 8px",
                background: "var(--bg-elevated)",
                border: "1px solid var(--border-subtle)",
              }}
            >
              <span
                style={{
                  fontFamily: "var(--font-mono)",
                  color: "var(--text-primary)",
                  minWidth: "118px",
                }}
              >
                {d.ip}
              </span>
              <span
                style={{
                  fontFamily: "var(--font-cond)",
                  fontSize: "10px",
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  padding: "1px 6px",
                  border: "1px solid var(--ink)",
                  color: "var(--text-secondary)",
                  background: "var(--card-bg)",
                  whiteSpace: "nowrap",
                }}
              >
                {cls.kind}
              </span>
              <span style={{ flex: 1 }} />
              <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "var(--text-primary)" }}>
                {d.hits.toLocaleString()}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function GeoipMap({
  data,
  loading,
  unresolved,
}: {
  data: GeoipMapPoint[] | null;
  loading: boolean;
  unresolved: UnresolvedIp[] | null;
}) {
  const { theme } = useSettings();
  const isLight = theme === "light";
  const tileUrl = isLight
    ? "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}.png"
    : "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png";
  const mapBg = isLight ? "#f5f6fa" : "#0b0f1e";
  const legendBg = isLight ? "rgba(255,255,255,0.9)" : "rgba(11,15,30,0.85)";
  const popupText = isLight ? "#1a1d2e" : "#e8ecf4";
  const unresolvedList = unresolved ?? [];

  if (!data || data.length === 0) {
    if (loading) return <EmptyState loading={true} message="" />;
    return (
      <div style={{ height: "520px", width: "100%", borderRadius: "var(--radius-md)", overflow: "hidden", position: "relative" }}>
        <MapContainer
          center={[25, 0]}
          zoom={2}
          minZoom={2}
          maxZoom={6}
          scrollWheelZoom={false}
          dragging={false}
          touchZoom={false}
          doubleClickZoom={false}
          zoomControl={false}
          keyboard={false}
          worldCopyJump
          style={{ height: "100%", width: "100%", background: mapBg, filter: "grayscale(0.5) opacity(0.55)" }}
          attributionControl={false}
        >
          <TileLayer url={tileUrl} noWrap={false} />
        </MapContainer>
        <div
          style={{
            position: "absolute",
            inset: 0,
            zIndex: 500,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "linear-gradient(180deg, transparent 0%, rgba(0,0,0,0.15) 100%)",
            pointerEvents: "none",
          }}
        >
          <div
            style={{
              maxWidth: "440px",
              padding: "20px 22px",
              background: "var(--card-bg)",
              border: "2px solid var(--ink)",
              boxShadow: "var(--shadow-offset-sm)",
              pointerEvents: "auto",
            }}
          >
            <div
              style={{
                fontFamily: "var(--font-cond)",
                fontSize: "11px",
                letterSpacing: "0.14em",
                textTransform: "uppercase",
                color: "var(--text-secondary)",
                marginBottom: "8px",
              }}
            >
              GeoIP · waiting for external traffic
            </div>
            <div
              style={{
                fontFamily: "var(--font-display)",
                fontSize: "20px",
                fontWeight: 700,
                lineHeight: 1.15,
                color: "var(--text-primary)",
                marginBottom: "12px",
              }}
            >
              No geolocated requests in this window.
            </div>
            <ul
              style={{
                listStyle: "none",
                padding: 0,
                margin: 0,
                fontSize: "12.5px",
                lineHeight: 1.55,
                color: "var(--text-secondary)",
              }}
            >
              <li style={{ display: "flex", gap: "8px", marginBottom: "4px" }}>
                <span style={{ color: "var(--red)", fontWeight: 700 }}>·</span>
                Приватные IP (127.0.0.1, 172.x, 10.x, 192.168.x) не имеют GeoIP-координат — это нормально.
              </li>
              {unresolvedList.length > 0 ? (
                <li style={{ display: "flex", gap: "8px", marginBottom: "4px" }}>
                  <span style={{ color: "var(--red)", fontWeight: 700 }}>·</span>
                  Внешние IP ниже не разрешились — обычно это RFC 5737 test-ranges (203.0.113.x, 198.51.100.x) из ваших curl-тестов, не настоящие атакующие.
                </li>
              ) : (
                <>
                  <li style={{ display: "flex", gap: "8px", marginBottom: "4px" }}>
                    <span style={{ color: "var(--red)", fontWeight: 700 }}>·</span>
                    Точки появятся, когда придёт реальный внешний трафик через Angie на одно из ваших подключений.
                  </li>
                  <li style={{ display: "flex", gap: "8px" }}>
                    <span style={{ color: "var(--red)", fontWeight: 700 }}>·</span>
                    Проверьте, что Angie работает (логи без ошибок upstream) и GeoLite2-City.mmdb смонтирован.
                  </li>
                </>
              )}
            </ul>
            <UnresolvedIpsList data={unresolvedList} compact />
          </div>
        </div>
      </div>
    );
  }
  const maxHits = Math.max(...data.map((d) => d.hits), 1);
  const minHits = Math.min(...data.map((d) => d.hits), 1);

  const dotRadius = (hits: number) => {
    const minR = 5;
    const maxR = 22;
    if (maxHits === minHits) return (minR + maxR) / 2;
    return minR + ((hits - minHits) / (maxHits - minHits)) * (maxR - minR);
  };
  const dotColor = (hits: number) => {
    const ratio = maxHits === minHits ? 0.5 : (hits - minHits) / (maxHits - minHits);
    if (ratio < 0.33) return "#10b981";
    if (ratio < 0.66) return "#f59e0b";
    return "#f43f5e";
  };

  return (
    <div>
    <div style={{ height: "520px", width: "100%", borderRadius: "var(--radius-md)", overflow: "hidden", position: "relative" }}>
      <MapContainer
        center={[25, 0]}
        zoom={2}
        minZoom={2}
        maxZoom={6}
        scrollWheelZoom
        dragging
        touchZoom
        doubleClickZoom
        zoomControl={false}
        keyboard={false}
        worldCopyJump
        maxBounds={[[-90, -180], [90, 180]]}
        maxBoundsViscosity={0.5}
        style={{ height: "100%", width: "100%", background: mapBg }}
        attributionControl={false}
      >
        <TileLayer url={tileUrl} noWrap={false} />
        {data.map((d, i) => (
          <CircleMarker
            key={i}
            center={[d.latitude, d.longitude]}
            radius={dotRadius(d.hits)}
            pathOptions={{ fillColor: dotColor(d.hits), color: dotColor(d.hits), weight: 1.5, opacity: 0.9, fillOpacity: 0.55 }}
          >
            <Popup>
              <div style={{ fontSize: "12px", color: popupText }}>
                <strong>{d.city_name || d.country_code}</strong>
                <br />
                {d.hits.toLocaleString()} requests
                {d.country_code && d.city_name ? <><br />{d.country_code}</> : null}
              </div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
      <div
        style={{
          position: "absolute",
          bottom: "12px",
          left: "12px",
          zIndex: 1000,
          background: legendBg,
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
      <UnresolvedIpsList data={unresolvedList} />
    </div>
  );
}

function GrafanaTab({
  connections,
  connectionId,
  onConnectionChange,
}: {
  connections: Connection[];
  connectionId: number | null;
  onConnectionChange: (id: number | null) => void;
}) {
  const selected = useMemo(() => connections.find((c) => c.id === connectionId) ?? null, [connections, connectionId]);
  const varConnection = useMemo(() => {
    if (!selected || !selected.domains || selected.domains.length === 0) return null;
    return selected.domains;
  }, [selected]);

  const src = useMemo(() => {
    const params = new URLSearchParams({ orgId: "1", refresh: "10s", theme: "dark", kiosk: "tv" });
    if (varConnection) for (const domain of varConnection) params.append("var-connection", domain);
    return `/grafana/d/waf-nginx-dashboard/waf-and-nginx-security-dashboard-2?${params.toString()}`;
  }, [varConnection]);

  // Drive navigation through ref so the iframe element stays mounted.
  const iframeRef = useRef<HTMLIFrameElement>(null);
  useEffect(() => {
    const el = iframeRef.current;
    if (!el) return;
    const fullUrl = new URL(src, window.location.href).toString();
    if (el.src === fullUrl) return;
    el.src = src;
  }, [src]);

  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          marginBottom: "12px",
          padding: "10px 16px",
          background: "var(--card-bg, #1a1a2e)",
          borderRadius: "var(--radius-md, 8px)",
          border: "1px solid var(--border-color, #2a2a2a)",
        }}
      >
        <span style={{ fontSize: "13px", color: "var(--text-secondary, #888)", fontWeight: 500 }}>Domain:</span>
        <select
          data-testid="grafana-connection-picker"
          value={connectionId ?? ""}
          onChange={(e) => {
            const v = e.target.value;
            onConnectionChange(v === "" ? null : parseInt(v, 10));
          }}
          style={{
            padding: "6px 10px",
            fontSize: "13px",
            border: "1px solid var(--border-color, #2a2a2a)",
            borderRadius: "var(--radius-sm, 6px)",
            background: "var(--input-bg, #0d0d1a)",
            color: "var(--text-primary, #e0e0e0)",
            outline: "none",
            cursor: "pointer",
            minWidth: "220px",
          }}
        >
          <option value="">All domains (global dashboard)</option>
          {connections.filter((c) => c.enabled).map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
              {c.domains && c.domains.length > 0 ? ` (${c.domains.join(", ")})` : ""}
            </option>
          ))}
        </select>
      </div>

      <div className="card" style={{ padding: "8px", overflow: "hidden", height: "calc(100vh - 280px)", minHeight: "640px" }}>
        <iframe
          ref={iframeRef}
          src={src}
          style={{ border: "none", width: "100%", height: "100%", borderRadius: "var(--radius-md)" }}
          title="Grafana Dashboard"
          sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
        />
      </div>
    </div>
  );
}

function NativePanels({
  hours,
  connectionId,
  visiblePanels,
}: {
  hours: number;
  connectionId: number | null;
  visiblePanels: Set<PanelKey>;
}) {
  const deps = useMemo(() => [hours, connectionId] as const, [hours, connectionId]);

  const metrics = useDashboardPanel<Metrics>(
    () => api.getMetrics(hours, connectionId),
    deps,
    15_000,
    visiblePanels.has("metricTotalRequests") ||
      visiblePanels.has("metricBlockedThreats") ||
      visiblePanels.has("metricAvgLatency") ||
      visiblePanels.has("metricActiveRules"),
  );
  const traffic = useDashboardPanel<TrafficDataPoint[]>(() => api.getTraffic(hours, connectionId), deps, 15_000, visiblePanels.has("trafficChart"));
  const wafEvents = useDashboardPanel<TimelinePoint[]>(() => api.getWafEventsTimeline(hours, connectionId), deps, 15_000, visiblePanels.has("wafEvents"));
  const topRules = useDashboardPanel<RuleHit[]>(() => api.getTopRules(hours, connectionId), deps, 30_000, visiblePanels.has("topRules"));
  const severity = useDashboardPanel<SeveritySlice[]>(() => api.getSeverityDistribution(hours, connectionId), deps, 30_000, visiblePanels.has("severity"));
  const topAttackers = useDashboardPanel<IpHit[]>(() => api.getTopAttackingIps(hours, connectionId), deps, 30_000, visiblePanels.has("topAttackers"));
  const anomaly = useDashboardPanel<AnomalyPoint[]>(() => api.getAnomalyScore(hours, connectionId), deps, 15_000, visiblePanels.has("anomaly"));
  const threatOrigins = useDashboardPanel<ThreatOrigin[]>(() => api.getThreatOrigins(hours, connectionId), deps, 30_000, visiblePanels.has("threatOrigins"));
  const topTags = useDashboardPanel<TagHit[]>(() => api.getTopTags(hours, connectionId), deps, 30_000, visiblePanels.has("topTags"));
  const topUris = useDashboardPanel<UriHit[]>(() => api.getTopUris(hours, connectionId), deps, 30_000, visiblePanels.has("topUris"));
  const topRuleFiles = useDashboardPanel<RuleFileHit[]>(() => api.getTopRuleFiles(hours, connectionId), deps, 30_000, visiblePanels.has("topRuleFiles"));
  const statusCodes = useDashboardPanel<StatusCodePoint[]>(() => api.getStatusCodes(hours, connectionId), deps, 15_000, visiblePanels.has("statusCodes"));
  const topClientIps = useDashboardPanel<IpHit[]>(() => api.getTopClientIps(hours, connectionId), deps, 30_000, visiblePanels.has("topClientIps"));
  const topUserAgents = useDashboardPanel<UserAgentHit[]>(() => api.getTopUserAgents(hours, connectionId), deps, 30_000, visiblePanels.has("topUserAgents"));
  const byCountry = useDashboardPanel<CountryHit[]>(() => api.getRequestsByCountry(hours, connectionId), deps, 30_000, visiblePanels.has("byCountry"));
  const trafficVolume = useDashboardPanel<BytesPoint[]>(() => api.getTrafficVolume(hours, connectionId), deps, 15_000, visiblePanels.has("trafficVolume"));
  const rps = useDashboardPanel<RpsPoint[]>(() => api.getRequestsPerSecond(hours, connectionId), deps, 15_000, visiblePanels.has("rps"));
  const events = useDashboardPanel<SecurityEvent[]>(() => api.getEvents(15, "all", hours, connectionId), deps, 15_000, visiblePanels.has("securityEvents"));
  const geoip = useDashboardPanel<GeoipMapPoint[]>(() => api.getGeoipMap(hours, connectionId), deps, 30_000, visiblePanels.has("geoipMap"));
  const geoipUnresolved = useDashboardPanel<UnresolvedIp[]>(() => api.getGeoipUnresolved(hours, connectionId), deps, 30_000, visiblePanels.has("geoipMap"));

  const m = metrics.data;

  return (
    <>
      {(visiblePanels.has("metricTotalRequests") ||
        visiblePanels.has("metricBlockedThreats") ||
        visiblePanels.has("metricAvgLatency") ||
        visiblePanels.has("metricActiveRules")) && (
        <div className="metrics-grid" data-testid="metrics-row">
          {visiblePanels.has("metricTotalRequests") && (
            <div
              className="metric-card"
              title="Все HTTP-запросы, прошедшие через Angie за выбранный период. Под значением — изменение относительно предыдущего такого же окна."
            >
              <div className="metric-icon indigo">
                <Gauge size={18} />
              </div>
              <div className="metric-label">Total Requests</div>
              <div className="metric-value">{m ? formatNumber(m.total_requests) : metrics.initialLoading ? "…" : "—"}</div>
              <div className={`metric-change ${(m?.total_requests_change ?? 0) >= 0 ? "up" : "down"}`}>
                {m ? `${m.total_requests_change >= 0 ? "+" : ""}${m.total_requests_change}% vs previous` : "—"}
              </div>
            </div>
          )}
          {visiblePanels.has("metricBlockedThreats") && (
            <div
              className="metric-card"
              title="Сколько запросов ModSecurity заблокировал по правилам CRS. Под значением — число событий high+critical severity."
            >
              <div className="metric-icon rose">
                <ShieldOff size={18} />
              </div>
              <div className="metric-label">Blocked Threats</div>
              <div className="metric-value">{m ? formatNumber(m.blocked_threats) : metrics.initialLoading ? "…" : "—"}</div>
              <div className="metric-change down">{m ? `${m.high_severity_count} high severity` : "Monitored by WAF"}</div>
            </div>
          )}
          {visiblePanels.has("metricAvgLatency") && (
            <div
              className="metric-card"
              title="Средняя задержка ответа upstream (request_time) за период. Health % — обобщённый показатель состояния стека (Angie+ModSec+CrowdSec)."
            >
              <div className="metric-icon violet">
                <Clock size={18} />
              </div>
              <div className="metric-label">Avg Latency</div>
              <div className="metric-value">{m ? `${m.avg_latency_ms.toFixed(1)} ms` : metrics.initialLoading ? "…" : "—"}</div>
              <div className="metric-change up">{m ? `Health ${m.system_health}%` : "Performance metrics"}</div>
            </div>
          )}
          {visiblePanels.has("metricActiveRules") && (
            <div
              className="metric-card"
              title="Количество загруженных правил OWASP CRS в ModSecurity, готовых отрабатывать на трафике."
            >
              <div className="metric-icon emerald">
                <ScrollText size={18} />
              </div>
              <div className="metric-label">Active Rules</div>
              <div className="metric-value">{m ? m.active_rules.toLocaleString() : metrics.initialLoading ? "…" : "—"}</div>
              <div className="metric-change up">CRS Protection</div>
            </div>
          )}
        </div>
      )}

      {visiblePanels.has("trafficChart") && (
        <PanelCard title="Traffic Overview (Clean vs Malicious)" icon={<BarChart3 size={16} />}>
          <TrafficChart data={traffic.data} loading={traffic.initialLoading} />
        </PanelCard>
      )}

      {visiblePanels.has("wafEvents") && (
        <PanelCard title="🔥 WAF Events Over Time" icon={<Activity size={16} />}>
          <TimelineSeries
            data={wafEvents.data}
            loading={wafEvents.initialLoading}
            valueOf={(d) => (d as TimelinePoint).hits}
            color="#ef4444"
            valueLabel="WAF events"
          />
        </PanelCard>
      )}

      {(visiblePanels.has("topRules") || visiblePanels.has("severity")) && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
          {visiblePanels.has("topRules") && (
            <PanelCard title="🚨 Top Rules by Trigger Count" icon={<ShieldAlert size={16} />} style={{ marginBottom: 0 }}>
              <HorizontalBars data={topRules.data} loading={topRules.initialLoading} labelOf={(d: RuleHit) => injectionLabel(d.rule)} valueOf={(d: RuleHit) => d.hits} />
            </PanelCard>
          )}
          {visiblePanels.has("severity") && (
            <PanelCard title="⚠️ Severity Distribution" icon={<PieChart size={16} />} style={{ marginBottom: 0 }}>
              <SeverityDonut data={severity.data} loading={severity.initialLoading} />
            </PanelCard>
          )}
        </div>
      )}

      {(visiblePanels.has("topAttackers") || visiblePanels.has("anomaly")) && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
          {visiblePanels.has("topAttackers") && (
            <PanelCard title="🌍 Top Attacking IPs" icon={<Users size={16} />} style={{ marginBottom: 0 }}>
              <HorizontalBars data={topAttackers.data} loading={topAttackers.initialLoading} labelOf={(d: IpHit) => d.ip} valueOf={(d: IpHit) => d.hits} gradient="linear-gradient(90deg, var(--danger), #f59e0b)" />
            </PanelCard>
          )}
          {visiblePanels.has("anomaly") && (
            <PanelCard title="🧠 Anomaly Score Timeline" icon={<AlertTriangle size={16} />} style={{ marginBottom: 0 }}>
              <TimelineSeries
                data={anomaly.data}
                loading={anomaly.initialLoading}
                valueOf={(d) => (d as AnomalyPoint).score}
                color="#f97316"
                valueLabel="Anomaly score"
              />
            </PanelCard>
          )}
        </div>
      )}

      {(visiblePanels.has("threatOrigins") || visiblePanels.has("topTags")) && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
          {visiblePanels.has("threatOrigins") && (
            <PanelCard title="Threat Origins by Country" icon={<Globe size={16} />} style={{ marginBottom: 0 }}>
              <ThreatOriginsChart data={threatOrigins.data} loading={threatOrigins.initialLoading} />
            </PanelCard>
          )}
          {visiblePanels.has("topTags") && (
            <PanelCard title="🏷 Top Tags" icon={<Tag size={16} />} style={{ marginBottom: 0 }}>
              <HorizontalBars data={topTags.data} loading={topTags.initialLoading} labelOf={(d: TagHit) => d.tag} valueOf={(d: TagHit) => d.hits} gradient="linear-gradient(90deg, var(--accent-2), var(--accent-1))" />
            </PanelCard>
          )}
        </div>
      )}

      {(visiblePanels.has("topUris") || visiblePanels.has("topRuleFiles")) && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
          {visiblePanels.has("topUris") && (
            <PanelCard title="📄 Top Blocked URIs" icon={<Link size={16} />} style={{ marginBottom: 0 }}>
              <HorizontalBars data={topUris.data} loading={topUris.initialLoading} labelOf={(d: UriHit) => d.uri} valueOf={(d: UriHit) => d.hits} />
            </PanelCard>
          )}
          {visiblePanels.has("topRuleFiles") && (
            <PanelCard title="🧩 Top Attack Families" icon={<FileCode size={16} />} style={{ marginBottom: 0 }}>
              <HorizontalBars data={topRuleFiles.data} loading={topRuleFiles.initialLoading} labelOf={(d: RuleFileHit) => ruleFileToFamily(d.file)} valueOf={(d: RuleFileHit) => d.hits} />
            </PanelCard>
          )}
        </div>
      )}

      {visiblePanels.has("statusCodes") && (
        <PanelCard title="📈 HTTP Status Codes Over Time" icon={<TrendingUp size={16} />}>
          <StatusCodesChart data={statusCodes.data} loading={statusCodes.initialLoading} />
        </PanelCard>
      )}

      {(visiblePanels.has("topClientIps") || visiblePanels.has("topUserAgents")) && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
          {visiblePanels.has("topClientIps") && (
            <PanelCard title="🌐 Top Client IPs" icon={<HardDrive size={16} />} style={{ marginBottom: 0 }}>
              <HorizontalBars data={topClientIps.data} loading={topClientIps.initialLoading} labelOf={(d: IpHit) => d.ip} valueOf={(d: IpHit) => d.hits} gradient="linear-gradient(90deg, #6366f1, #8b5cf6)" />
            </PanelCard>
          )}
          {visiblePanels.has("topUserAgents") && (
            <PanelCard title="🤖 Top User-Agents" icon={<Bot size={16} />} style={{ marginBottom: 0 }}>
              <HorizontalBars
                data={topUserAgents.data}
                loading={topUserAgents.initialLoading}
                labelOf={(d: UserAgentHit) => (d.user_agent.length > 28 ? d.user_agent.slice(0, 27) + "…" : d.user_agent)}
                valueOf={(d: UserAgentHit) => d.hits}
              />
            </PanelCard>
          )}
        </div>
      )}

      {(visiblePanels.has("byCountry") || visiblePanels.has("trafficVolume")) && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
          {visiblePanels.has("byCountry") && (
            <PanelCard title="🌍 Requests by Country" icon={<Flag size={16} />} style={{ marginBottom: 0 }}>
              <HorizontalBars data={byCountry.data} loading={byCountry.initialLoading} labelOf={(d: CountryHit) => d.country_code} valueOf={(d: CountryHit) => d.hits} gradient="linear-gradient(90deg, #10b981, var(--accent-1))" />
            </PanelCard>
          )}
          {visiblePanels.has("trafficVolume") && (
            <PanelCard title="📊 Traffic Volume (Bytes)" icon={<BarChart3 size={16} />} style={{ marginBottom: 0 }}>
              <TimelineSeries
                data={trafficVolume.data}
                loading={trafficVolume.initialLoading}
                valueOf={(d) => (d as BytesPoint).bytes}
                color="#3b82f6"
                unit="bytes"
                valueLabel="Bytes sent"
              />
            </PanelCard>
          )}
        </div>
      )}

      {visiblePanels.has("rps") && (
        <PanelCard title="⏱ Requests per Second" icon={<Zap size={16} />}>
          <TimelineSeries
            data={rps.data}
            loading={rps.initialLoading}
            valueOf={(d) => (d as RpsPoint).rps}
            color="#06b6d4"
            unit="rps"
            valueLabel="Req / sec"
          />
        </PanelCard>
      )}

      {visiblePanels.has("securityEvents") && (
        <PanelCard title="Recent Security Events" icon={<ShieldAlert size={16} />}>
          <EventsTable data={events.data} loading={events.initialLoading} />
        </PanelCard>
      )}

      {visiblePanels.has("geoipMap") && (
        <PanelCard title="GeoIP Attack Origins Map" icon={<Map size={16} />}>
          <GeoipMap data={geoip.data} loading={geoip.initialLoading} unresolved={geoipUnresolved.data} />
        </PanelCard>
      )}
    </>
  );
}

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<Tab>("grafana");

  const [timeValue, setTimeValue] = useState<number>(24);
  const [timeUnit, setTimeUnit] = useState<TimeUnit>("hours");

  const [visiblePanels, setVisiblePanels] = useState<Set<PanelKey>>(() => loadVisible());
  const [gearOpen, setGearOpen] = useState(false);
  const gearPopoverRef = useRef<HTMLDivElement>(null);

  const [connections, setConnections] = useState<Connection[]>([]);
  const [connectionId, setConnectionId] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.getConnections().then((data) => {
      if (!cancelled) setConnections(data);
    }).catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([...visiblePanels]));
    } catch {
      /* ignore */
    }
  }, [visiblePanels]);

  const togglePanel = useCallback((key: PanelKey) => {
    setVisiblePanels((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  useEffect(() => {
    if (!gearOpen) return;
    const handleClick = (e: MouseEvent) => {
      if (gearPopoverRef.current && !gearPopoverRef.current.contains(e.target as Node)) setGearOpen(false);
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setGearOpen(false);
    };
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [gearOpen]);

  const unitMultiplier = UNITS.find((u) => u.value === timeUnit)?.multiplier ?? 1;
  const selectedHours = +(timeValue * unitMultiplier).toFixed(4);
  const MAX_HOURS = 8760;
  const maxValue = Math.floor(MAX_HOURS / unitMultiplier);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Dashboard</h1>
          <p>
            {activeTab === "grafana"
              ? "Real-time WAF monitoring and analytics powered by Grafana"
              : "Native WAF metrics, threat intelligence and traffic analytics"}
          </p>
        </div>
      </div>

      <div style={{ display: "flex", gap: 0, marginBottom: "20px", borderBottom: "2px solid var(--border-color, #2a2a2a)" }}>
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

      {activeTab === "native" && (
        <>
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
            <span style={{ fontSize: "13px", color: "var(--text-secondary, #888)", fontWeight: 500 }}>Time Range:</span>
            <input
              type="number"
              min={1}
              max={maxValue}
              value={timeValue}
              onChange={(e) => {
                const v = parseInt(e.target.value, 10);
                if (!isNaN(v) && v >= 1 && v <= maxValue) setTimeValue(v);
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
                <option key={unit.value} value={unit.value}>{unit.label}</option>
              ))}
            </select>
            <span style={{ fontSize: "12px", color: "var(--text-secondary, #666)" }}>
              (last {timeValue} {timeUnit === "minutes" ? "min" : timeUnit === "hours" ? "hr" : "day"}{timeValue !== 1 ? "s" : ""})
            </span>

            <span style={{ fontSize: "13px", color: "var(--text-secondary, #888)", fontWeight: 500, marginLeft: "12px" }}>Domain:</span>
            <select
              data-testid="dashboard-connection-picker"
              value={connectionId ?? ""}
              onChange={(e) => {
                const v = e.target.value;
                setConnectionId(v === "" ? null : parseInt(v, 10));
              }}
              style={{
                padding: "6px 10px",
                fontSize: "13px",
                border: "1px solid var(--border-color, #2a2a2a)",
                borderRadius: "var(--radius-sm, 6px)",
                background: "var(--input-bg, #0d0d1a)",
                color: "var(--text-primary, #e0e0e0)",
                outline: "none",
                cursor: "pointer",
                minWidth: "180px",
              }}
            >
              <option value="">All domains</option>
              {connections.filter((c) => c.enabled).map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                  {c.domains && c.domains.length > 0 ? ` (${c.domains.join(", ")})` : ""}
                </option>
              ))}
            </select>

            <div style={{ position: "relative", marginLeft: "auto" }}>
              <button
                data-testid="dashboard-gear"
                className="settings-gear-btn"
                onClick={() => setGearOpen(!gearOpen)}
                title="Panel Visibility"
                style={{ width: "32px", height: "32px" }}
              >
                <Cog size={16} />
              </button>
              {gearOpen && (
                <div
                  ref={gearPopoverRef}
                  style={{
                    position: "absolute",
                    top: "calc(100% + 8px)",
                    right: "0",
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--border-default)",
                    borderRadius: "var(--radius-md)",
                    padding: "6px",
                    boxShadow: "0 16px 48px rgba(0, 0, 0, 0.5), 0 0 0 1px var(--border-subtle)",
                    zIndex: 50,
                    minWidth: "260px",
                    maxHeight: "70vh",
                    overflowY: "auto",
                    animation: "scaleIn var(--duration-fast) var(--ease-out)",
                  }}
                >
                  <div style={{ fontSize: "10px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--text-muted)", padding: "8px 10px 4px" }}>
                    Metrics
                  </div>
                  {METRIC_ITEMS.map((p) => (
                    <PanelToggleRow key={p.key} item={p} on={visiblePanels.has(p.key)} onClick={() => togglePanel(p.key)} />
                  ))}
                  <div style={{ fontSize: "10px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--text-muted)", padding: "12px 10px 4px", borderTop: "1px solid var(--border-subtle)", marginTop: "2px" }}>
                    Panels
                  </div>
                  {PANEL_ITEMS.map((p) => (
                    <PanelToggleRow key={p.key} item={p} on={visiblePanels.has(p.key)} onClick={() => togglePanel(p.key)} />
                  ))}
                </div>
              )}
            </div>
          </div>

          <NativePanels hours={selectedHours} connectionId={connectionId} visiblePanels={visiblePanels} />
        </>
      )}

      {activeTab === "grafana" && (
        <GrafanaTab connections={connections} connectionId={connectionId} onConnectionChange={setConnectionId} />
      )}
    </div>
  );
}

function PanelToggleRow({
  item,
  on,
  onClick,
}: {
  item: { key: PanelKey; icon: React.ReactNode; label: string };
  on: boolean;
  onClick: () => void;
}) {
  return (
    <div className="checkbox-row" onClick={onClick} style={{ padding: "8px 10px", cursor: "pointer" }}>
      <div
        style={{
          width: "32px",
          height: "24px",
          borderRadius: "12px",
          background: on ? "var(--accent-1)" : "var(--border-strong)",
          position: "relative",
          transition: "background var(--duration-fast) var(--ease-out)",
          flexShrink: 0,
        }}
      >
        <div
          style={{
            position: "absolute",
            top: "2px",
            left: on ? "10px" : "2px",
            width: "20px",
            height: "20px",
            borderRadius: "50%",
            background: "#fff",
            transition: "left var(--duration-fast) var(--ease-out)",
            boxShadow: "0 1px 3px rgba(0,0,0,0.3)",
          }}
        />
      </div>
      <span style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "13px" }}>
        {item.icon}
        {item.label}
      </span>
    </div>
  );
}
