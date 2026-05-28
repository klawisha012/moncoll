import { createEffect, createSignal, createMemo, onCleanup, onMount, For, Show } from "solid-js";
import * as echarts from "echarts";
import {
  Cog,
  BarChart3,
  Globe,
  ShieldAlert,
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
} from "lucide-solid";
import { api } from "../api/client";
import type {
  Metrics,
  TrafficDataPoint,
  ThreatOrigin,
  SecurityEvent,
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
import { useSettings } from "../context/SettingsContext";
import { useGlobalFilters } from "../context/GlobalFiltersContext";
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
import { subscribe, type GeoipMapDelta } from "../realtime/client";


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
  | "securityEvents";

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
];

const METRIC_ITEMS: { key: PanelKey; icon: () => any; labelKey: string }[] = [
  { key: "metricTotalRequests", icon: () => <Gauge size={14} />, labelKey: "dashboard.metric.totalRequests" },
  { key: "metricBlockedThreats", icon: () => <ShieldOff size={14} />, labelKey: "dashboard.metric.blockedThreats" },
  { key: "metricAvgLatency", icon: () => <Clock size={14} />, labelKey: "dashboard.metric.avgLatency" },
  { key: "metricActiveRules", icon: () => <ScrollText size={14} />, labelKey: "dashboard.metric.activeRules" },
];

const PANEL_ITEMS: { key: PanelKey; icon: () => any; labelKey: string }[] = [
  { key: "trafficChart", icon: () => <BarChart3 size={14} />, labelKey: "dashboard.shortPanel.traffic" },
  { key: "wafEvents", icon: () => <Activity size={14} />, labelKey: "dashboard.shortPanel.events" },
  { key: "topRules", icon: () => <ShieldAlert size={14} />, labelKey: "dashboard.shortPanel.topRules" },
  { key: "severity", icon: () => <PieChart size={14} />, labelKey: "dashboard.shortPanel.severityDist" },
  { key: "topAttackers", icon: () => <Users size={14} />, labelKey: "dashboard.shortPanel.topAttackingIPs" },
  { key: "anomaly", icon: () => <AlertTriangle size={14} />, labelKey: "dashboard.shortPanel.anomaly" },
  { key: "threatOrigins", icon: () => <Globe size={14} />, labelKey: "dashboard.shortPanel.threatOrigins" },
  { key: "topTags", icon: () => <Tag size={14} />, labelKey: "dashboard.shortPanel.topTags" },
  { key: "topUris", icon: () => <Link size={14} />, labelKey: "dashboard.shortPanel.topUris" },
  { key: "topRuleFiles", icon: () => <FileCode size={14} />, labelKey: "dashboard.shortPanel.topFamilies" },
  { key: "statusCodes", icon: () => <TrendingUp size={14} />, labelKey: "dashboard.shortPanel.statusCodes" },
  { key: "topClientIps", icon: () => <HardDrive size={14} />, labelKey: "dashboard.shortPanel.topClientIPs" },
  { key: "topUserAgents", icon: () => <Bot size={14} />, labelKey: "dashboard.shortPanel.topUserAgents" },
  { key: "byCountry", icon: () => <Flag size={14} />, labelKey: "dashboard.shortPanel.byCountry" },
  { key: "trafficVolume", icon: () => <BarChart3 size={14} />, labelKey: "dashboard.shortPanel.bytesVolume" },
  { key: "rps", icon: () => <Zap size={14} />, labelKey: "dashboard.shortPanel.rps" },
  { key: "securityEvents", icon: () => <ShieldAlert size={14} />, labelKey: "dashboard.shortPanel.recentEvents" },
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

// No-flicker fetch hook: only the very first fetch (or one triggered by a
// deps change while we have no cached data) shows a spinner. Background
// refreshes are silent — the previous data stays on screen.
function useDashboardPanel<T>(
  fetcher: () => Promise<T>,
  deps: () => any,
  intervalMs: number | null = 15_000,
  enabled: () => boolean = () => true,
): { data: () => T | null; setData: (v: T) => void; initialLoading: () => boolean; error: () => string | null } {
  const [data, setData] = createSignal<T | null>(null);
  const [initialLoading, setInitialLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    if (!enabled()) return;
    deps(); // track dependencies reactively

    let cancelled = false;

    const run = async () => {
      try {
        const result = await fetcher();
        if (cancelled) return;
        setData(() => result);
        setError(null);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to load");
      } finally {
        if (!cancelled) setInitialLoading(false);
      }
    };

    run();
    
    let id: any = null;
    if (intervalMs !== null && intervalMs > 0) {
      id = setInterval(run, intervalMs);
    }
    
    onCleanup(() => {
      cancelled = true;
      if (id !== null) clearInterval(id);
    });
  });

  const customSetData = (val: T) => {
    setData(() => val);
    setInitialLoading(false);
  };

  return { data, setData: customSetData, initialLoading, error };
}

function PanelCard(props: {
  title: string;
  icon?: any;
  children: any;
  style?: any;
  headerActions?: any;
}) {
  return (
    <div class="card" style={{ "margin-bottom": "16px", ...props.style }}>
      <div class="card-header" style={{ display: "flex", "align-items": "center", "justify-content": "space-between", gap: "8px" }}>
        <div style={{ display: "flex", "align-items": "center", gap: "8px" }}>
          {props.icon}
          <h2 style={{ "font-size": "15px", margin: "0" }}>{props.title}</h2>
        </div>
        {props.headerActions}
      </div>
      <div style={{ padding: "8px 4px" }}>{props.children}</div>
    </div>
  );
}

function TimelineSeriesInner(props: {
  data: { timestamp: string }[];
  loading: boolean;
  valueOf: (d: { timestamp: string }) => number;
  color: string;
  unit?: "count" | "bytes" | "rps";
  valueLabel?: string;
  type?: "line" | "bar";
}) {
  const settings = useSettings();
  let chartRef: HTMLDivElement | undefined;
  let chart: echarts.ECharts | undefined;

  const fmt = (v: number) => {
    if (props.unit === "bytes") return formatBytes(v);
    if (props.unit === "rps") {
      if (v === 0) return "0 rps";
      const formatted = v < 0.1 ? v.toFixed(3) : v.toFixed(2);
      return `${parseFloat(formatted)} rps`;
    }
    return formatNumber(Math.round(v));
  };

  const categories = () => props.data.map((d) => {
    if (!d.timestamp) return "";
    const dateObj = new Date(d.timestamp);
    return isNaN(dateObj.getTime()) ? String(d.timestamp) : dateObj.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  });

  const seriesData = () => props.data.map((d) => props.valueOf(d));

  onMount(() => {
    if (!chartRef) return;
    chart = echarts.init(chartRef);

    const handleResize = () => {
      chart?.resize();
    };
    window.addEventListener("resize", handleResize);

    onCleanup(() => {
      window.removeEventListener("resize", handleResize);
      chart?.dispose();
    });
  });

  createEffect(() => {
    if (!chart) return;

    const theme = settings.theme;
    const isDark = theme === "dark";

    const option: echarts.EChartsOption = {
      grid: {
        top: 20,
        left: 55,
        right: 15,
        bottom: 25,
        containLabel: false
      },
      tooltip: {
        trigger: "axis",
        backgroundColor: isDark ? "#1a1915" : "#fdfcf7",
        borderColor: "var(--border-subtle)",
        borderWidth: 1,
        textStyle: {
          color: "var(--text-primary)",
          fontFamily: "var(--font-body)",
          fontSize: 12
        },
        shadowColor: "rgba(0, 0, 0, 0.2)",
        shadowBlur: 10,
        padding: 10,
        formatter: (params: any) => {
          if (!params || params.length === 0) return "";
          const idx = params[0].dataIndex;
          const item = props.data[idx];
          if (!item) return "";
          const val = props.valueOf(item);
          const formattedDate = item.timestamp && !isNaN(new Date(item.timestamp).getTime())
            ? new Date(item.timestamp).toLocaleString([], {
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              })
            : "";

          return `
            <div style="font-family: var(--font-body); min-width: 160px;">
              <div style="font-weight: 600; margin-bottom: 6px; font-size: 12px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 4px;">
                ${formattedDate}
              </div>
              <div style="font-size: 11px; display: flex; flex-direction: column; gap: 4px;">
                <div style="display: flex; justify-content: space-between; gap: 12px; align-items: center;">
                  <span style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: ${props.color}; display: inline-block;"></span>
                    ${props.valueLabel ?? "Value"}:
                  </span>
                  <span style="font-family: var(--font-mono); font-weight: 600;">${fmt(val)}</span>
                </div>
              </div>
            </div>
          `;
        }
      },
      xAxis: {
        type: "category",
        data: categories(),
        axisLine: {
          lineStyle: {
            color: "var(--border-subtle)",
            width: 1
          }
        },
        axisLabel: {
          color: "var(--text-secondary)",
          fontFamily: "var(--font-body)",
          fontSize: 10
        },
        boundaryGap: props.type === "bar"
      },
      yAxis: {
        type: "value",
        minInterval: props.unit === "rps" ? 0 : 1,
        axisLine: { show: false },
        splitLine: {
          lineStyle: {
            color: "var(--border-subtle)",
            type: "dashed"
          }
        },
        axisLabel: {
          color: "var(--text-secondary)",
          fontFamily: "var(--font-body)",
          fontSize: 10,
          formatter: (v: number) => fmt(v)
        }
      },
      series: [
        props.type === "bar"
          ? {
              type: "bar",
              color: props.color,
              barWidth: "60%",
              itemStyle: {
                borderRadius: [2, 2, 0, 0]
              },
              data: seriesData()
            }
          : {
              type: "line",
              smooth: true,
              showSymbol: false,
              color: props.color,
              lineStyle: {
                width: 2.5,
                color: props.color
              },
              areaStyle: {
                color: {
                  type: "linear",
                  x: 0,
                  y: 0,
                  x2: 0,
                  y2: 1,
                  colorStops: [
                    { offset: 0, color: props.color + "59" },
                    { offset: 1, color: "transparent" }
                  ]
                }
              },
              data: seriesData()
            }
      ]
    };

    chart.setOption(option);
  });

  return (
    <div ref={chartRef} style={{ width: "100%", height: "280px" }} />
  );
}

function TimelineSeries(props: {
  data: { timestamp: string }[] | null;
  loading: boolean;
  valueOf: (d: { timestamp: string }) => number;
  color: string;
  unit?: "count" | "bytes" | "rps";
  valueLabel?: string;
  type?: "line" | "bar";
}) {
  const settings = useSettings();
  return (
    <Show when={props.data && props.data.length > 0} fallback={<EmptyState loading={props.loading} message={settings.t("dashboard.empty.noData")} />}>
      <TimelineSeriesInner {...props} data={props.data!} />
    </Show>
  );
}

const STATUS_COLORS = {
  c2xx: "#10b981",
  c3xx: "#3b82f6",
  c4xx: "#f59e0b",
  c5xx: "#ef4444",
} as const;

const STATUS_KEYS = ["c2xx", "c3xx", "c4xx", "c5xx"] as const;
type StatusKey = (typeof STATUS_KEYS)[number];

function StatusCodesChartInner(props: { data: StatusCodePoint[]; loading: boolean }) {
  const settings = useSettings();
  let chartRef: HTMLDivElement | undefined;
  let chart: echarts.ECharts | undefined;

  const categories = () => props.data.map((d) => {
    if (!d.timestamp) return "";
    const dateObj = new Date(d.timestamp);
    return isNaN(dateObj.getTime()) ? String(d.timestamp) : dateObj.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  });

  const c2xxData = () => props.data.map((d) => d.c2xx ?? 0);
  const c3xxData = () => props.data.map((d) => d.c3xx ?? 0);
  const c4xxData = () => props.data.map((d) => d.c4xx ?? 0);
  const c5xxData = () => props.data.map((d) => d.c5xx ?? 0);

  onMount(() => {
    if (!chartRef) return;
    chart = echarts.init(chartRef);

    const handleResize = () => {
      chart?.resize();
    };
    window.addEventListener("resize", handleResize);

    onCleanup(() => {
      window.removeEventListener("resize", handleResize);
      chart?.dispose();
    });
  });

  createEffect(() => {
    if (!chart) return;

    const theme = settings.theme;
    const isDark = theme === "dark";

    const option: echarts.EChartsOption = {
      grid: {
        top: 30,
        left: 55,
        right: 15,
        bottom: 25,
        containLabel: false
      },
      tooltip: {
        trigger: "axis",
        backgroundColor: isDark ? "#1a1915" : "#fdfcf7",
        borderColor: "var(--border-subtle)",
        borderWidth: 1,
        textStyle: {
          color: "var(--text-primary)",
          fontFamily: "var(--font-body)",
          fontSize: 12
        },
        shadowColor: "rgba(0, 0, 0, 0.2)",
        shadowBlur: 10,
        padding: 10,
        formatter: (params: any) => {
          if (!params || params.length === 0) return "";
          const idx = params[0].dataIndex;
          const item = props.data[idx];
          if (!item) return "";

          const c2 = item.c2xx ?? 0;
          const c3 = item.c3xx ?? 0;
          const c4 = item.c4xx ?? 0;
          const c5 = item.c5xx ?? 0;
          const total = c2 + c3 + c4 + c5;

          const formattedDate = item.timestamp && !isNaN(new Date(item.timestamp).getTime())
            ? new Date(item.timestamp).toLocaleString([], {
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              })
            : "";

          return `
            <div style="font-family: var(--font-body); min-width: 180px;">
              <div style="font-weight: 600; margin-bottom: 6px; font-size: 12px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 4px;">
                ${formattedDate}
              </div>
              <div style="font-size: 11px; display: flex; flex-direction: column; gap: 4px;">
                <div style="display: flex; justify-content: space-between; gap: 12px; align-items: center;">
                  <span style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: ${STATUS_COLORS.c2xx}; display: inline-block;"></span>
                    2xx:
                  </span>
                  <span style="font-family: var(--font-mono); font-weight: 500;">${c2.toLocaleString()}</span>
                </div>
                <div style="display: flex; justify-content: space-between; gap: 12px; align-items: center;">
                  <span style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: ${STATUS_COLORS.c3xx}; display: inline-block;"></span>
                    3xx:
                  </span>
                  <span style="font-family: var(--font-mono); font-weight: 500;">${c3.toLocaleString()}</span>
                </div>
                <div style="display: flex; justify-content: space-between; gap: 12px; align-items: center;">
                  <span style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: ${STATUS_COLORS.c4xx}; display: inline-block;"></span>
                    4xx:
                  </span>
                  <span style="font-family: var(--font-mono); font-weight: 500;">${c4.toLocaleString()}</span>
                </div>
                <div style="display: flex; justify-content: space-between; gap: 12px; align-items: center;">
                  <span style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: ${STATUS_COLORS.c5xx}; display: inline-block;"></span>
                    5xx:
                  </span>
                  <span style="font-family: var(--font-mono); font-weight: 500;">${c5.toLocaleString()}</span>
                </div>
                <div style="display: flex; justify-content: space-between; gap: 12px; border-top: 1px dashed var(--border-subtle); margin-top: 4px; padding-top: 4px; align-items: center;">
                  <span>Total:</span>
                  <span style="font-family: var(--font-mono); font-weight: 600;">${total.toLocaleString()}</span>
                </div>
              </div>
            </div>
          `;
        }
      },
      legend: {
        show: true,
        left: "left",
        top: 0,
        textStyle: {
          color: "var(--text-secondary)",
          fontFamily: "var(--font-mono)",
          fontSize: 11
        },
        itemWidth: 10,
        itemHeight: 10,
        icon: "rect"
      },
      xAxis: {
        type: "category",
        data: categories(),
        axisLine: {
          lineStyle: {
            color: "var(--border-subtle)",
            width: 1
          }
        },
        axisLabel: {
          color: "var(--text-secondary)",
          fontFamily: "var(--font-body)",
          fontSize: 10
        },
        boundaryGap: true
      },
      yAxis: {
        type: "value",
        axisLine: { show: false },
        splitLine: {
          lineStyle: {
            color: "var(--border-subtle)",
            type: "dashed"
          }
        },
        axisLabel: {
          color: "var(--text-secondary)",
          fontFamily: "var(--font-body)",
          fontSize: 10,
          formatter: (v: number) => formatNumber(Math.round(v))
        }
      },
      series: [
        {
          name: "2xx",
          type: "bar",
          stack: "status",
          color: STATUS_COLORS.c2xx,
          barWidth: "60%",
          data: c2xxData()
        },
        {
          name: "3xx",
          type: "bar",
          stack: "status",
          color: STATUS_COLORS.c3xx,
          barWidth: "60%",
          data: c3xxData()
        },
        {
          name: "4xx",
          type: "bar",
          stack: "status",
          color: STATUS_COLORS.c4xx,
          barWidth: "60%",
          data: c4xxData()
        },
        {
          name: "5xx",
          type: "bar",
          stack: "status",
          color: STATUS_COLORS.c5xx,
          barWidth: "60%",
          itemStyle: {
            borderRadius: [2, 2, 0, 0]
          },
          data: c5xxData()
        }
      ]
    };

    chart.setOption(option);
  });

  return (
    <div ref={chartRef} style={{ width: "100%", height: "300px" }} />
  );
}

function StatusCodesChart(props: { data: StatusCodePoint[] | null; loading: boolean }) {
  const settings = useSettings();
  return (
    <Show when={props.data && props.data.length > 0} fallback={<EmptyState loading={props.loading} message={settings.t("dashboard.empty.noStatusData")} />}>
      <StatusCodesChartInner data={props.data!} loading={props.loading} />
    </Show>
  );
}

function HorizontalBars(props: {
  data: unknown[] | null;
  loading: boolean;
  labelOf: (d: any) => string;
  valueOf: (d: any) => number;
  gradient?: string;
  valueLabel?: string;
}) {
  const settings = useSettings();
  const [hoverRow, setHoverRow] = createSignal<number | null>(null);
  let wrapRef: HTMLDivElement | undefined;
  const [pos, setPos] = createSignal<{ x: number; y: number; containerW: number } | null>(null);

  const safeData = () => props.data ?? [];
  const resolvedValueLabel = () => props.valueLabel ?? settings.t("dashboard.tooltip.hits");
  const maxVal = () => Math.max(...safeData().map((d) => props.valueOf(d)), 1);
  const total = () => safeData().reduce<number>((a, d) => a + props.valueOf(d), 0);

  const onRowMove = (e: MouseEvent, idx: number) => {
    const wrap = wrapRef;
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    setHoverRow(idx);
    setPos({ x: e.clientX - rect.left, y: e.clientY - rect.top, containerW: rect.width });
  };

  const hovered = () => {
    const idx = hoverRow();
    return idx !== null ? safeData()[idx] : null;
  };

  return (
    <Show when={props.data && props.data.length > 0} fallback={<EmptyState loading={props.loading} message={settings.t("dashboard.empty.noDataShort")} />}>
      <div
        ref={wrapRef}
        style={{ display: "flex", "flex-direction": "column", gap: "6px", padding: "4px 8px", position: "relative" }}
        onMouseLeave={() => {
          setHoverRow(null);
          setPos(null);
        }}
      >
        <For each={safeData()}>
          {(d, i) => {
            const label = props.labelOf(d);
            const val = props.valueOf(d);
            const isHover = () => hoverRow() === i();
            return (
              <div
                onMouseMove={(e) => onRowMove(e, i())}
                style={{
                  display: "flex",
                  "align-items": "center",
                  gap: "10px",
                  "min-height": "26px",
                  cursor: "default",
                  filter: isHover() ? "brightness(1.12)" : undefined,
                  transition: "filter var(--duration-fast) var(--ease-out)",
                }}
              >
                <span
                  style={{
                    width: "180px",
                    "font-size": "12px",
                    "font-family": "monospace",
                    color: "var(--text-secondary)",
                    "white-space": "nowrap",
                    overflow: "hidden",
                    "text-overflow": "ellipsis",
                    "flex-shrink": 0,
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
                    "border-radius": "3px",
                    overflow: "hidden",
                    position: "relative",
                    outline: isHover() ? "1px solid var(--ink)" : undefined,
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      width: `${(val / maxVal()) * 100}%`,
                      background: props.gradient ?? "linear-gradient(90deg, var(--accent-1), var(--accent-2))",
                      "border-radius": "3px",
                      display: "flex",
                      "align-items": "center",
                      "padding-left": "8px",
                    }}
                  >
                    <span style={{ "font-size": "11px", "font-weight": 600, color: "#fff", "white-space": "nowrap" }}>
                      {formatNumber(val)}
                    </span>
                  </div>
                </div>
              </div>
            );
          }}
        </For>
        <Show when={hovered() !== null && hoverRow() !== null && pos()}>
          <ChartTooltip
            x={pos()!.x}
            y={pos()!.y}
            containerWidth={pos()!.containerW}
            title={props.labelOf(hovered()!)}
            rows={[
              { label: resolvedValueLabel(), value: props.valueOf(hovered()!).toLocaleString() },
              {
                label: settings.t("dashboard.tooltip.shareTop"),
                value: total() > 0 ? `${((props.valueOf(hovered()!) / total()) * 100).toFixed(1)}%` : "—",
              },
              { label: settings.t("dashboard.tooltip.rank"), value: `#${hoverRow()! + 1} of ${safeData().length}` },
            ]}
          />
        </Show>
      </div>
    </Show>
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

function SeverityDonutInner(props: { data: SeveritySlice[]; loading: boolean }) {
  const settings = useSettings();
  const [hoverSeverity, setHoverSeverity] = createSignal<string | null>(null);

  const activeData = () => props.data.filter(s => s.hits > 0);
  const totalHits = () => activeData().reduce((sum, s) => sum + s.hits, 0);

  const slices = createMemo(() => {
    const list = activeData();
    const total = totalHits();
    return list.map((item) => ({
      ...item,
      percentage: total > 0 ? item.hits / total : 0
    }));
  });

  let chartRef: HTMLDivElement | undefined;
  let chart: echarts.ECharts | undefined;

  onMount(() => {
    if (!chartRef) return;
    chart = echarts.init(chartRef);

    const handleResize = () => {
      chart?.resize();
    };
    window.addEventListener("resize", handleResize);

    chart.on("mouseover", (params) => {
      if (params.seriesType === "pie") {
        setHoverSeverity(params.name);
      }
    });

    chart.on("mouseout", () => {
      setHoverSeverity(null);
    });

    onCleanup(() => {
      window.removeEventListener("resize", handleResize);
      chart?.dispose();
    });
  });

  createEffect(() => {
    if (!chart) return;

    const dataPoints = slices().map((s) => ({
      name: s.severity,
      value: s.hits,
      itemStyle: {
        color: SEVERITY_COLORS[s.severity] || "#888"
      }
    }));

    const option: echarts.EChartsOption = {
      tooltip: {
        show: false
      },
      series: [
        {
          name: "Severity",
          type: "pie",
          radius: ["55%", "72%"],
          center: ["50%", "50%"],
          avoidLabelOverlap: false,
          label: {
            show: false
          },
          emphasis: {
            scale: true,
            scaleSize: 8,
            itemStyle: {
              shadowBlur: 10,
              shadowOffsetX: 0,
              shadowColor: "rgba(0, 0, 0, 0.5)"
            }
          },
          labelLine: {
            show: false
          },
          data: dataPoints
        }
      ]
    };

    chart.setOption(option);
  });

  createEffect(() => {
    if (!chart) return;
    const hovered = hoverSeverity();
    if (hovered) {
      chart.dispatchAction({
        type: "highlight",
        seriesIndex: 0,
        name: hovered
      });
    } else {
      chart.dispatchAction({
        type: "downplay",
        seriesIndex: 0
      });
    }
  });

  return (
    <div style={{ display: "flex", "align-items": "center", gap: "24px", width: "100%", "justify-content": "center", "flex-wrap": "wrap", padding: "12px 8px" }} class="solid-donut-chart-wrapper">
      <div style={{ width: "180px", height: "180px", "position": "relative", "flex-shrink": 0 }}>
        <div ref={chartRef} style={{ width: "100%", height: "100%" }} />
        
        {/* Center Text displaying Stats */}
        <div style={{
          position: "absolute",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
          "text-align": "center",
          "pointer-events": "none",
          display: "flex",
          "flex-direction": "column",
          "align-items": "center",
          "justify-content": "center"
        }}>
          <div style={{
            "font-family": "var(--font-mono)",
            "font-size": "10px",
            "font-weight": "500",
            "letter-spacing": "0.1em",
            color: "var(--text-muted)",
            "text-transform": "uppercase"
          }}>
            TOTAL
          </div>
          <div style={{
            "font-family": "var(--font-display)",
            "font-size": "22px",
            "font-weight": "700",
            color: "var(--text-primary)",
            "margin-top": "2px"
          }}>
            {formatNumber(totalHits())}
          </div>
        </div>
      </div>

      <div style={{ display: "flex", "flex-direction": "column", gap: "6px", "flex-grow": 1, "min-width": "180px" }}>
        <For each={slices()}>
          {(slice) => {
            const color = SEVERITY_COLORS[slice.severity] || "#888";
            const isHovered = () => hoverSeverity() === slice.severity;
            return (
              <div
                style={{
                  display: "flex",
                  "align-items": "center",
                  "justify-content": "space-between",
                  padding: "4px 8px",
                  "border-radius": "4px",
                  background: isHovered() ? "var(--bg-elevated)" : "transparent",
                  cursor: "pointer",
                  transition: "background var(--duration-fast) var(--ease-out)",
                }}
                onMouseEnter={() => setHoverSeverity(slice.severity)}
                onMouseLeave={() => setHoverSeverity(null)}
              >
                <span style={{ display: "flex", "align-items": "center", gap: "8px", "font-family": "var(--font-mono)", "font-size": "11px", color: "var(--text-secondary)" }}>
                  <span style={{ width: "8px", height: "8px", "border-radius": "50%", background: color, display: "inline-block", "box-shadow": isHovered() ? `0 0 6px ${color}` : "none" }}></span>
                  {slice.severity}
                </span>
                <span style={{ "font-family": "var(--font-mono)", "font-size": "11px", "font-weight": "600", color: "var(--text-primary)" }}>
                  {formatNumber(slice.hits)} ({(slice.percentage * 100).toFixed(1)}%)
                </span>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}

function SeverityDonut(props: { data: SeveritySlice[] | null; loading: boolean }) {
  const settings = useSettings();
  const safeData = () => props.data ?? [];
  return (
    <Show when={props.data && props.data.length > 0 && safeData().some(s => s.hits > 0)} fallback={<EmptyState loading={props.loading} message={settings.t("dashboard.empty.noSeverityData")} />}>
      <SeverityDonutInner data={props.data!} loading={props.loading} />
    </Show>
  );
}

function ThreatOriginsChart(props: { data: ThreatOrigin[] | null; loading: boolean }) {
  const settings = useSettings();
  const [hoverRow, setHoverRow] = createSignal<number | null>(null);
  let wrapRef: HTMLDivElement | undefined;
  const [pos, setPos] = createSignal<{ x: number; y: number; containerW: number } | null>(null);

  const safeData = () => props.data ?? [];
  const maxPct = () => Math.max(...safeData().map((d) => d.blocks_percent), 1);
  const totalPct = () => safeData().reduce<number>((a, d) => a + d.blocks_percent, 0);

  const onMove = (e: MouseEvent, idx: number) => {
    const wrap = wrapRef;
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    setHoverRow(idx);
    setPos({ x: e.clientX - rect.left, y: e.clientY - rect.top, containerW: rect.width });
  };

  const hovered = () => {
    const idx = hoverRow();
    return idx !== null ? safeData()[idx] : null;
  };

  return (
    <Show when={props.data && props.data.length > 0} fallback={<EmptyState loading={props.loading} message={settings.t("dashboard.empty.noThreatData")} />}>
      <div
        ref={wrapRef}
        style={{ display: "flex", "flex-direction": "column", gap: "8px", padding: "8px", position: "relative" }}
        onMouseLeave={() => {
          setHoverRow(null);
          setPos(null);
        }}
      >
        <For each={safeData()}>
          {(d, i) => {
            const isHover = () => hoverRow() === i();
            return (
              <div
                onMouseMove={(e) => onMove(e, i())}
                style={{
                  display: "flex",
                  "align-items": "center",
                  gap: "12px",
                  height: "26px",
                  filter: isHover() ? "brightness(1.12)" : undefined,
                  transition: "filter var(--duration-fast) var(--ease-out)",
                }}
              >
                <span style={{ width: "44px", "font-size": "12px", "font-weight": 600, color: "var(--text-secondary)", "text-align": "right", "flex-shrink": 0 }}>
                  {d.country_code}
                </span>
                <div
                  style={{
                    flex: 1,
                    height: "100%",
                    background: "var(--bg-elevated)",
                    "border-radius": "3px",
                    overflow: "hidden",
                    outline: isHover() ? "1px solid var(--ink)" : undefined,
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      width: `${(d.blocks_percent / maxPct()) * 100}%`,
                      background: "linear-gradient(90deg, var(--danger), var(--accent-2))",
                      "border-radius": "3px",
                      display: "flex",
                      "align-items": "center",
                      "padding-left": "10px",
                    }}
                  >
                    <span style={{ "font-size": "11px", "font-weight": 600, color: "#fff", "white-space": "nowrap" }}>
                      {d.blocks_percent}%
                    </span>
                  </div>
                </div>
              </div>
            );
          }}
        </For>
        <Show when={hovered() && hoverRow() !== null && pos()}>
          <ChartTooltip
            x={pos()!.x}
            y={pos()!.y}
            containerWidth={pos()!.containerW}
            title={hovered()!.country || hovered()!.country_code}
            rows={[
              { label: settings.t("dashboard.tooltip.countryCode"), value: hovered()!.country_code },
              { label: settings.t("dashboard.tooltip.blockShare"), value: `${hovered()!.blocks_percent}%` },
              {
                label: settings.t("dashboard.tooltip.ofTopN"),
                value: totalPct() > 0 ? `${((hovered()!.blocks_percent / totalPct()) * 100).toFixed(1)}%` : "—",
              },
              { label: settings.t("dashboard.tooltip.rank"), value: `#${hoverRow()! + 1} of ${safeData().length}` },
            ]}
          />
        </Show>
      </div>
    </Show>
  );
}

function EventsTable(props: { data: SecurityEvent[] | null; loading: boolean }) {
  const settings = useSettings();
  const severityColors: Record<string, string> = {
    critical: "var(--danger)",
    high: "var(--danger)",
    medium: "var(--warning)",
    low: "var(--info)",
    info: "var(--text-muted)",
  };

  return (
    <Show when={props.data && props.data.length > 0} fallback={<EmptyState loading={props.loading} message={settings.t("dashboard.empty.noEvents")} />}>
      <div class="table-wrapper" style={{ "max-height": "360px", "overflow-y": "auto" }}>
        <table>
          <thead>
            <tr>
              <th>{settings.t("dashboard.table.time")}</th>
              <th>{settings.t("dashboard.table.rule")}</th>
              <th>{settings.t("dashboard.table.ip")}</th>
              <th>{settings.t("dashboard.table.path")}</th>
              <th>{settings.t("dashboard.table.severity")}</th>
            </tr>
          </thead>
          <tbody>
            <For each={props.data}>
              {(e) => (
                <tr>
                  <td style={{ "white-space": "nowrap", "font-size": "12px" }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td style={{ "font-size": "12px", "font-family": "monospace" }}>{injectionLabel(e.type)}</td>
                  <td style={{ "font-size": "12px", "font-family": "monospace" }}>{e.ip}</td>
                  <td style={{ "font-size": "12px", "font-family": "monospace", "max-width": "320px", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>
                    {e.path}
                  </td>
                  <td>
                    <span
                      class="badge"
                      style={{
                        background: `${severityColors[e.severity] || "var(--text-muted)"}22`,
                        color: severityColors[e.severity] || "var(--text-muted)",
                        "font-size": "11px",
                      }}
                    >
                      {e.severity}
                    </span>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>
    </Show>
  );
}

function NativePanels(props: {
  hours: number;
  connectionId: number | null;
  visiblePanels: Set<PanelKey>;
}) {
  const settings = useSettings();
  const [refreshTick, setRefreshTick] = createSignal(0);
  const deps = () => [props.hours, props.connectionId, refreshTick()] as [number, number | null, number];

  onMount(() => {
    let lastRefresh = 0;
    const unsubMap = subscribe<GeoipMapDelta>("dashboard:map", (delta) => {
      const now = Date.now();
      // Throttle refreshes to maximum once every 3 seconds to avoid overloading ClickHouse/FastAPI
      if (now - lastRefresh >= 3000) {
        lastRefresh = now;
        setRefreshTick((t) => t + 1);
      }
    });
    onCleanup(() => unsubMap());
  });

  const metrics = useDashboardPanel<Metrics>(
    () => api.getMetrics(props.hours, props.connectionId),
    deps,
    15_000, // Enable safe, tenant-scoped HTTP polling
    () => props.visiblePanels.has("metricTotalRequests") ||
      props.visiblePanels.has("metricBlockedThreats") ||
      props.visiblePanels.has("metricAvgLatency") ||
      props.visiblePanels.has("metricActiveRules"),
  );
  const traffic = useDashboardPanel<TrafficDataPoint[]>(
    () => api.getTraffic(props.hours, props.connectionId),
    deps,
    15_000, // Enable safe, tenant-scoped HTTP polling
    () => props.visiblePanels.has("trafficChart")
  );
  const wafEvents = useDashboardPanel<TimelinePoint[]>(() => api.getWafEventsTimeline(props.hours, props.connectionId), deps, 15_000, () => props.visiblePanels.has("wafEvents"));
  const topRules = useDashboardPanel<RuleHit[]>(() => api.getTopRules(props.hours, props.connectionId), deps, 30_000, () => props.visiblePanels.has("topRules"));
  const severity = useDashboardPanel<SeveritySlice[]>(() => api.getSeverityDistribution(props.hours, props.connectionId), deps, 30_000, () => props.visiblePanels.has("severity"));
  const topAttackers = useDashboardPanel<IpHit[]>(() => api.getTopAttackingIps(props.hours, props.connectionId), deps, 30_000, () => props.visiblePanels.has("topAttackers"));
  const anomaly = useDashboardPanel<AnomalyPoint[]>(() => api.getAnomalyScore(props.hours, props.connectionId), deps, 15_000, () => props.visiblePanels.has("anomaly"));
  const threatOrigins = useDashboardPanel<ThreatOrigin[]>(() => api.getThreatOrigins(props.hours, props.connectionId), deps, 30_000, () => props.visiblePanels.has("threatOrigins"));
  const topTags = useDashboardPanel<TagHit[]>(() => api.getTopTags(props.hours, props.connectionId), deps, 30_000, () => props.visiblePanels.has("topTags"));
  const topUris = useDashboardPanel<UriHit[]>(() => api.getTopUris(props.hours, props.connectionId), deps, 30_000, () => props.visiblePanels.has("topUris"));
  const topRuleFiles = useDashboardPanel<RuleFileHit[]>(() => api.getTopRuleFiles(props.hours, props.connectionId), deps, 30_000, () => props.visiblePanels.has("topRuleFiles"));
  const statusCodes = useDashboardPanel<StatusCodePoint[]>(() => api.getStatusCodes(props.hours, props.connectionId), deps, 15_000, () => props.visiblePanels.has("statusCodes"));
  const topClientIps = useDashboardPanel<IpHit[]>(() => api.getTopClientIps(props.hours, props.connectionId), deps, 30_000, () => props.visiblePanels.has("topClientIps"));
  const topUserAgents = useDashboardPanel<UserAgentHit[]>(() => api.getTopUserAgents(props.hours, props.connectionId), deps, 30_000, () => props.visiblePanels.has("topUserAgents"));
  const byCountry = useDashboardPanel<CountryHit[]>(() => api.getRequestsByCountry(props.hours, props.connectionId), deps, 30_000, () => props.visiblePanels.has("byCountry"));
  const trafficVolume = useDashboardPanel<BytesPoint[]>(() => api.getTrafficVolume(props.hours, props.connectionId), deps, 15_000, () => props.visiblePanels.has("trafficVolume"));
  const [rpsMetric, setRpsMetric] = createSignal<"rps" | "volume">("rps");
  const rpsDeps = () => [props.hours, props.connectionId, rpsMetric()] as [number, number | null, "rps" | "volume"];
  const rps = useDashboardPanel<RpsPoint[]>(
    () => api.getRequestsPerSecond(props.hours, props.connectionId, rpsMetric()),
    rpsDeps,
    15_000,
    () => props.visiblePanels.has("rps")
  );
  const events = useDashboardPanel<SecurityEvent[]>(
    () => api.getEvents(15, "all", props.hours, props.connectionId),
    deps,
    15_000,
    () => props.visiblePanels.has("securityEvents"),
  );

  const m = () => metrics.data();

  return (
    <>
      <Show when={props.visiblePanels.has("metricTotalRequests") ||
        props.visiblePanels.has("metricBlockedThreats") ||
        props.visiblePanels.has("metricAvgLatency") ||
        props.visiblePanels.has("metricActiveRules")}>
        <div class="metrics-grid" data-testid="metrics-row">
          <Show when={props.visiblePanels.has("metricTotalRequests")}>
            <div
              class="metric-card"
              title="Все HTTP-запросы, прошедшие через Angie за выбранный период. Под значением — изменение относительно предыдущего такого же окна."
            >
              <div class="metric-icon indigo">
                <Gauge size={18} />
              </div>
              <div class="metric-label">{settings.t("dashboard.metric.totalRequests")}</div>
              <div class="metric-value">{m() ? formatNumber(m()!.total_requests) : metrics.initialLoading() ? "…" : "—"}</div>
              <div class={`metric-change ${(m()?.total_requests_change ?? 0) >= 0 ? "up" : "down"}`}>
                {m() ? `${m()!.total_requests_change >= 0 ? "+" : ""}${m()!.total_requests_change}% ${settings.t("dashboard.metric.vsPrevious")}` : "—"}
              </div>
            </div>
          </Show>
          <Show when={props.visiblePanels.has("metricBlockedThreats")}>
            <div
              class="metric-card"
              title="Сколько запросов ModSecurity заблокировал по правилам CRS. Под значением — число событий high+critical severity."
            >
              <div class="metric-icon rose">
                <ShieldOff size={18} />
              </div>
              <div class="metric-label">{settings.t("dashboard.metric.blockedThreats")}</div>
              <div class="metric-value">{m() ? formatNumber(m()!.blocked_threats) : metrics.initialLoading() ? "…" : "—"}</div>
              <div class="metric-change down">{m() ? `${m()!.high_severity_count} ${settings.t("dashboard.metric.highSeverity")}` : settings.t("dashboard.metric.monitoredByWaf")}</div>
            </div>
          </Show>
          <Show when={props.visiblePanels.has("metricAvgLatency")}>
            <div
              class="metric-card"
              title="Средняя задержка ответа upstream (request_time) за период. Health % — обобщённый показатель состояния стека (Angie+ModSec+CrowdSec)."
            >
              <div class="metric-icon violet">
                <Clock size={18} />
              </div>
              <div class="metric-label">{settings.t("dashboard.metric.avgLatency")}</div>
              <div class="metric-value">{m() ? `${m()!.avg_latency_ms.toFixed(1)} ms` : metrics.initialLoading() ? "…" : "—"}</div>
              <div class="metric-change up">{m() ? `Health ${m()!.system_health}%` : settings.t("dashboard.metric.performance")}</div>
            </div>
          </Show>
          <Show when={props.visiblePanels.has("metricActiveRules")}>
            <div
              class="metric-card"
              title="Количество загруженных правил OWASP CRS в ModSecurity, готовых отрабатывать на трафике."
            >
              <div class="metric-icon emerald">
                <ScrollText size={18} />
              </div>
              <div class="metric-label">{settings.t("dashboard.metric.activeRules")}</div>
              <div class="metric-value">{m() ? m()!.active_rules.toLocaleString() : metrics.initialLoading() ? "…" : "—"}</div>
              <div class="metric-change up">{settings.t("dashboard.metric.crsProtection")}</div>
            </div>
          </Show>
        </div>
      </Show>

      <Show when={props.visiblePanels.has("trafficChart")}>
        <PanelCard title={settings.t("dashboard.panel.traffic")} icon={<BarChart3 size={16} />}>
          <TrafficChart data={traffic.data()} loading={traffic.initialLoading()} />
        </PanelCard>
      </Show>

      <Show when={props.visiblePanels.has("wafEvents")}>
        <PanelCard title={settings.t("dashboard.panel.events")} icon={<Activity size={16} />}>
          <TimelineSeries
            data={wafEvents.data()}
            loading={wafEvents.initialLoading()}
            valueOf={(d) => (d as TimelinePoint).hits}
            color="#ef4444"
            valueLabel={settings.t("dashboard.tooltip.wafEvents")}
          />
        </PanelCard>
      </Show>

      <Show when={props.visiblePanels.has("topRules") || props.visiblePanels.has("severity")}>
        <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "16px", "margin-bottom": "16px" }}>
          <Show when={props.visiblePanels.has("topRules")}>
            <PanelCard title={settings.t("dashboard.panel.topRules")} icon={<ShieldAlert size={16} />} style={{ "margin-bottom": 0 }}>
              <HorizontalBars data={topRules.data()} loading={topRules.initialLoading()} labelOf={(d: RuleHit) => injectionLabel(d.rule)} valueOf={(d: RuleHit) => d.hits} />
            </PanelCard>
          </Show>
          <Show when={props.visiblePanels.has("severity")}>
            <PanelCard title={settings.t("dashboard.panel.severityDist")} icon={<PieChart size={16} />} style={{ "margin-bottom": 0 }}>
              <SeverityDonut data={severity.data()} loading={severity.initialLoading()} />
            </PanelCard>
          </Show>
        </div>
      </Show>

      <Show when={props.visiblePanels.has("topAttackers") || props.visiblePanels.has("anomaly")}>
        <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "16px", "margin-bottom": "16px" }}>
          <Show when={props.visiblePanels.has("topAttackers")}>
            <PanelCard title={settings.t("dashboard.panel.topAttackingIPs")} icon={<Users size={16} />} style={{ "margin-bottom": 0 }}>
              <HorizontalBars data={topAttackers.data()} loading={topAttackers.initialLoading()} labelOf={(d: IpHit) => d.ip} valueOf={(d: IpHit) => d.hits} gradient="linear-gradient(90deg, var(--danger), #f59e0b)" />
            </PanelCard>
          </Show>
          <Show when={props.visiblePanels.has("anomaly")}>
            <PanelCard title={settings.t("dashboard.panel.anomalyTimeline")} icon={<AlertTriangle size={16} />} style={{ "margin-bottom": 0 }}>
              <TimelineSeries
                data={anomaly.data()}
                loading={anomaly.initialLoading()}
                valueOf={(d) => (d as AnomalyPoint).score}
                color="#f97316"
                valueLabel={settings.t("dashboard.tooltip.anomalyScore")}
              />
            </PanelCard>
          </Show>
        </div>
      </Show>

      <Show when={props.visiblePanels.has("threatOrigins") || props.visiblePanels.has("topTags")}>
        <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "16px", "margin-bottom": "16px" }}>
          <Show when={props.visiblePanels.has("threatOrigins")}>
            <PanelCard title={settings.t("dashboard.panel.threatOrigins")} icon={<Globe size={16} />} style={{ "margin-bottom": 0 }}>
              <ThreatOriginsChart data={threatOrigins.data()} loading={threatOrigins.initialLoading()} />
            </PanelCard>
          </Show>
          <Show when={props.visiblePanels.has("topTags")}>
            <PanelCard title={settings.t("dashboard.panel.topTags")} icon={<Tag size={16} />} style={{ "margin-bottom": 0 }}>
              <HorizontalBars data={topTags.data()} loading={topTags.initialLoading()} labelOf={(d: TagHit) => d.tag} valueOf={(d: TagHit) => d.hits} gradient="linear-gradient(90deg, var(--accent-2), var(--accent-1))" />
            </PanelCard>
          </Show>
        </div>
      </Show>

      <Show when={props.visiblePanels.has("topUris") || props.visiblePanels.has("topRuleFiles")}>
        <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "16px", "margin-bottom": "16px" }}>
          <Show when={props.visiblePanels.has("topUris")}>
            <PanelCard title={settings.t("dashboard.panel.topUris")} icon={<Link size={16} />} style={{ "margin-bottom": 0 }}>
              <HorizontalBars data={topUris.data()} loading={topUris.initialLoading()} labelOf={(d: UriHit) => d.uri} valueOf={(d: UriHit) => d.hits} />
            </PanelCard>
          </Show>
          <Show when={props.visiblePanels.has("topRuleFiles")}>
            <PanelCard title={settings.t("dashboard.panel.topFamilies")} icon={<FileCode size={16} />} style={{ "margin-bottom": 0 }}>
              <HorizontalBars data={topRuleFiles.data()} loading={topRuleFiles.initialLoading()} labelOf={(d: RuleFileHit) => ruleFileToFamily(d.file)} valueOf={(d: RuleFileHit) => d.hits} />
            </PanelCard>
          </Show>
        </div>
      </Show>

      <Show when={props.visiblePanels.has("statusCodes")}>
        <PanelCard title={settings.t("dashboard.panel.statusCodes")} icon={<TrendingUp size={16} />}>
          <StatusCodesChart data={statusCodes.data()} loading={statusCodes.initialLoading()} />
        </PanelCard>
      </Show>

      <Show when={props.visiblePanels.has("topClientIps") || props.visiblePanels.has("topUserAgents")}>
        <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "16px", "margin-bottom": "16px" }}>
          <Show when={props.visiblePanels.has("topClientIps")}>
            <PanelCard title={settings.t("dashboard.panel.topClientIPs")} icon={<HardDrive size={16} />} style={{ "margin-bottom": 0 }}>
              <HorizontalBars data={topClientIps.data()} loading={topClientIps.initialLoading()} labelOf={(d: IpHit) => d.ip} valueOf={(d: IpHit) => d.hits} gradient="linear-gradient(90deg, #6366f1, #8b5cf6)" />
            </PanelCard>
          </Show>
          <Show when={props.visiblePanels.has("topUserAgents")}>
            <PanelCard title={settings.t("dashboard.panel.topUserAgents")} icon={<Bot size={16} />} style={{ "margin-bottom": 0 }}>
              <HorizontalBars
                data={topUserAgents.data()}
                loading={topUserAgents.initialLoading()}
                labelOf={(d: UserAgentHit) => (d.user_agent.length > 28 ? d.user_agent.slice(0, 27) + "…" : d.user_agent)}
                valueOf={(d: UserAgentHit) => d.hits}
              />
            </PanelCard>
          </Show>
        </div>
      </Show>

      <Show when={props.visiblePanels.has("byCountry") || props.visiblePanels.has("trafficVolume")}>
        <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "16px", "margin-bottom": "16px" }}>
          <Show when={props.visiblePanels.has("byCountry")}>
            <PanelCard title={settings.t("dashboard.panel.byCountry")} icon={<Flag size={16} />} style={{ "margin-bottom": 0 }}>
              <HorizontalBars data={byCountry.data()} loading={byCountry.initialLoading()} labelOf={(d: CountryHit) => d.country_code} valueOf={(d: CountryHit) => d.hits} gradient="linear-gradient(90deg, #10b981, var(--accent-1))" />
            </PanelCard>
          </Show>
          <Show when={props.visiblePanels.has("trafficVolume")}>
            <PanelCard title={settings.t("dashboard.panel.bytesVolume")} icon={<BarChart3 size={16} />} style={{ "margin-bottom": 0 }}>
              <TimelineSeries
                data={trafficVolume.data()}
                loading={trafficVolume.initialLoading()}
                valueOf={(d) => (d as BytesPoint).bytes}
                color="#3b82f6"
                unit="bytes"
                valueLabel={settings.t("dashboard.tooltip.bytesSent")}
              />
            </PanelCard>
          </Show>
        </div>
      </Show>

      <Show when={props.visiblePanels.has("rps")}>
        <PanelCard
          title={settings.t("dashboard.panel.rps")}
          icon={<Zap size={16} />}
          headerActions={
            <div style={{ display: "flex", background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", "border-radius": "4px", padding: "2px" }}>
              <button
                onClick={() => setRpsMetric("rps")}
                style={{
                  background: rpsMetric() === "rps" ? "var(--accent-1)" : "transparent",
                  color: rpsMetric() === "rps" ? "#fff" : "var(--text-secondary)",
                  border: "none",
                  "font-size": "10px",
                  "font-family": "var(--font-mono)",
                  "font-weight": 600,
                  padding: "2px 8px",
                  "border-radius": "3px",
                  cursor: "pointer",
                  transition: "background var(--duration-fast), color var(--duration-fast)"
                }}
              >
                RPS
              </button>
              <button
                onClick={() => setRpsMetric("volume")}
                style={{
                  background: rpsMetric() === "volume" ? "var(--accent-1)" : "transparent",
                  color: rpsMetric() === "volume" ? "#fff" : "var(--text-secondary)",
                  border: "none",
                  "font-size": "10px",
                  "font-family": "var(--font-mono)",
                  "font-weight": 600,
                  padding: "2px 8px",
                  "border-radius": "3px",
                  cursor: "pointer",
                  transition: "background var(--duration-fast), color var(--duration-fast)"
                }}
              >
                {props.hours <= 2 ? "RPM" : "RPH"}
              </button>
            </div>
          }
        >
          <TimelineSeries
            data={rps.data()}
            loading={rps.initialLoading()}
            valueOf={(d) => (d as RpsPoint).rps}
            color="#06b6d4"
            unit={rpsMetric() === "rps" ? "rps" : "count"}
            valueLabel={rpsMetric() === "rps" ? settings.t("dashboard.tooltip.reqPerSec") : (props.hours <= 2 ? "RPM" : "RPH")}
            type="bar"
          />
        </PanelCard>
      </Show>

      <Show when={props.visiblePanels.has("securityEvents")}>
        <PanelCard title={settings.t("dashboard.panel.recentEvents")} icon={<ShieldAlert size={16} />}>
          <EventsTable data={events.data()} loading={events.initialLoading()} />
        </PanelCard>
      </Show>
    </>
  );
}

export default function Dashboard() {
  const settings = useSettings();
  const filters = useGlobalFilters();

  const [visiblePanels, setVisiblePanels] = createSignal<Set<PanelKey>>(loadVisible());
  const [gearOpen, setGearOpen] = createSignal(false);
  let gearPopoverRef: HTMLDivElement | undefined;

  createEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([...visiblePanels()]));
    } catch {
      /* ignore */
    }
  });

  const togglePanel = (key: PanelKey) => {
    setVisiblePanels((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  createEffect(() => {
    if (!gearOpen()) return;
    const handleClick = (e: MouseEvent) => {
      if (gearPopoverRef && !gearPopoverRef.contains(e.target as Node)) setGearOpen(false);
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setGearOpen(false);
    };
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    onCleanup(() => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    });
  });

  return (
    <div>
      <div class="page-header">
        <div>
          <h1>{settings.t("dashboard.title")}</h1>
          <p>{settings.t("dashboard.subtitle.native")}</p>
        </div>
      </div>

      <div
        style={{
          display: "flex",
          "justify-content": "flex-end",
          "margin-bottom": "16px",
        }}
      >
        <div style={{ position: "relative" }}>
          <button
            data-testid="dashboard-gear"
            class="settings-gear-btn"
            onClick={() => setGearOpen(!gearOpen())}
            title={settings.t("dashboard.ui.panelVisibility")}
            style={{ width: "32px", height: "32px" }}
          >
            <Cog size={16} />
          </button>
          <Show when={gearOpen()}>
            <div
              ref={gearPopoverRef}
              style={{
                position: "absolute",
                top: "calc(100% + 8px)",
                right: "0",
                background: "var(--bg-elevated)",
                border: "1px solid var(--border-default)",
                "border-radius": "var(--radius-md)",
                padding: "6px",
                "box-shadow": "0 16px 48px rgba(0, 0, 0, 0.5), 0 0 0 1px var(--border-subtle)",
                "z-index": 50,
                "min-width": "260px",
                "max-height": "70vh",
                "overflow-y": "auto",
                animation: "scaleIn var(--duration-fast) var(--ease-out)",
              }}
            >
              <div style={{ "font-size": "10px", "font-weight": 700, "text-transform": "uppercase", "letter-spacing": "0.06em", color: "var(--text-muted)", padding: "8px 10px 4px" }}>
                {settings.t("dashboard.ui.sectionMetrics")}
              </div>
              <For each={METRIC_ITEMS}>
                {(p) => (
                  <PanelToggleRow item={p} on={visiblePanels().has(p.key)} onClick={() => togglePanel(p.key)} />
                )}
              </For>
              <div style={{ "font-size": "10px", "font-weight": 700, "text-transform": "uppercase", "letter-spacing": "0.06em", color: "var(--text-muted)", padding: "12px 10px 4px", "border-top": "1px solid var(--border-subtle)", "margin-top": "2px" }}>
                {settings.t("dashboard.ui.sectionPanels")}
              </div>
              <For each={PANEL_ITEMS}>
                {(p) => (
                  <PanelToggleRow item={p} on={visiblePanels().has(p.key)} onClick={() => togglePanel(p.key)} />
                )}
              </For>
            </div>
          </Show>
        </div>
      </div>

      <NativePanels hours={filters.selectedHours} connectionId={filters.connectionId} visiblePanels={visiblePanels()} />
    </div>
  );
}

function PanelToggleRow(props: {
  item: { key: PanelKey; icon: () => any; labelKey: string };
  on: boolean;
  onClick: () => void;
}) {
  const settings = useSettings();
  return (
    <div class="checkbox-row" onClick={props.onClick} style={{ padding: "8px 10px", cursor: "pointer" }}>
      <div
        style={{
          width: "32px",
          height: "24px",
          "border-radius": "12px",
          background: props.on ? "var(--accent-1)" : "var(--border-strong)",
          position: "relative",
          transition: "background var(--duration-fast) var(--ease-out)",
          "flex-shrink": 0,
        }}
      >
        <div
          style={{
            position: "absolute",
            top: "2px",
            left: props.on ? "10px" : "2px",
            width: "20px",
            height: "20px",
            "border-radius": "50%",
            background: "#fff",
            transition: "left var(--duration-fast) var(--ease-out)",
            "box-shadow": "0 1px 3px rgba(0,0,0,0.3)",
          }}
        />
      </div>
      <span style={{ display: "flex", "align-items": "center", gap: "8px", "font-size": "13px" }}>
        {props.item.icon()}
        {settings.t(props.item.labelKey)}
      </span>
    </div>
  );
}
