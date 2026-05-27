import { createEffect, createSignal, createMemo, onCleanup, onMount, For, Show } from "solid-js";
import ApexCharts from "apexcharts";
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
  deps: () => [number, number | null],
  intervalMs = 15_000,
  enabled: () => boolean = () => true,
): { data: () => T | null; initialLoading: () => boolean; error: () => string | null } {
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
    const id = setInterval(run, intervalMs);
    onCleanup(() => {
      cancelled = true;
      clearInterval(id);
    });
  });

  return { data, initialLoading, error };
}

function PanelCard(props: {
  title: string;
  icon?: any;
  children: any;
  style?: any;
}) {
  return (
    <div class="card" style={{ "margin-bottom": "16px", ...props.style }}>
      <div class="card-header" style={{ display: "flex", "align-items": "center", gap: "8px" }}>
        {props.icon}
        <h2 style={{ "font-size": "15px", margin: "0" }}>{props.title}</h2>
      </div>
      <div style={{ padding: "8px 4px" }}>{props.children}</div>
    </div>
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
  let chartRef: HTMLDivElement | undefined;
  let chart: ApexCharts | undefined;

  const safeData = () => props.data ?? [];
  const values = () => safeData().map(props.valueOf);
  const maxVal = () => Math.max(...values(), 1);

  const fmt = (v: number) => {
    if (props.unit === "bytes") return formatBytes(v);
    if (props.unit === "rps") return `${Math.round(v)} rps`;
    return formatNumber(Math.round(v));
  };

  onMount(() => {
    if (!chartRef) return;

    const isBar = props.type === "bar";

    const options: any = {
      chart: {
        type: isBar ? "bar" : "area",
        height: 280,
        fontFamily: "var(--font-body)",
        foreColor: "var(--text-secondary)",
        toolbar: { show: false },
        animations: { enabled: false },
      },
      series: [
        {
          name: props.valueLabel ?? "Value",
          data: [],
        },
      ],
      colors: [props.color],
      grid: {
        borderColor: "var(--border-subtle)",
        strokeDashArray: 3,
        xaxis: { lines: { show: false } },
        yaxis: { lines: { show: true } },
      },
      stroke: {
        curve: "straight",
        width: isBar ? 0 : 2,
      },
      fill: {
        type: "gradient",
        gradient: {
          shadeIntensity: 1,
          opacityFrom: isBar ? 0.85 : 0.32,
          opacityTo: 0.01,
          stops: [0, 100],
        },
      },
      xaxis: {
        type: "category",
        categories: [],
        axisBorder: { show: true, color: "var(--line)", strokeWidth: 2 },
        axisTicks: { show: true, color: "var(--line)" },
        labels: {
          style: {
            fontSize: "11px",
            fontFamily: "var(--font-body)",
          },
        },
      },
      yaxis: {
        labels: {
          formatter: (v: number) => fmt(v),
          style: {
            fontSize: "11px",
            fontFamily: "var(--font-body)",
          },
        },
      },
      tooltip: {
        theme: settings.theme === "dark" ? "dark" : "light",
        x: { show: true },
        y: {
          formatter: (v: number) => fmt(v),
        },
        style: {
          fontSize: "12px",
          fontFamily: "var(--font-body)",
        },
      },
      theme: {
        mode: settings.theme as "dark" | "light",
      },
      dataLabels: { enabled: false },
    };

    chart = new ApexCharts(chartRef, options);
    chart.render();

    onCleanup(() => {
      chart?.destroy();
    });
  });

  createEffect(() => {
    const list = safeData();
    if (!chart || !list.length) return;

    const currentValues = list.map(props.valueOf);
    const categories = list.map((d) =>
      new Date(d.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    );

    chart.updateSeries([
      {
        name: props.valueLabel ?? "Value",
        data: currentValues,
      },
    ]);

    chart.updateOptions({
      xaxis: {
        categories: categories,
      },
    }, false, false);
  });

  createEffect(() => {
    const theme = settings.theme;
    chart?.updateOptions({
      theme: {
        mode: theme as "dark" | "light",
      },
      tooltip: {
        theme: theme as "dark" | "light",
      },
    }, false, false);
  });

  return (
    <Show when={props.data && props.data.length > 0} fallback={<EmptyState loading={props.loading} message={settings.t("dashboard.empty.noData")} />}>
      <div ref={chartRef} style={{ width: "100%", height: "280px" }} />
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

function StatusCodesChart(props: { data: StatusCodePoint[] | null; loading: boolean }) {
  const settings = useSettings();
  let chartRef: HTMLDivElement | undefined;
  let chart: ApexCharts | undefined;

  const safeData = () => props.data ?? [];

  onMount(() => {
    if (!chartRef) return;

    const options: any = {
      chart: {
        type: "bar",
        height: 300,
        stacked: true,
        fontFamily: "var(--font-body)",
        foreColor: "var(--text-secondary)",
        toolbar: { show: false },
        animations: { enabled: false },
      },
      series: [
        { name: "2xx", data: [] },
        { name: "3xx", data: [] },
        { name: "4xx", data: [] },
        { name: "5xx", data: [] },
      ],
      colors: [STATUS_COLORS.c2xx, STATUS_COLORS.c3xx, STATUS_COLORS.c4xx, STATUS_COLORS.c5xx],
      grid: {
        borderColor: "var(--border-subtle)",
        strokeDashArray: 3,
        xaxis: { lines: { show: false } },
        yaxis: { lines: { show: true } },
      },
      plotOptions: {
        bar: {
          columnWidth: "70%",
          borderRadius: 2,
        },
      },
      xaxis: {
        type: "category",
        categories: [],
        axisBorder: { show: true, color: "var(--line)", strokeWidth: 2 },
        axisTicks: { show: true, color: "var(--line)" },
        labels: {
          style: {
            fontSize: "11px",
            fontFamily: "var(--font-body)",
          },
        },
      },
      yaxis: {
        labels: {
          formatter: (v: number) => formatNumber(Math.round(v)),
          style: {
            fontSize: "11px",
            fontFamily: "var(--font-body)",
          },
        },
      },
      tooltip: {
        theme: settings.theme === "dark" ? "dark" : "light",
        y: {
          formatter: (v: number) => formatNumber(Math.round(v)),
        },
      },
      theme: {
        mode: settings.theme as "dark" | "light",
      },
      dataLabels: { enabled: false },
      legend: {
        position: "top",
        horizontalAlign: "left",
        fontFamily: "var(--font-mono)",
        fontSize: "12px",
        markers: {
          radius: 3,
        },
      },
    };

    chart = new ApexCharts(chartRef, options);
    chart.render();

    onCleanup(() => {
      chart?.destroy();
    });
  });

  createEffect(() => {
    const list = safeData();
    if (!chart || !list.length) return;

    const seriesData = {
      c2xx: [] as number[],
      c3xx: [] as number[],
      c4xx: [] as number[],
      c5xx: [] as number[],
    };

    list.forEach((d) => {
      seriesData.c2xx.push(d.c2xx);
      seriesData.c3xx.push(d.c3xx);
      seriesData.c4xx.push(d.c4xx);
      seriesData.c5xx.push(d.c5xx);
    });

    const categories = list.map((d) =>
      new Date(d.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    );

    chart.updateSeries([
      { name: "2xx", data: seriesData.c2xx },
      { name: "3xx", data: seriesData.c3xx },
      { name: "4xx", data: seriesData.c4xx },
      { name: "5xx", data: seriesData.c5xx },
    ]);

    chart.updateOptions({
      xaxis: {
        categories: categories,
      },
    }, false, false);
  });

  createEffect(() => {
    const theme = settings.theme;
    chart?.updateOptions({
      theme: {
        mode: theme as "dark" | "light",
      },
      tooltip: {
        theme: theme as "dark" | "light",
      },
    }, false, false);
  });

  return (
    <Show when={props.data && props.data.length > 0} fallback={<EmptyState loading={props.loading} message={settings.t("dashboard.empty.noStatusData")} />}>
      <div ref={chartRef} style={{ width: "100%", height: "300px" }} />
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

function SeverityDonut(props: { data: SeveritySlice[] | null; loading: boolean }) {
  const settings = useSettings();
  let chartRef: HTMLDivElement | undefined;
  let chart: ApexCharts | undefined;

  const safeData = () => props.data ?? [];

  onMount(() => {
    if (!chartRef) return;

    const options: any = {
      chart: {
        type: "donut",
        height: 250,
        fontFamily: "var(--font-body)",
        foreColor: "var(--text-secondary)",
      },
      series: [],
      labels: [],
      colors: [],
      plotOptions: {
        pie: {
          donut: {
            size: "65%",
            labels: {
              show: true,
              total: {
                show: true,
                label: "TOTAL",
                fontFamily: "var(--font-mono)",
                color: "var(--text-muted)",
                fontSize: "12px",
                formatter: (w: any) => {
                  const sum = w.globals.seriesTotals.reduce((a: number, b: number) => a + b, 0);
                  return formatNumber(sum);
                },
              },
              value: {
                show: true,
                fontSize: "20px",
                fontFamily: "var(--font-display)",
                fontWeight: 700,
                color: "var(--text-primary)",
                formatter: (v: string) => formatNumber(parseInt(v, 10)),
              },
              name: {
                show: true,
                fontSize: "12px",
                fontFamily: "var(--font-mono)",
              },
            },
          },
        },
      },
      legend: {
        position: "right",
        fontFamily: "var(--font-mono)",
        fontSize: "12px",
        markers: {
          radius: 3,
        },
        formatter: (seriesName: string, opts: any) => {
          const val = opts.w.globals.series[opts.seriesIndex];
          const totalHits = opts.w.globals.seriesTotals.reduce((a: number, b: number) => a + b, 0);
          const percent = totalHits > 0 ? ((val / totalHits) * 100).toFixed(1) : "0.0";
          return `${seriesName}: ${formatNumber(val)} (${percent}%)`;
        },
      },
      tooltip: {
        theme: settings.theme === "dark" ? "dark" : "light",
        y: {
          formatter: (v: number) => `${v.toLocaleString()} hits`,
        },
      },
      theme: {
        mode: settings.theme as "dark" | "light",
      },
      dataLabels: { enabled: false },
    };

    chart = new ApexCharts(chartRef, options);
    chart.render();

    onCleanup(() => {
      chart?.destroy();
    });
  });

  createEffect(() => {
    const list = safeData();
    if (!chart || !list.length) return;

    const series = list.map((s) => s.hits);
    const labels = list.map((s) => s.severity);
    const colors = list.map((s) => SEVERITY_COLORS[s.severity] || "#888");

    chart.updateOptions({
      series: series,
      labels: labels,
      colors: colors,
    }, false, false);
  });

  createEffect(() => {
    const theme = settings.theme;
    chart?.updateOptions({
      theme: {
        mode: theme as "dark" | "light",
      },
      tooltip: {
        theme: theme as "dark" | "light",
      },
    }, false, false);
  });

  return (
    <Show when={props.data && props.data.length > 0 && safeData().some(s => s.hits > 0)} fallback={<EmptyState loading={props.loading} message={settings.t("dashboard.empty.noSeverityData")} />}>
      <div ref={chartRef} style={{ width: "100%", "min-height": "250px" }} />
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
  const deps = () => [props.hours, props.connectionId] as [number, number | null];

  const metrics = useDashboardPanel<Metrics>(
    () => api.getMetrics(props.hours, props.connectionId),
    deps,
    15_000,
    () => props.visiblePanels.has("metricTotalRequests") ||
      props.visiblePanels.has("metricBlockedThreats") ||
      props.visiblePanels.has("metricAvgLatency") ||
      props.visiblePanels.has("metricActiveRules"),
  );
  const traffic = useDashboardPanel<TrafficDataPoint[]>(() => api.getTraffic(props.hours, props.connectionId), deps, 15_000, () => props.visiblePanels.has("trafficChart"));
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
  const rps = useDashboardPanel<RpsPoint[]>(() => api.getRequestsPerSecond(props.hours, props.connectionId), deps, 15_000, () => props.visiblePanels.has("rps"));
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
        <PanelCard title={settings.t("dashboard.panel.rps")} icon={<Zap size={16} />}>
          <TimelineSeries
            data={rps.data()}
            loading={rps.initialLoading()}
            valueOf={(d) => Math.ceil((d as RpsPoint).rps)}
            color="#06b6d4"
            unit="rps"
            valueLabel={settings.t("dashboard.tooltip.reqPerSec")}
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
