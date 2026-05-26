import { Show, For, createMemo } from "solid-js";
import type { TrafficDataPoint } from "../../api/client";
import {
  ChartTooltip,
  EmptyState,
  formatNumber,
  useSvgHover,
} from "./chart-utils";

interface Props {
  data: TrafficDataPoint[] | null;
  loading: boolean;
  /**
   * Optional ISO timestamps to highlight on the chart — used by the Tests
   * page to overlay a "spike" marker on the bars that landed during a test
   * run. The matching bar is highlighted with a glow ring; if no bar matches
   * (e.g. the marker landed between bucket boundaries) we draw a vertical
   * dashed pin at the closest bucket so the user can still see where the
   * test fired.
   */
  markerTimes?: string[];
}

export default function TrafficChart(props: Props) {
  const padding = { top: 16, right: 16, bottom: 36, left: 60 };
  const width = 1200;
  const height = 340;
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const safeData = () => props.data ?? [];
  const maxVal = () => Math.max(...safeData().map((d) => d.clean + d.malicious), 1);
  const stepX = () => chartW / Math.max(safeData().length, 1);
  const barW = () => Math.max(3, Math.floor(chartW / Math.max(safeData().length, 1)) - 2);

  const hover = useSvgHover(
    width,
    padding.left,
    padding.right,
    stepX,
    () => safeData().length,
  );

  const yTicks = 5;
  const tickVals = () => {
    const mv = maxVal();
    const vals: number[] = [];
    for (let i = 0; i <= yTicks; i++) {
      vals.push(Math.round((mv / yTicks) * i));
    }
    return vals;
  };

  const hovered = () => {
    const idx = hover.hoverIdx;
    return idx !== null ? safeData()[idx] : null;
  };

  // Pre-compute which bars (by index) overlap a marker timestamp. Charts are
  // bucketed by hour, so we find the bar whose start <= markerTs < next-start.
  const markerSet = createMemo(() => {
    const set = new Set<number>();
    const markers = props.markerTimes;
    const sd = safeData();
    if (markers && markers.length && sd.length > 0) {
      const bucketMs = sd.map((d) => new Date(d.timestamp).getTime());
      for (const ts of markers) {
        const t = new Date(ts).getTime();
        if (Number.isNaN(t)) continue;
        // Find the latest bucket whose start is <= t.
        let idx = -1;
        for (let i = 0; i < bucketMs.length; i++) {
          if (bucketMs[i] <= t) idx = i;
          else break;
        }
        if (idx < 0) idx = 0;
        set.add(idx);
      }
    }
    return set;
  });

  return (
    <Show
      when={props.data && props.data.length > 0}
      fallback={<EmptyState loading={props.loading} message="No traffic data available" />}
    >
      <div
        ref={hover.refWrap}
        style={{ position: "relative" }}
        onMouseMove={hover.onMove}
        onMouseLeave={hover.onLeave}
      >
        <svg
          ref={hover.refSvg}
          viewBox={`0 0 ${width} ${height}`}
          style={{ width: "100%", height: "auto", display: "block" }}
        >
          <For each={tickVals()}>
            {(v) => {
              const y = () => padding.top + chartH - (v / maxVal()) * chartH;
              return (
                <g>
                  <line
                    x1={padding.left}
                    y1={y()}
                    x2={width - padding.right}
                    y2={y()}
                    stroke="var(--border-subtle)"
                    stroke-width="0.5"
                  />
                  <text
                    x={padding.left - 8}
                    y={y() + 4}
                    text-anchor="end"
                    fill="var(--text-muted)"
                    font-size="12"
                  >
                    {formatNumber(v)}
                  </text>
                </g>
              );
            }}
          </For>
          <For each={safeData()}>
            {(d, i) => {
              const x = () => padding.left + i() * stepX();
              const cleanH = () => (d.clean / maxVal()) * chartH;
              const malH = () => (d.malicious / maxVal()) * chartH;
              const isHover = () => hover.hoverIdx === i();
              const isMarker = () => markerSet().has(i());
              const labelInterval = () => Math.max(1, Math.floor(safeData().length / 10));

              return (
                <g>
                  <rect
                    x={x() + 1}
                    y={padding.top + chartH - cleanH() - malH()}
                    width={barW()}
                    height={cleanH()}
                    fill="var(--ok)"
                    opacity={isHover() ? 1 : 0.85}
                    rx="1"
                  />
                  <rect
                    x={x() + 1}
                    y={padding.top + chartH - malH()}
                    width={barW()}
                    height={malH()}
                    fill="var(--red)"
                    opacity={isHover() ? 1 : 0.9}
                    rx="1"
                  />
                  <Show when={isMarker()}>
                    <rect
                      x={x() - 1}
                      y={padding.top + chartH - cleanH() - malH() - 4}
                      width={barW() + 4}
                      height={cleanH() + malH() + 8}
                      fill="none"
                      stroke="var(--amber, #f59e0b)"
                      stroke-width="2"
                      stroke-dasharray="3 2"
                      pointer-events="none"
                    />
                    <circle
                      cx={x() + barW() / 2 + 1}
                      cy={padding.top + chartH - cleanH() - malH() - 10}
                      r="4"
                      fill="var(--amber, #f59e0b)"
                      stroke="var(--ink)"
                      stroke-width="1"
                    />
                  </Show>
                  <Show when={i() % labelInterval() === 0}>
                    <text
                      x={x() + barW() / 2}
                      y={height - 8}
                      text-anchor="middle"
                      fill="var(--text-muted)"
                      font-size="11"
                    >
                      {new Date(d.timestamp).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </text>
                  </Show>
                </g>
              );
            }}
          </For>
          <Show when={hover.hoverIdx !== null}>
            <line
              x1={padding.left + (hover.hoverIdx ?? 0) * stepX() + barW() / 2 + 1}
              y1={padding.top}
              x2={padding.left + (hover.hoverIdx ?? 0) * stepX() + barW() / 2 + 1}
              y2={padding.top + chartH}
              stroke="var(--ink)"
              stroke-width="1"
              stroke-dasharray="3 3"
              opacity={0.7}
              pointer-events="none"
            />
          </Show>
          <rect
            x={padding.left}
            y={4}
            width="12"
            height="12"
            rx="2"
            fill="var(--ok)"
            opacity={0.85}
          />
          <text x={padding.left + 16} y={14} fill="var(--text-secondary)" font-size="12">
            Clean
          </text>
          <rect
            x={padding.left + 70}
            y={4}
            width="12"
            height="12"
            rx="2"
            fill="var(--red)"
            opacity={0.9}
          />
          <text x={padding.left + 86} y={14} fill="var(--text-secondary)" font-size="12">
            Malicious
          </text>
          <Show when={markerSet().size > 0}>
            <rect
              x={padding.left + 168}
              y={4}
              width="12"
              height="12"
              fill="none"
              stroke="var(--amber, #f59e0b)"
              stroke-width="2"
              stroke-dasharray="3 2"
            />
            <text x={padding.left + 184} y={14} fill="var(--text-secondary)" font-size="12">
              Test marker
            </text>
          </Show>
        </svg>
        <Show when={hovered()}>
          {(hv) => (
            <Show when={hover.pos}>
              {(pos) => (
                <ChartTooltip
                  x={pos().x}
                  y={pos().y}
                  containerWidth={pos().containerW}
                  title={new Date(hv().timestamp).toLocaleString([], {
                    month: "short",
                    day: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                  rows={[
                    { label: "Clean", value: hv().clean.toLocaleString(), color: "var(--ok)" },
                    { label: "Malicious", value: hv().malicious.toLocaleString(), color: "var(--red)" },
                    { label: "Total", value: (hv().clean + hv().malicious).toLocaleString() },
                    {
                      label: "Block rate",
                      value:
                        hv().clean + hv().malicious > 0
                          ? `${((hv().malicious / (hv().clean + hv().malicious)) * 100).toFixed(1)}%`
                          : "0%",
                    },
                  ]}
                />
              )}
            </Show>
          )}
        </Show>
      </div>
    </Show>
  );
}
