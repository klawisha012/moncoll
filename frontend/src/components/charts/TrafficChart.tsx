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

export default function TrafficChart({ data, loading, markerTimes }: Props) {
  const padding = { top: 16, right: 16, bottom: 36, left: 60 };
  const width = 1200;
  const height = 340;
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const safeData = data ?? [];
  const maxVal = Math.max(...safeData.map((d) => d.clean + d.malicious), 1);
  const barW = Math.max(3, Math.floor(chartW / Math.max(safeData.length, 1)) - 2);
  const stepX = chartW / Math.max(safeData.length, 1);

  const { hoverIdx, pos, wrapRef, svgRef, onMove, onLeave } = useSvgHover(
    width,
    padding.left,
    padding.right,
    stepX,
    safeData.length,
  );

  if (!data || data.length === 0)
    return <EmptyState loading={loading} message="No traffic data available" />;

  const yTicks = 5;
  const tickVals: number[] = [];
  for (let i = 0; i <= yTicks; i++) tickVals.push(Math.round((maxVal / yTicks) * i));

  const hovered = hoverIdx !== null ? data[hoverIdx] : null;

  // Pre-compute which bars (by index) overlap a marker timestamp. Charts are
  // bucketed by hour, so we find the bar whose start <= markerTs < next-start.
  const markerSet = new Set<number>();
  if (markerTimes && markerTimes.length && data.length > 0) {
    const bucketMs: number[] = data.map((d) => new Date(d.timestamp).getTime());
    for (const ts of markerTimes) {
      const t = new Date(ts).getTime();
      if (Number.isNaN(t)) continue;
      // Find the latest bucket whose start is <= t.
      let idx = -1;
      for (let i = 0; i < bucketMs.length; i++) {
        if (bucketMs[i] <= t) idx = i;
        else break;
      }
      if (idx < 0) idx = 0;
      markerSet.add(idx);
    }
  }

  return (
    <div
      ref={wrapRef}
      style={{ position: "relative" }}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
    >
      <svg
        ref={svgRef}
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: "100%", height: "auto", display: "block" }}
      >
        {tickVals.map((v) => {
          const y = padding.top + chartH - (v / maxVal) * chartH;
          return (
            <g key={v}>
              <line
                x1={padding.left}
                y1={y}
                x2={width - padding.right}
                y2={y}
                stroke="var(--border-subtle)"
                strokeWidth="0.5"
              />
              <text
                x={padding.left - 8}
                y={y + 4}
                textAnchor="end"
                fill="var(--text-muted)"
                fontSize="12"
              >
                {formatNumber(v)}
              </text>
            </g>
          );
        })}
        {data.map((d, i) => {
          const x = padding.left + i * stepX;
          const cleanH = (d.clean / maxVal) * chartH;
          const malH = (d.malicious / maxVal) * chartH;
          const isHover = hoverIdx === i;
          const isMarker = markerSet.has(i);
          return (
            <g key={d.timestamp}>
              <rect
                x={x + 1}
                y={padding.top + chartH - cleanH - malH}
                width={barW}
                height={cleanH}
                fill="var(--ok)"
                opacity={isHover ? 1 : 0.85}
                rx="1"
              />
              <rect
                x={x + 1}
                y={padding.top + chartH - malH}
                width={barW}
                height={malH}
                fill="var(--red)"
                opacity={isHover ? 1 : 0.9}
                rx="1"
              />
              {isMarker && (
                <>
                  <rect
                    x={x - 1}
                    y={padding.top + chartH - cleanH - malH - 4}
                    width={barW + 4}
                    height={cleanH + malH + 8}
                    fill="none"
                    stroke="var(--amber, #f59e0b)"
                    strokeWidth="2"
                    strokeDasharray="3 2"
                    pointerEvents="none"
                  />
                  <circle
                    cx={x + barW / 2 + 1}
                    cy={padding.top + chartH - cleanH - malH - 10}
                    r="4"
                    fill="var(--amber, #f59e0b)"
                    stroke="var(--ink)"
                    strokeWidth="1"
                  />
                </>
              )}
              {i % Math.max(1, Math.floor(data.length / 10)) === 0 && (
                <text
                  x={x + barW / 2}
                  y={height - 8}
                  textAnchor="middle"
                  fill="var(--text-muted)"
                  fontSize="11"
                >
                  {new Date(d.timestamp).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
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
        <rect
          x={padding.left}
          y={4}
          width="12"
          height="12"
          rx="2"
          fill="var(--ok)"
          opacity={0.85}
        />
        <text x={padding.left + 16} y={14} fill="var(--text-secondary)" fontSize="12">
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
        <text x={padding.left + 86} y={14} fill="var(--text-secondary)" fontSize="12">
          Malicious
        </text>
        {markerSet.size > 0 && (
          <>
            <rect
              x={padding.left + 168}
              y={4}
              width="12"
              height="12"
              fill="none"
              stroke="var(--amber, #f59e0b)"
              strokeWidth="2"
              strokeDasharray="3 2"
            />
            <text x={padding.left + 184} y={14} fill="var(--text-secondary)" fontSize="12">
              Test marker
            </text>
          </>
        )}
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
            { label: "Clean", value: hovered.clean.toLocaleString(), color: "var(--ok)" },
            { label: "Malicious", value: hovered.malicious.toLocaleString(), color: "var(--red)" },
            { label: "Total", value: (hovered.clean + hovered.malicious).toLocaleString() },
            {
              label: "Block rate",
              value:
                hovered.clean + hovered.malicious > 0
                  ? `${((hovered.malicious / (hovered.clean + hovered.malicious)) * 100).toFixed(1)}%`
                  : "0%",
            },
          ]}
        />
      )}
    </div>
  );
}
