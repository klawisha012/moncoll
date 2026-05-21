import { useState, useRef, useCallback } from "react";

/** Tiny K/M number formatter shared by the SVG charts. */
export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

export function formatBytes(n: number): string {
  if (n >= 1024 ** 4) return `${(n / 1024 ** 4).toFixed(1)} TB`;
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

export function EmptyState({ message, loading }: { message: string; loading: boolean }) {
  if (loading) {
    return (
      <div className="loading-spinner" style={{ padding: "48px 0", fontSize: "13px" }}>
        Loading…
      </div>
    );
  }
  return (
    <div
      style={{
        padding: "48px 0",
        textAlign: "center",
        color: "var(--text-muted)",
        fontSize: "13px",
      }}
    >
      {message}
    </div>
  );
}

export type TooltipRow = { label: string; value: string; color?: string };

export function ChartTooltip({
  x,
  y,
  containerWidth,
  title,
  rows,
}: {
  x: number;
  y: number;
  containerWidth: number;
  title: string;
  rows: TooltipRow[];
}) {
  // Flip tooltip to the left of the cursor if it would overflow the container.
  const estW = 200;
  const flip = x + estW + 24 > containerWidth;
  const dx = flip ? -estW - 12 : 14;
  return (
    <div
      role="tooltip"
      style={{
        position: "absolute",
        left: x + dx,
        top: Math.max(8, y - 8),
        transform: "translateY(-100%)",
        pointerEvents: "none",
        background: "var(--card-bg)",
        border: "2px solid var(--ink)",
        boxShadow: "var(--shadow-offset-sm)",
        padding: "8px 10px",
        minWidth: "150px",
        maxWidth: `${estW}px`,
        zIndex: 30,
        fontFamily: "var(--font-body)",
      }}
    >
      <div
        style={{
          fontFamily: "var(--font-cond)",
          fontSize: "11px",
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          color: "var(--text-secondary)",
          marginBottom: "6px",
          borderBottom: "1px solid var(--border-subtle)",
          paddingBottom: "4px",
        }}
      >
        {title}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
        {rows.map((r, i) => (
          <div
            key={i}
            style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px" }}
          >
            {r.color && (
              <span
                aria-hidden
                style={{
                  width: 9,
                  height: 9,
                  background: r.color,
                  border: "1px solid var(--ink)",
                  flexShrink: 0,
                }}
              />
            )}
            <span style={{ color: "var(--text-secondary)", flex: 1 }}>{r.label}</span>
            <span
              style={{
                fontFamily: "var(--font-mono)",
                fontWeight: 600,
                color: "var(--text-primary)",
              }}
            >
              {r.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function useSvgHover(
  viewBoxW: number,
  padLeft: number,
  padRight: number,
  stepX: number,
  dataLen: number,
) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const [pos, setPos] = useState<{ x: number; y: number; containerW: number } | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const onMove = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      const svg = svgRef.current;
      const wrap = wrapRef.current;
      if (!svg || !wrap || dataLen === 0) return;
      const rect = svg.getBoundingClientRect();
      const wrapRect = wrap.getBoundingClientRect();
      if (rect.width === 0) return;
      const relX = ((e.clientX - rect.left) / rect.width) * viewBoxW;
      if (relX < padLeft || relX > viewBoxW - padRight) {
        setHoverIdx(null);
        setPos(null);
        return;
      }
      const idx = Math.floor((relX - padLeft) / stepX);
      const clamped = Math.max(0, Math.min(dataLen - 1, idx));
      setHoverIdx(clamped);
      setPos({
        x: e.clientX - wrapRect.left,
        y: e.clientY - wrapRect.top,
        containerW: wrapRect.width,
      });
    },
    [viewBoxW, padLeft, padRight, stepX, dataLen],
  );

  const onLeave = useCallback(() => {
    setHoverIdx(null);
    setPos(null);
  }, []);

  return { hoverIdx, pos, wrapRef, svgRef, onMove, onLeave };
}
