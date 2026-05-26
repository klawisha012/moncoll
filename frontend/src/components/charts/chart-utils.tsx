import { createSignal, Show, For } from "solid-js";

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

export function EmptyState(props: { message: string; loading: boolean }) {
  return (
    <Show
      when={!props.loading}
      fallback={
        <div class="loading-spinner" style={{ padding: "48px 0", "font-size": "13px" }}>
          Loading…
        </div>
      }
    >
      <div
        style={{
          padding: "48px 0",
          "text-align": "center",
          color: "var(--text-muted)",
          "font-size": "13px",
        }}
      >
        {props.message}
      </div>
    </Show>
  );
}

export type TooltipRow = { label: string; value: string; color?: string };

export function ChartTooltip(props: {
  x: number;
  y: number;
  containerWidth: number;
  title: string;
  rows: TooltipRow[];
}) {
  // Flip tooltip to the left of the cursor if it would overflow the container.
  const estW = 200;
  const flip = () => props.x + estW + 24 > props.containerWidth;
  const dx = () => flip() ? -estW - 12 : 14;

  return (
    <div
      role="tooltip"
      style={{
        position: "absolute",
        left: `${props.x + dx()}px`,
        top: `${Math.max(8, props.y - 8)}px`,
        transform: "translateY(-100%)",
        "pointer-events": "none",
        background: "var(--card-bg)",
        border: "2px solid var(--ink)",
        "box-shadow": "var(--shadow-offset-sm)",
        padding: "8px 10px",
        "min-width": "150px",
        "max-width": `${estW}px`,
        "z-index": 30,
        "font-family": "var(--font-body)",
      }}
    >
      <div
        style={{
          "font-family": "var(--font-cond)",
          "font-size": "11px",
          "letter-spacing": "0.08em",
          "text-transform": "uppercase",
          color: "var(--text-secondary)",
          "margin-bottom": "6px",
          "border-bottom": "1px solid var(--border-subtle)",
          "padding-bottom": "4px",
        }}
      >
        {props.title}
      </div>
      <div style={{ display: "flex", "flex-direction": "column", gap: "3px" }}>
        <For each={props.rows}>
          {(r) => (
            <div
              style={{ display: "flex", "align-items": "center", gap: "8px", "font-size": "12px" }}
            >
              <Show when={r.color}>
                <span
                  aria-hidden
                  style={{
                    width: "9px",
                    height: "9px",
                    background: r.color,
                    border: "1px solid var(--ink)",
                    "flex-shrink": 0,
                  }}
                />
              </Show>
              <span style={{ color: "var(--text-secondary)", flex: 1 }}>{r.label}</span>
              <span
                style={{
                  "font-family": "var(--font-mono)",
                  "font-weight": 600,
                  color: "var(--text-primary)",
                }}
              >
                {r.value}
              </span>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}

export function useSvgHover(
  viewBoxW: number,
  padLeft: number,
  padRight: number,
  stepX: () => number,
  dataLen: () => number,
) {
  const [hoverIdx, setHoverIdx] = createSignal<number | null>(null);
  const [pos, setPos] = createSignal<{ x: number; y: number; containerW: number } | null>(null);
  let wrapRef: HTMLDivElement | undefined;
  let svgRef: SVGSVGElement | undefined;

  const onMove = (e: MouseEvent) => {
    const svg = svgRef;
    const wrap = wrapRef;
    const len = dataLen();
    if (!svg || !wrap || len === 0) return;
    const rect = svg.getBoundingClientRect();
    const wrapRect = wrap.getBoundingClientRect();
    if (rect.width === 0) return;
    const relX = ((e.clientX - rect.left) / rect.width) * viewBoxW;
    if (relX < padLeft || relX > viewBoxW - padRight) {
      setHoverIdx(null);
      setPos(null);
      return;
    }
    const idx = Math.floor((relX - padLeft) / stepX());
    const clamped = Math.max(0, Math.min(len - 1, idx));
    setHoverIdx(clamped);
    setPos({
      x: e.clientX - wrapRect.left,
      y: e.clientY - wrapRect.top,
      containerW: wrapRect.width,
    });
  };

  const onLeave = () => {
    setHoverIdx(null);
    setPos(null);
  };

  return {
    get hoverIdx() {
      return hoverIdx();
    },
    get pos() {
      return pos();
    },
    onMove,
    onLeave,
    refWrap: (el: HTMLDivElement) => {
      wrapRef = el;
    },
    refSvg: (el: SVGSVGElement) => {
      svgRef = el;
    },
  };
}
