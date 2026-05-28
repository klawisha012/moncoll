import { createSignal, onMount, For, Show, createMemo, createEffect } from "solid-js";
import { feature } from "topojson-client";
import { geoEqualEarth, geoPath } from "d3-geo";
import type { GeoipMapPoint } from "../api/client";

export interface MapMarker extends GeoipMapPoint {
  topIp?: string;
  topAttacks?: string[];
}

interface Props {
  data: MapMarker[];
  theme: "light" | "dark";
  requestsLabel: string;
}

const TOPO_URL = "https://unpkg.com/world-atlas@2/countries-110m.json";

function colorFor(hits: number, min: number, max: number): string {
  const ratio = max === min ? 0.5 : (hits - min) / (max - min);
  if (ratio < 0.33) return "#10b981";
  if (ratio < 0.66) return "#f59e0b";
  return "#f43f5e";
}

export default function Geoip2DMap(props: Props) {
  const [selected, setSelected] = createSignal<{
    key: string;
    m: MapMarker;
    x: number;
    y: number;
  } | null>(null);

  const [lastHitsMap, setLastHitsMap] = createSignal<Record<string, number>>({});
  const [pulseTimestamps, setPulseTimestamps] = createSignal<Record<string, number>>({});

  createEffect(() => {
    const currentHits: Record<string, number> = {};
    const prevHits = lastHitsMap();
    let hasChanges = false;
    const newPulses: Record<string, number> = {};

    for (const m of props.data) {
      const k = keyOf(m);
      currentHits[k] = m.hits;

      const prev = prevHits[k];
      if (prev !== undefined && m.hits > prev) {
        newPulses[k] = Date.now();
        hasChanges = true;

        // Auto-remove pulse after 2 seconds to trigger reactivity
        setTimeout(() => {
          setPulseTimestamps((curr) => {
            const next = { ...curr };
            delete next[k];
            return next;
          });
        }, 2000);
      }
    }

    setLastHitsMap(currentHits);
    if (hasChanges) {
      setPulseTimestamps((curr) => ({ ...curr, ...newPulses }));
    }
  });

  const [countries, setCountries] = createSignal<any[]>([]);

  // Simple pan & zoom state
  const [zoom, setZoom] = createSignal(1);
  const [pan, setPan] = createSignal([0, 0]);
  let isDragging = false;
  let startX = 0;
  let startY = 0;

  // D3 Projection setup
  const width = 1200;
  const height = 620;
  const projection = geoEqualEarth()
    .scale(200)
    .translate([width / 2, height / 2]);
  const pathGenerator = geoPath().projection(projection);

  onMount(() => {
    fetch(TOPO_URL)
      .then((r) => r.json())
      .then((topo) => {
        const obj = topo.objects?.countries;
        if (!obj) return;
        const fc = feature(topo, obj) as any;
        setCountries(fc.features);
      })
      .catch(() => {
        // Network failure fallback
      });
  });

  const isLight = () => props.theme === "light";
  const keyOf = (m: MapMarker) =>
    `${(m.country_code || "").toUpperCase()}|${m.latitude.toFixed(2)}|${m.longitude.toFixed(2)}|${m.city_name || ""}`;

  const hitsStats = createMemo(() => {
    const hits = props.data.map((d) => d.hits);
    return {
      maxHits: Math.max(...hits, 1),
      minHits: Math.min(...hits, 1),
    };
  });

  const maxHits = () => hitsStats().maxHits;
  const minHits = () => hitsStats().minHits;

  const bg = () => (isLight() ? "#e8eef6" : "#05070f");
  const seaFill = () => (isLight() ? "#dde6f1" : "#0a1024");
  const landFill = () => (isLight() ? "#cdd6e3" : "#1c2638");
  const landStroke = () => (isLight() ? "#9ba6b8" : "rgba(110, 130, 160, 0.5)");

  const markerRadius = (hits: number) => {
    const minR = 3;
    const maxR = 11;
    const maxH = maxHits();
    const minH = minHits();
    if (maxH === minH) return (minR + maxR) / 2;
    return minR + ((hits - minH) / (maxH - minH)) * (maxR - minR);
  };

  const handleWheel = (e: WheelEvent) => {
    e.preventDefault();
    const factor = 1.15;
    const newZoom = e.deltaY < 0 
      ? Math.min(8, zoom() * factor) 
      : Math.max(1, zoom() / factor);

    if (newZoom === 1) {
      setPan([0, 0]);
    }
    setZoom(newZoom);
  };

  const handleMouseDown = (e: MouseEvent) => {
    if (zoom() <= 1) return;
    isDragging = true;
    startX = e.clientX - pan()[0];
    startY = e.clientY - pan()[1];
  };

  const handleMouseMove = (e: MouseEvent) => {
    if (!isDragging) return;
    setPan([e.clientX - startX, e.clientY - startY]);
  };

  const handleMouseUp = () => {
    isDragging = false;
  };

  return (
    <div
      style={{
        position: "relative",
        width: "100%",
        height: "100%",
        background: bg(),
        overflow: "hidden",
        cursor: zoom() > 1 ? (isDragging ? "grabbing" : "grab") : "default",
      }}
      onClick={() => setSelected(null)}
      onWheel={handleWheel}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
    >
      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{
          width: "100%",
          height: "100%",
          background: seaFill(),
          display: "block",
        }}
      >
        <g transform={`translate(${pan()[0]}, ${pan()[1]}) scale(${zoom()})`} style={{ "transform-origin": "center" }}>
          {/* Countries */}
          <g>
            <For each={countries()}>
              {(geo) => (
                <path
                  d={pathGenerator(geo) || ""}
                  fill={landFill()}
                  stroke={landStroke()}
                  stroke-width={0.4 / zoom()}
                  style={{
                    outline: "none",
                    transition: "fill 0.14s ease-out",
                  }}
                  class="country-path"
                />
              )}
            </For>
          </g>

          {/* Points / Markers */}
          <For each={props.data}>
            {(m) => {
              const xy = projection([m.longitude, m.latitude]);
              if (!xy) return null;
              const color = colorFor(m.hits, minHits(), maxHits());
              const k = keyOf(m);
              const isActive = () => selected()?.key === k;
              const r = () => (markerRadius(m.hits) * (isActive() ? 1.25 : 1)) / Math.sqrt(zoom());

              const hasPulse = () => {
                return pulseTimestamps()[k] !== undefined;
              };

              return (
                <g>
                  {/* Pulsing ripple ring */}
                  <Show when={hasPulse()}>
                    <circle
                      cx={xy[0]}
                      cy={xy[1]}
                      r={r()}
                      fill="none"
                      stroke={color}
                      stroke-width={1.2 / Math.sqrt(zoom())}
                      style={{ "pointer-events": "none" }}
                    >
                      <animate
                        attributeName="r"
                        begin="0s"
                        dur="2s"
                        values={`${r()}; ${r() * 2.8}`}
                        repeatCount="indefinite"
                      />
                      <animate
                        attributeName="stroke-opacity"
                        begin="0s"
                        dur="2s"
                        values="0.75; 0"
                        repeatCount="indefinite"
                      />
                    </circle>
                  </Show>

                  {/* Main Marker */}
                  <circle
                    cx={xy[0]}
                    cy={xy[1]}
                    r={r()}
                    fill={color}
                    fill-opacity={isActive() ? 0.85 : 0.55}
                    stroke={color}
                    stroke-width={(isActive() ? 2 : 1.4) / Math.sqrt(zoom())}
                    style={{ cursor: "pointer", transition: "all 0.14s ease-out" }}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelected((prev) =>
                        prev?.key === k
                          ? null
                          : { key: k, m, x: e.clientX, y: e.clientY },
                      );
                    }}
                  />
                </g>
              );
            }}
          </For>
        </g>
      </svg>

      <Show when={selected()}>
        {(sel) => {
          const m = sel().m;
          const color = colorFor(m.hits, minHits(), maxHits());
          const latH = m.latitude >= 0 ? "N" : "S";
          const lonH = m.longitude >= 0 ? "E" : "W";
          const coords = `${Math.abs(m.latitude).toFixed(2)}°${latH}, ${Math.abs(m.longitude).toFixed(2)}°${lonH}`;
          const muted = "#6c7384";
          
          const labelStyle = {
            color: muted,
            "text-transform": "uppercase",
            "font-size": "9px",
            "letter-spacing": "0.6px",
            "min-width": "56px",
          };
          const rowStyle = {
            display: "flex",
            gap: "6px",
            "align-items": "baseline",
            "font-size": "10.5px",
            "margin-top": "2px",
          };
          const valStyle = {
            color: "#e8ecf4",
            "font-family": "var(--font-mono, ui-monospace, monospace)",
          };
          const sep = {
            "border-top": "1px solid rgba(255,255,255,0.06)",
            "margin-top": "5px",
            "padding-top": "5px",
          };

          return (
            <div
              onClick={(e) => e.stopPropagation()}
              style={{
                position: "fixed",
                left: `${sel().x + 14}px`,
                top: `${sel().y + 14}px`,
                "z-index": 6,
                "pointer-events": "auto",
                "min-width": "200px",
                "max-width": "280px",
                padding: "9px 11px",
                background: "rgba(11, 15, 30, 0.95)",
                border: "1px solid rgba(255,255,255,0.18)",
                "border-left": `3px solid ${color}`,
                "border-radius": "4px",
                color: "#e8ecf4",
                "font-family": "var(--font-sans, system-ui)",
                "font-size": "11.5px",
                "line-height": 1.5,
                "box-shadow": "0 6px 22px rgba(0,0,0,0.55)",
                "backdrop-filter": "blur(8px)",
              }}
            >
              {/* Header */}
              <div
                style={{
                  display: "flex",
                  "align-items": "baseline",
                  gap: "6px",
                  "padding-bottom": "5px",
                  "margin-bottom": "5px",
                  "border-bottom": "1px solid rgba(255,255,255,0.08)",
                }}
              >
                <span style={{ "font-weight": 700, "font-size": "14px", "letter-spacing": "0.5px" }}>
                  {m.country_code || "—"}
                </span>
                <Show when={m.city_name}>
                  <span style={{ "font-size": "11.5px", color: "#c5cad6", "font-weight": 500 }}>
                    {m.city_name}
                  </span>
                </Show>
              </div>

              <div style={rowStyle}>
                <span style={labelStyle}>Coords</span>
                <span style={valStyle}>{coords}</span>
              </div>

              <Show when={m.topIp}>
                <div style={rowStyle}>
                  <span style={labelStyle}>Top IP</span>
                  <span style={valStyle}>{m.topIp}</span>
                </div>
              </Show>

              <Show when={m.topAttacks && m.topAttacks.length > 0}>
                <div style={sep}>
                  <div style={{ ...labelStyle, "min-width": 0, "margin-bottom": "3px" }}>Attacks</div>
                  <For each={m.topAttacks}>
                    {(a) => (
                      <div
                        style={{
                          "font-size": "10.5px",
                          "padding-left": "9px",
                          position: "relative",
                          color,
                        }}
                      >
                        <span style={{ position: "absolute", left: 0, opacity: 0.6 }}>›</span>
                        {a}
                      </div>
                    )}
                  </For>
                </div>
              </Show>

              <div
                style={{
                  ...sep,
                  "font-weight": 600,
                  "font-size": "11.5px",
                  color,
                }}
              >
                {m.hits.toLocaleString()}{" "}
                <span style={{ color: "#9aa3b4", "font-weight": 400 }}>{props.requestsLabel}</span>
              </div>
            </div>
          );
        }}
      </Show>
    </div>
  );
}
