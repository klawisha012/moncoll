import { useMemo, useState } from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup,
} from "react-simple-maps";
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

export default function Geoip2DMap({ data, theme, requestsLabel }: Props) {
  // Click-to-toggle: открываем карточку по клику, закрываем по клику по тому
  // же маркеру или по карте. Hover отвергнут — при кластеризации меток курсор
  // не может попасть на соседний пин, всплывающая карточка перекрывает цели.
  const [selected, setSelected] = useState<
    { key: string; m: MapMarker; x: number; y: number } | null
  >(null);
  const isLight = theme === "light";

  const keyOf = (m: MapMarker) =>
    `${(m.country_code || "").toUpperCase()}|${m.latitude.toFixed(2)}|${m.longitude.toFixed(2)}|${m.city_name || ""}`;

  const { maxHits, minHits } = useMemo(() => {
    const hits = data.map((d) => d.hits);
    return { maxHits: Math.max(...hits, 1), minHits: Math.min(...hits, 1) };
  }, [data]);

  const bg = isLight ? "#e8eef6" : "#05070f";
  const seaFill = isLight ? "#dde6f1" : "#0a1024";
  const landFill = isLight ? "#cdd6e3" : "#1c2638";
  const landStroke = isLight ? "#9ba6b8" : "rgba(110, 130, 160, 0.5)";

  const markerRadius = (hits: number) => {
    const minR = 3;
    const maxR = 11;
    if (maxHits === minHits) return (minR + maxR) / 2;
    return minR + ((hits - minHits) / (maxHits - minHits)) * (maxR - minR);
  };

  return (
    <div
      style={{
        position: "relative",
        width: "100%",
        height: "100%",
        background: bg,
        overflow: "hidden",
      }}
      // Клик по карте (не по пину — пин stopPropagation'ит) закрывает карточку.
      onClick={() => setSelected(null)}
    >
      <ComposableMap
        projection="geoEqualEarth"
        projectionConfig={{ scale: 200 }}
        width={1200}
        height={620}
        style={{ width: "100%", height: "100%", background: seaFill }}
      >
        <ZoomableGroup
          zoom={1}
          minZoom={1}
          maxZoom={8}
          center={[0, 0]}
          translateExtent={[[0, 0], [1200, 620]]}
        >
          <Geographies geography={TOPO_URL}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill={landFill}
                  stroke={landStroke}
                  strokeWidth={0.4}
                  style={{
                    default: { outline: "none" },
                    hover: { outline: "none", fill: isLight ? "#bfc8d8" : "#26334a" },
                    pressed: { outline: "none" },
                  }}
                />
              ))
            }
          </Geographies>
          {data.map((m, i) => {
            const color = colorFor(m.hits, minHits, maxHits);
            const k = keyOf(m);
            const isActive = selected?.key === k;
            return (
              <Marker
                key={i}
                coordinates={[m.longitude, m.latitude]}
                onClick={(e: React.MouseEvent<SVGGElement>) => {
                  e.stopPropagation();
                  setSelected((prev) =>
                    prev?.key === k
                      ? null
                      : { key: k, m, x: e.clientX, y: e.clientY },
                  );
                }}
              >
                <circle
                  r={markerRadius(m.hits) * (isActive ? 1.25 : 1)}
                  fill={color}
                  fillOpacity={isActive ? 0.85 : 0.55}
                  stroke={color}
                  strokeWidth={isActive ? 2 : 1.4}
                  style={{ cursor: "pointer", transition: "all 0.14s ease-out" }}
                />
              </Marker>
            );
          })}
        </ZoomableGroup>
      </ComposableMap>

      {selected && (() => {
        const m = selected.m;
        const color = colorFor(m.hits, minHits, maxHits);
        const latH = m.latitude >= 0 ? "N" : "S";
        const lonH = m.longitude >= 0 ? "E" : "W";
        const coords = `${Math.abs(m.latitude).toFixed(2)}°${latH}, ${Math.abs(m.longitude).toFixed(2)}°${lonH}`;
        const muted = "#6c7384";
        const labelStyle: React.CSSProperties = {
          color: muted,
          textTransform: "uppercase",
          fontSize: 9,
          letterSpacing: 0.6,
          minWidth: 56,
        };
        const rowStyle: React.CSSProperties = {
          display: "flex",
          gap: 6,
          alignItems: "baseline",
          fontSize: 10.5,
          marginTop: 2,
        };
        const valStyle: React.CSSProperties = {
          color: "#e8ecf4",
          fontFamily: "var(--font-mono, ui-monospace, monospace)",
        };
        const sep: React.CSSProperties = {
          borderTop: "1px solid rgba(255,255,255,0.06)",
          marginTop: 5,
          paddingTop: 5,
        };
        return (
          <div
            // pointerEvents: auto — карточку можно копировать/выделять,
            // клики по ней не закрывают её (stopPropagation на самой div).
            onClick={(e) => e.stopPropagation()}
            style={{
              position: "fixed",
              left: selected.x + 14,
              top: selected.y + 14,
              zIndex: 6,
              pointerEvents: "auto",
              minWidth: 200,
              maxWidth: 280,
              padding: "9px 11px",
              background: "rgba(11, 15, 30, 0.95)",
              border: "1px solid rgba(255,255,255,0.18)",
              borderLeft: `3px solid ${color}`,
              borderRadius: 4,
              color: "#e8ecf4",
              fontFamily: "var(--font-sans, system-ui)",
              fontSize: 11.5,
              lineHeight: 1.5,
              boxShadow: "0 6px 22px rgba(0,0,0,0.55)",
              backdropFilter: "blur(8px)",
            }}
          >
            {/* Header: country code (big) + city (muted) */}
            <div
              style={{
                display: "flex",
                alignItems: "baseline",
                gap: 6,
                paddingBottom: 5,
                marginBottom: 5,
                borderBottom: "1px solid rgba(255,255,255,0.08)",
              }}
            >
              <span style={{ fontWeight: 700, fontSize: 14, letterSpacing: 0.5 }}>
                {m.country_code || "—"}
              </span>
              {m.city_name && (
                <span style={{ fontSize: 11.5, color: "#c5cad6", fontWeight: 500 }}>
                  {m.city_name}
                </span>
              )}
            </div>

            <div style={rowStyle}>
              <span style={labelStyle}>Coords</span>
              <span style={valStyle}>{coords}</span>
            </div>

            {m.topIp && (
              <div style={rowStyle}>
                <span style={labelStyle}>Top IP</span>
                <span style={valStyle}>{m.topIp}</span>
              </div>
            )}

            {m.topAttacks && m.topAttacks.length > 0 && (
              <div style={sep}>
                <div style={{ ...labelStyle, minWidth: 0, marginBottom: 3 }}>Attacks</div>
                {m.topAttacks.map((a, idx) => (
                  <div
                    key={idx}
                    style={{
                      fontSize: 10.5,
                      paddingLeft: 9,
                      position: "relative",
                      color,
                    }}
                  >
                    <span style={{ position: "absolute", left: 0, opacity: 0.6 }}>›</span>
                    {a}
                  </div>
                ))}
              </div>
            )}

            <div
              style={{
                ...sep,
                fontWeight: 600,
                fontSize: 11.5,
                color,
              }}
            >
              {m.hits.toLocaleString()}{" "}
              <span style={{ color: "#9aa3b4", fontWeight: 400 }}>{requestsLabel}</span>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
