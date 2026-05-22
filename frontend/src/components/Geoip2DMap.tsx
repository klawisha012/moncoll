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
  const [hovered, setHovered] = useState<{ m: MapMarker; x: number; y: number } | null>(null);
  const isLight = theme === "light";

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
      onMouseLeave={() => setHovered(null)}
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
            return (
              <Marker
                key={i}
                coordinates={[m.longitude, m.latitude]}
                onMouseEnter={(e) =>
                  setHovered({ m, x: e.clientX, y: e.clientY })
                }
                onMouseMove={(e) =>
                  setHovered({ m, x: e.clientX, y: e.clientY })
                }
                onMouseLeave={() => setHovered(null)}
              >
                <circle
                  r={markerRadius(m.hits)}
                  fill={color}
                  fillOpacity={0.55}
                  stroke={color}
                  strokeWidth={1.4}
                  style={{ cursor: "pointer" }}
                />
              </Marker>
            );
          })}
        </ZoomableGroup>
      </ComposableMap>

      {hovered && (
        <div
          style={{
            position: "fixed",
            left: hovered.x + 14,
            top: hovered.y + 14,
            zIndex: 6,
            pointerEvents: "none",
            minWidth: 140,
            maxWidth: 240,
            padding: "8px 10px",
            background: "rgba(11, 15, 30, 0.94)",
            border: "1px solid rgba(255,255,255,0.18)",
            borderLeft: `3px solid ${colorFor(hovered.m.hits, minHits, maxHits)}`,
            borderRadius: 4,
            color: "#e8ecf4",
            fontFamily: "var(--font-sans, system-ui)",
            fontSize: 12,
            lineHeight: 1.45,
            boxShadow: "0 6px 18px rgba(0,0,0,0.45)",
          }}
        >
          <div style={{ fontWeight: 700, fontSize: 13 }}>
            {hovered.m.city_name || hovered.m.country_code || "—"}
            {hovered.m.country_code && hovered.m.city_name ? (
              <span style={{ color: "#9aa3b4", fontWeight: 400 }}> · {hovered.m.country_code}</span>
            ) : null}
          </div>
          {hovered.m.topIp && (
            <div style={{ fontFamily: "var(--font-mono, ui-monospace)", fontSize: 11, color: "#9aa3b4" }}>
              {hovered.m.topIp}
            </div>
          )}
          {hovered.m.topAttacks && hovered.m.topAttacks.length > 0 && (
            <div
              style={{
                fontSize: 11,
                color: colorFor(hovered.m.hits, minHits, maxHits),
                marginTop: 2,
              }}
            >
              {hovered.m.topAttacks.join(", ")}
            </div>
          )}
          <div style={{ fontSize: 11, color: "#9aa3b4", marginTop: 2 }}>
            {hovered.m.hits.toLocaleString()} {requestsLabel}
          </div>
        </div>
      )}
    </div>
  );
}
