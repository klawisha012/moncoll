import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Globe, { type GlobeMethods } from "react-globe.gl";
import { feature } from "topojson-client";
import { MeshPhongMaterial } from "three";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import type { GeoipMapPoint } from "../api/client";

export interface GlobeMarker extends GeoipMapPoint {
  topIp?: string;
  topAttacks?: string[];
}

interface Props {
  data: GlobeMarker[];
  theme: "light" | "dark";
  requestsLabel: string;
}

type CountryFeature = Feature<Geometry, { name: string }>;
type GlobeLabel = { name: string; lat: number; lng: number; ocean?: boolean };

const COUNTRIES_TOPOJSON_URL = "https://unpkg.com/world-atlas@2/countries-110m.json";

function makeStarfield(numStars: number, w: number, h: number): string {
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d");
  if (!ctx) return "";
  ctx.fillStyle = "#000";
  ctx.fillRect(0, 0, w, h);
  ctx.imageSmoothingEnabled = false;
  for (let i = 0; i < numStars; i++) {
    const x = Math.floor(Math.random() * w);
    const y = Math.floor(Math.random() * h);
    const roll = Math.random();
    // Most stars are crisp 2x2 pixels; ~15% are brighter 3x3; ~5% have a halo.
    if (roll > 0.95) {
      ctx.fillStyle = "rgba(255,255,255,0.15)";
      ctx.fillRect(x - 2, y - 2, 6, 6);
      ctx.fillStyle = "rgba(255,255,255,0.9)";
      ctx.fillRect(x, y, 3, 3);
    } else if (roll > 0.8) {
      ctx.fillStyle = "rgba(255,255,255,0.85)";
      ctx.fillRect(x, y, 3, 3);
    } else {
      const a = (0.5 + Math.random() * 0.5).toFixed(3);
      ctx.fillStyle = `rgba(255,255,255,${a})`;
      ctx.fillRect(x, y, 2, 2);
    }
  }
  return canvas.toDataURL("image/png");
}

const OCEAN_LABELS: GlobeLabel[] = [
  { name: "PACIFIC OCEAN", lat: 0, lng: -160, ocean: true },
  { name: "PACIFIC OCEAN", lat: -10, lng: 160, ocean: true },
  { name: "ATLANTIC OCEAN", lat: 15, lng: -40, ocean: true },
  { name: "ATLANTIC OCEAN", lat: -25, lng: -20, ocean: true },
  { name: "INDIAN OCEAN", lat: -15, lng: 75, ocean: true },
  { name: "ARCTIC OCEAN", lat: 82, lng: 0, ocean: true },
  { name: "SOUTHERN OCEAN", lat: -65, lng: 0, ocean: true },
  { name: "Mediterranean Sea", lat: 35, lng: 18, ocean: true },
  { name: "Caribbean Sea", lat: 15, lng: -75, ocean: true },
  { name: "Bering Sea", lat: 58, lng: -178, ocean: true },
  { name: "Sea of Japan", lat: 40, lng: 135, ocean: true },
  { name: "South China Sea", lat: 15, lng: 115, ocean: true },
  { name: "Black Sea", lat: 43, lng: 35, ocean: true },
  { name: "Red Sea", lat: 20, lng: 38, ocean: true },
  { name: "Bay of Bengal", lat: 15, lng: 88, ocean: true },
  { name: "Arabian Sea", lat: 15, lng: 65, ocean: true },
  { name: "North Sea", lat: 56, lng: 4, ocean: true },
  { name: "Norwegian Sea", lat: 68, lng: 2, ocean: true },
  { name: "Hudson Bay", lat: 60, lng: -86, ocean: true },
  { name: "Coral Sea", lat: -16, lng: 153, ocean: true },
  { name: "Tasman Sea", lat: -40, lng: 160, ocean: true },
];

function colorFor(hits: number, min: number, max: number): string {
  const ratio = max === min ? 0.5 : (hits - min) / (max - min);
  if (ratio < 0.33) return "#10b981";
  if (ratio < 0.66) return "#f59e0b";
  return "#f43f5e";
}

function centroidOf(geom: Geometry): [number, number] | null {
  let sumX = 0;
  let sumY = 0;
  let n = 0;
  const walk = (coords: unknown): void => {
    if (!Array.isArray(coords)) return;
    if (typeof coords[0] === "number" && typeof coords[1] === "number") {
      sumX += coords[0] as number;
      sumY += coords[1] as number;
      n++;
      return;
    }
    for (const c of coords) walk(c);
  };
  walk((geom as { coordinates?: unknown }).coordinates);
  if (n === 0) return null;
  return [sumX / n, sumY / n];
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function buildMarker(
  d: GlobeMarker,
  color: string,
  theme: "light" | "dark",
  requestsLabel: string,
): HTMLDivElement {
  const el = document.createElement("div");
  el.style.cssText = `
    position: absolute;
    transform: translate(-50%, -100%);
    pointer-events: auto;
    cursor: pointer;
    font-family: var(--font-sans, system-ui);
    color: ${theme === "light" ? "#1a1d2e" : "#e8ecf4"};
  `;
  const place = escapeHtml(d.city_name || d.country_code || "—");
  const cc = escapeHtml(d.country_code || "");
  const ip = d.topIp ? escapeHtml(d.topIp) : "";
  const attacks =
    d.topAttacks && d.topAttacks.length > 0 ? d.topAttacks.map(escapeHtml).join(", ") : "";

  const cardBg = "rgba(11,15,30,0.92)";
  const cardBorder = "rgba(255,255,255,0.18)";
  const muted = "#9aa3b4";

  el.innerHTML = `
    <div style="
      min-width: 132px;
      max-width: 220px;
      padding: 6px 9px;
      margin-bottom: 4px;
      background: ${cardBg};
      border: 1px solid ${cardBorder};
      border-left: 3px solid ${color};
      border-radius: 4px;
      font-size: 11px;
      line-height: 1.4;
      color: #e8ecf4;
      box-shadow: 0 4px 14px rgba(0,0,0,0.45);
      backdrop-filter: blur(6px);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    ">
      <div style="font-weight: 700; font-size: 12px;">
        ${place}${cc && d.city_name ? ` · <span style="color:${muted}">${cc}</span>` : ""}
      </div>
      ${ip ? `<div style="font-family: var(--font-mono, ui-monospace); font-size: 10.5px; color: ${muted};">${ip}</div>` : ""}
      ${attacks ? `<div style="font-size: 10.5px; color: ${color}; margin-top: 2px;">${attacks}</div>` : ""}
      <div style="font-size: 10px; color: ${muted}; margin-top: 2px;">
        ${d.hits.toLocaleString()} ${escapeHtml(requestsLabel)}
      </div>
    </div>
    <svg width="14" height="20" viewBox="0 0 14 20" style="display:block; margin: 0 auto; filter: drop-shadow(0 2px 3px rgba(0,0,0,0.4));">
      <path d="M7 0 C3.13 0 0 3.13 0 7 c0 5.25 7 13 7 13 s7 -7.75 7 -13 c0 -3.87 -3.13 -7 -7 -7 z" fill="${color}" stroke="#0b0f1e" stroke-width="1"/>
      <circle cx="7" cy="7" r="2.6" fill="#0b0f1e"/>
    </svg>
  `;
  return el;
}

export default function GeoipGlobe({ data, theme, requestsLabel }: Props) {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [size, setSize] = useState<{ w: number; h: number }>({ w: 800, h: 520 });
  const [countries, setCountries] = useState<CountryFeature[]>([]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => {
      const rect = el.getBoundingClientRect();
      setSize({ w: Math.max(rect.width, 320), h: Math.max(rect.height, 320) });
    };
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetch(COUNTRIES_TOPOJSON_URL)
      .then((r) => r.json())
      .then((topo) => {
        if (cancelled) return;
        const obj = topo.objects?.countries;
        if (!obj) return;
        const fc = feature(topo, obj) as unknown as FeatureCollection<Geometry, { name: string }>;
        setCountries(fc.features as CountryFeature[]);
      })
      .catch(() => {
        // network failure — globe still renders without polygons/labels
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const g = globeRef.current;
    if (!g) return;
    const controls = g.controls();
    if (controls) {
      controls.autoRotate = true;
      controls.autoRotateSpeed = 0.3;
      controls.enableZoom = true;
      controls.enableDamping = true;
      controls.dampingFactor = 0.12;
      controls.rotateSpeed = 0.6;
      // Cap zoom-out so the polygon/sphere depth-buffer doesn't z-fight.
      controls.minDistance = 110;
      controls.maxDistance = 600;
    }
    g.pointOfView({ lat: 25, lng: 0, altitude: 2.4 }, 0);
  }, [size.w]);

  const { maxHits, minHits } = useMemo(() => {
    const hits = data.map((d) => d.hits);
    return { maxHits: Math.max(...hits, 1), minHits: Math.min(...hits, 1) };
  }, [data]);

  // Water tone — pure black so land shows up as a lighter gray cap.
  const globeMaterial = useMemo(
    () => new MeshPhongMaterial({ color: 0x000000, emissive: 0x000000, shininess: 6 }),
    [],
  );

  // Sparse but crisp starfield — generated once at high resolution.
  const starfieldUrl = useMemo(() => makeStarfield(900, 4096, 2048), []);

  const labels = useMemo<GlobeLabel[]>(() => {
    const countryLabels: GlobeLabel[] = countries
      .map((c) => {
        const cent = centroidOf(c.geometry);
        if (!cent) return null;
        return { name: c.properties.name, lng: cent[0], lat: cent[1] };
      })
      .filter((x): x is GlobeLabel => x !== null);
    return [...OCEAN_LABELS, ...countryLabels];
  }, [countries]);

  // Memoized accessors so react-globe.gl doesn't refresh the scene every render.
  // Land = light gray cap, water = the black globe sphere underneath.
  // Altitude is raised slightly + fully opaque cap/side to prevent z-fighting
  // with the sphere when the camera zooms out (depth-buffer precision drops).
  const polyCapColor = useCallback(() => "rgb(56, 60, 68)", []);
  const polySideColor = useCallback(() => "rgb(40, 44, 52)", []);
  const polyStrokeColor = useCallback(() => "rgba(120, 130, 145, 0.55)", []);
  const polyAltitude = useCallback(() => 0.016, []);
  const labelLat = useCallback((d: object) => (d as GlobeLabel).lat, []);
  const labelLng = useCallback((d: object) => (d as GlobeLabel).lng, []);
  const labelText = useCallback((d: object) => (d as GlobeLabel).name, []);
  const labelSizeFn = useCallback(
    (d: object) => ((d as GlobeLabel).ocean ? 0.7 : 0.45),
    [],
  );
  const labelColorFn = useCallback(
    (d: object) =>
      (d as GlobeLabel).ocean ? "rgba(160,185,210,0.45)" : "rgba(220,225,235,0.78)",
    [],
  );
  const labelDotRadiusFn = useCallback(() => 0, []);
  // Labels must sit above the raised polygons (altitude 0.012) to avoid
  // clipping/z-fighting; keep some headroom.
  const labelAltitudeFn = useCallback(() => 0.018, []);
  const htmlLatFn = useCallback((d: object) => (d as GlobeMarker).latitude, []);
  const htmlLngFn = useCallback((d: object) => (d as GlobeMarker).longitude, []);
  const htmlElementFn = useCallback(
    (d: object) => {
      const m = d as GlobeMarker;
      return buildMarker(m, colorFor(m.hits, minHits, maxHits), theme, requestsLabel);
    },
    [minHits, maxHits, theme, requestsLabel],
  );

  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        height: "100%",
        background: "#000",
        overflow: "hidden",
      }}
    >
      <Globe
        ref={globeRef}
        width={size.w}
        height={size.h}
        backgroundColor="#000000"
        backgroundImageUrl={starfieldUrl}
        showAtmosphere={true}
        atmosphereColor="lightskyblue"
        atmosphereAltitude={0.20}
        globeMaterial={globeMaterial}
        showGlobe={true}
        polygonsData={countries}
        polygonCapColor={polyCapColor}
        polygonSideColor={polySideColor}
        polygonStrokeColor={polyStrokeColor}
        polygonAltitude={polyAltitude}
        polygonsTransitionDuration={0}
        labelsData={labels}
        labelLat={labelLat}
        labelLng={labelLng}
        labelText={labelText}
        labelSize={labelSizeFn}
        labelColor={labelColorFn}
        labelDotRadius={labelDotRadiusFn}
        labelAltitude={labelAltitudeFn}
        labelResolution={2}
        labelsTransitionDuration={0}
        htmlElementsData={data}
        htmlLat={htmlLatFn}
        htmlLng={htmlLngFn}
        htmlAltitude={0.02}
        htmlElement={htmlElementFn}
        htmlTransitionDuration={0}
      />
    </div>
  );
}
