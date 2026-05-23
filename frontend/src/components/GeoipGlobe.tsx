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

// One-time stylesheet injection — keeps hover/active transitions out of
// inline-style noise on every marker re-render. id-gate is idempotent
// across HMR/StrictMode.
const MARKER_STYLE_ID = "geoip-globe-marker-style";
function ensureMarkerStyle(): void {
  if (typeof document === "undefined") return;
  if (document.getElementById(MARKER_STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = MARKER_STYLE_ID;
  style.textContent = `
    /* react-globe.gl uses three.js CSS2DRenderer которое навешивает
       inline transform: translate(-50%,-50%) translate3d(x,y,0) на каждый
       html-маркер — наш собственный transform на этом же узле молча
       перетирается. Поэтому ЛЮБОЙ outer-transform тут бесполезен. Делаем
       wrapper фиксированного размера (14×20 — bbox пина), а пин и
       карточку позиционируем absolute внутри. Так центр wrapper'а
       совпадает с lat/lng-точкой (где react-globe.gl его и ставит), а
       мы вручную смещаем пин так чтобы его кончик попадал в этот центр.
       Без этого пин «съезжает» при отдалении камеры — фикс-pixel
       элемент не уменьшается вместе с глобусом. */
    .geoip-marker {
      position: absolute;
      width: 14px;
      height: 20px;
      pointer-events: auto;
      cursor: pointer;
      font-family: var(--font-sans, system-ui);
    }
    .geoip-marker.active {
      z-index: 10;
    }
    .geoip-marker-pin {
      position: absolute;
      left: 0;
      /* bottom: 50% — нижний край SVG (= кончик пина) совпадает с
         вертикальным центром wrapper'а, который и есть lat/lng. */
      bottom: 50%;
      width: 14px;
      height: 20px;
      filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.55));
      transition: transform 0.14s ease-out;
      /* Hover-scale крутится из точки кончика, не из геометрического
         центра SVG — иначе пин «прыгает» при наведении. */
      transform-origin: 50% 100%;
    }
    /* Hover-увеличение пина — hint что метка кликабельна. */
    .geoip-marker:hover .geoip-marker-pin,
    .geoip-marker.active .geoip-marker-pin {
      transform: scale(1.15);
    }
    .geoip-marker-card {
      position: absolute;
      left: 50%;
      /* 50% (центр wrapper'а) + 10px (полная высота пина наверх от
         кончика) + 6px зазор = bottom-edge карточки. */
      bottom: calc(50% + 26px);
      min-width: 200px;
      max-width: 280px;
      padding: 9px 11px;
      background: rgba(11, 15, 30, 0.95);
      border: 1px solid rgba(255, 255, 255, 0.18);
      border-radius: 4px;
      box-shadow: 0 6px 22px rgba(0, 0, 0, 0.55);
      backdrop-filter: blur(8px);
      color: #e8ecf4;
      font-size: 11.5px;
      line-height: 1.5;
      opacity: 0;
      visibility: hidden;
      transform: translateX(-50%) translateY(4px);
      transition:
        opacity 0.14s ease-out,
        transform 0.14s ease-out,
        visibility 0s linear 0.14s;
      pointer-events: none;
    }
    /* Card opens on click (.active), not on hover — иначе при плотной
       кластеризации меток курсор не может попасть на соседний пин,
       тулапы перекрывают цели. */
    .geoip-marker.active .geoip-marker-card {
      opacity: 1;
      visibility: visible;
      transform: translateX(-50%) translateY(0);
      transition:
        opacity 0.14s ease-out,
        transform 0.14s ease-out;
    }
    .geoip-marker-card-head {
      display: flex;
      align-items: baseline;
      gap: 6px;
      padding-bottom: 5px;
      margin-bottom: 5px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }
    .geoip-marker-cc {
      font-weight: 700;
      font-size: 14px;
      letter-spacing: 0.5px;
    }
    .geoip-marker-city {
      font-size: 11.5px;
      color: #c5cad6;
      font-weight: 500;
    }
    .geoip-marker-row {
      display: flex;
      gap: 6px;
      align-items: baseline;
      font-size: 10.5px;
      margin-top: 2px;
    }
    .geoip-marker-label {
      color: #6c7384;
      text-transform: uppercase;
      font-size: 9px;
      letter-spacing: 0.6px;
      min-width: 56px;
    }
    .geoip-marker-value {
      color: #e8ecf4;
      font-family: var(--font-mono, ui-monospace, monospace);
    }
    .geoip-marker-attacks {
      margin-top: 5px;
      padding-top: 5px;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
    }
    .geoip-marker-attack-item {
      font-size: 10.5px;
      padding-left: 9px;
      position: relative;
    }
    .geoip-marker-attack-item:before {
      content: "›";
      position: absolute;
      left: 0;
      opacity: 0.6;
    }
    .geoip-marker-hits {
      margin-top: 6px;
      padding-top: 5px;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
      font-weight: 600;
      font-size: 11.5px;
    }
  `;
  document.head.appendChild(style);
}

function fmtCoord(lat: number, lon: number): string {
  const latH = lat >= 0 ? "N" : "S";
  const lonH = lon >= 0 ? "E" : "W";
  return `${Math.abs(lat).toFixed(2)}°${latH}, ${Math.abs(lon).toFixed(2)}°${lonH}`;
}

function markerKey(d: GlobeMarker): string {
  // Stable identifier across data refetches/refresh — совпадает с тем что
  // backend публикует в дельтах (см. backend/src/realtime/consumer.py).
  return `${(d.country_code || "").toUpperCase()}|${d.latitude.toFixed(2)}|${d.longitude.toFixed(2)}|${d.city_name || ""}`;
}

// Глобальное состояние активной метки. Глобальное (а не React-state) потому
// что DOM-элементы маркеров создаются императивно через htmlElement-колбэк
// react-globe.gl, и при пересоздании (на data refetch) нам нужно вернуть
// `active` класс именно тому маркеру, который был открыт — пользователь
// не должен терять выделение на каждом 500ms-тике live-апдейта.
let _activeMarkerKey: string | null = null;
let _documentClickRegistered = false;

function setActiveMarker(key: string | null): void {
  _activeMarkerKey = key;
  if (typeof document === "undefined") return;
  document.querySelectorAll<HTMLElement>(".geoip-marker").forEach((el) => {
    el.classList.toggle("active", el.dataset.geoipKey === key);
  });
}

function ensureDocumentClick(): void {
  if (_documentClickRegistered || typeof document === "undefined") return;
  _documentClickRegistered = true;
  // Клик мимо любого маркера → закрываем активную карточку. Любой клик на
  // самом маркере останавливает propagation и не доходит сюда.
  document.addEventListener("click", (e) => {
    const target = e.target as HTMLElement | null;
    if (!target || !target.closest(".geoip-marker")) {
      if (_activeMarkerKey !== null) setActiveMarker(null);
    }
  });
}

function buildMarker(
  d: GlobeMarker,
  color: string,
  _theme: "light" | "dark",
  requestsLabel: string,
): HTMLDivElement {
  ensureMarkerStyle();
  ensureDocumentClick();

  const key = markerKey(d);
  const el = document.createElement("div");
  el.className = "geoip-marker";
  el.dataset.geoipKey = key;
  el.tabIndex = 0;
  // Восстановить открытое состояние после react-globe.gl recreate (например
  // при live-апдейте data из Centrifugo).
  if (_activeMarkerKey === key) el.classList.add("active");

  el.addEventListener("click", (e) => {
    e.stopPropagation();
    if (_activeMarkerKey === key) {
      // toggle off — второй клик по тому же пину закрывает карточку
      setActiveMarker(null);
    } else {
      setActiveMarker(key);
    }
  });
  // Keyboard-equivalent: Enter/Space на focused пине открывает карточку
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      e.stopPropagation();
      setActiveMarker(_activeMarkerKey === key ? null : key);
    }
    if (e.key === "Escape" && _activeMarkerKey === key) {
      setActiveMarker(null);
    }
  });

  const cc = escapeHtml(d.country_code || "—");
  const city = d.city_name ? escapeHtml(d.city_name) : "";
  const coords = fmtCoord(d.latitude, d.longitude);
  const ip = d.topIp ? escapeHtml(d.topIp) : "";
  const attackRows =
    d.topAttacks && d.topAttacks.length > 0
      ? d.topAttacks
          .map((a) => `<div class="geoip-marker-attack-item" style="color:${color};">${escapeHtml(a)}</div>`)
          .join("")
      : "";

  // Пин рендерится первым (он в потоке wrapper'а), карточка — absolute
  // выше пина. Раскрытие только по клику (.active), см. CSS.
  // Border-left на карточке красим severity-цветом — узнаваемая подпись.
  el.innerHTML = `
    <svg class="geoip-marker-pin" viewBox="0 0 14 20">
      <path d="M7 0 C3.13 0 0 3.13 0 7 c0 5.25 7 13 7 13 s7 -7.75 7 -13 c0 -3.87 -3.13 -7 -7 -7 z" fill="${color}" stroke="#0b0f1e" stroke-width="1"/>
      <circle cx="7" cy="7" r="2.6" fill="#0b0f1e"/>
    </svg>
    <div class="geoip-marker-card" style="border-left: 3px solid ${color};">
      <div class="geoip-marker-card-head">
        <span class="geoip-marker-cc">${cc}</span>
        ${city ? `<span class="geoip-marker-city">${city}</span>` : ""}
      </div>
      <div class="geoip-marker-row">
        <span class="geoip-marker-label">Coords</span>
        <span class="geoip-marker-value">${escapeHtml(coords)}</span>
      </div>
      ${
        ip
          ? `<div class="geoip-marker-row">
               <span class="geoip-marker-label">Top IP</span>
               <span class="geoip-marker-value">${ip}</span>
             </div>`
          : ""
      }
      ${
        attackRows
          ? `<div class="geoip-marker-attacks">
               <div class="geoip-marker-label" style="min-width:0; margin-bottom:3px;">Attacks</div>
               ${attackRows}
             </div>`
          : ""
      }
      <div class="geoip-marker-hits" style="color:${color};">
        ${d.hits.toLocaleString()} <span style="color:#9aa3b4; font-weight:400;">${escapeHtml(requestsLabel)}</span>
      </div>
    </div>
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
