import { createEffect, createMemo, createSignal, onCleanup, onMount, For, Show } from "solid-js";
import {
  api,
  GeoipMapPoint,
  UnresolvedIp,
  SecurityEvent,
} from "../api/client";
import { useSettings } from "../context/SettingsContext";
import { useGlobalFilters } from "../context/GlobalFiltersContext";
import { EmptyState } from "../components/charts/chart-utils";
import GeoipGlobe from "../components/GeoipGlobe";
import Geoip2DMap from "../components/Geoip2DMap";
import { injectionLabel } from "../utils/ruleNames";
import { subscribe, type GeoipMapDelta } from "../realtime/client";

interface EnrichedGeoPoint extends GeoipMapPoint {
  topIp?: string;
  topAttacks?: string[];
}

type View = "2d" | "3d";

function classifyUnresolvedIp(ip: string): { kind: string; reason: string } {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return { kind: "Other", reason: "Unparseable IPv4 address" };
  }
  const [a, b] = parts;
  if (a === 192 && b === 0 && parts[2] === 2) return { kind: "TEST-NET-1", reason: "RFC 5737." };
  if (a === 198 && b === 51 && parts[2] === 100) return { kind: "TEST-NET-2", reason: "RFC 5737." };
  if (a === 203 && b === 0 && parts[2] === 113) return { kind: "TEST-NET-3", reason: "RFC 5737." };
  if (a === 100 && b >= 64 && b <= 127) return { kind: "CGNAT", reason: "RFC 6598." };
  if (a >= 224 && a <= 239) return { kind: "Multicast", reason: "224.0.0.0/4." };
  if (a >= 240) return { kind: "Reserved", reason: "240.0.0.0/4." };
  return { kind: "Public", reason: "Missing from MaxMind GeoLite2." };
}

function GeoipMapPanel(props: {
  data: GeoipMapPoint[] | null;
  loading: boolean;
  events: SecurityEvent[] | null;
  view: View;
}) {
  const settings = useSettings();
  const isLight = () => settings.theme === "light";

  const enriched = createMemo<EnrichedGeoPoint[]>(() => {
    const data = props.data;
    const events = props.events;
    if (!data) return [];
    if (!events || events.length === 0) return data;
    const byCountry = new globalThis.Map<string, SecurityEvent[]>();
    for (const e of events) {
      const cc = (e.country || "").toUpperCase();
      if (!cc) continue;
      const arr = byCountry.get(cc) ?? [];
      arr.push(e);
      byCountry.set(cc, arr);
    }
    return data.map((p) => {
      const cc = (p.country_code || "").toUpperCase();
      const evts = byCountry.get(cc) ?? [];
      if (evts.length === 0) return p;
      const ipCounts = new globalThis.Map<string, number>();
      for (const ev of evts) {
        if (!ev.ip) continue;
        ipCounts.set(ev.ip, (ipCounts.get(ev.ip) ?? 0) + 1);
      }
      let topIp: string | undefined;
      let max = 0;
      for (const [ip, n] of ipCounts) {
        if (n > max) {
          max = n;
          topIp = ip;
        }
      }
      const attackSet = new Set<string>();
      for (const ev of evts) {
        const label = injectionLabel(ev.type);
        if (label) attackSet.add(label);
        if (attackSet.size >= 3) break;
      }
      return { ...p, topIp, topAttacks: Array.from(attackSet) };
    });
  });

  const mapBg = () => isLight() ? "#f5f6fa" : "#0b0f1e";

  return (
    <Show
      when={props.data && props.data.length > 0}
      fallback={
        <Show when={props.loading} fallback={
          <div style={{ width: "100%", height: "100%", background: mapBg(), display: "flex", "align-items": "center", "justify-content": "center", color: isLight() ? "#1a1d2e" : "#e8ecf4", "font-family": "var(--font-display)", "font-size": "18px", padding: "24px", "text-align": "center" }}>
            {settings.t("dashboard.empty.noGeoData")}
          </div>
        }>
          <EmptyState loading={true} message="" />
        </Show>
      }
    >
      <Show when={props.view === "3d"} fallback={
        <Geoip2DMap data={enriched()} theme={settings.theme} requestsLabel={settings.t("dashboard.tooltip.requests")} />
      }>
        <GeoipGlobe data={enriched()} theme={settings.theme} requestsLabel={settings.t("dashboard.tooltip.requests")} />
      </Show>
    </Show>
  );
}

export default function Home() {
  const settings = useSettings();
  const filters = useGlobalFilters();
  const hours = createMemo(() => Math.max(1, Math.round(filters.selectedHours)));
  const [view, setView] = createSignal<View>("3d");
  const [data, setData] = createSignal<GeoipMapPoint[] | null>(null);
  const [unresolved, setUnresolved] = createSignal<UnresolvedIp[] | null>(null);
  const [events, setEvents] = createSignal<SecurityEvent[] | null>(null);
  const [loading, setLoading] = createSignal(true);

  createEffect(() => {
    const h = hours();
    const connId = filters.connectionId;
    let cancelled = false;

    const fetchAll = async () => {
      try {
        const [m, u, ev] = await Promise.all([
          api.getGeoipMap(h, connId),
          api.getGeoipUnresolved(h, connId),
          api.getEvents(50, "all", h, connId),
        ]);
        if (cancelled) return;
        setData(m);
        setUnresolved(u);
        setEvents(ev);
      } catch {
        // keep last good data
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };
    
    fetchAll();
    // Fallback poll: re-fetch snapshot every 60s so the time-windowed view
    // (`hours=24`) stays accurate even after live deltas accumulate. Live
    // updates from Centrifugo arrive every ~500ms (see subscribe below).
    const id = setInterval(fetchAll, 60_000);

    onCleanup(() => {
      cancelled = true;
      clearInterval(id);
    });
  });

  // ── Real-time map deltas via Centrifugo ──
  // Backend aggregates raw geoip events into 500ms-batched deltas and
  // publishes to `dashboard:map`. We merge them into existing state so the
  // map lights up new attacks immediately without waiting for the next
  // fallback poll.
  onMount(() => {
    const unsub = subscribe<GeoipMapDelta>("dashboard:map", (delta) => {
      setData((prev) => {
        // Index existing points by bucket key (cc|lat|lon|city) for O(1) merge
        const idx = new Map<string, number>();
        const next = [...(prev ?? [])];
        next.forEach((p, i) => {
          const k = `${(p.country_code || "").toUpperCase()}|${p.latitude.toFixed(2)}|${p.longitude.toFixed(2)}|${p.city_name || ""}`;
          idx.set(k, i);
        });
        for (const pt of delta.points) {
          const k = `${pt.cc}|${pt.lat.toFixed(2)}|${pt.lon.toFixed(2)}|${pt.city || ""}`;
          const i = idx.get(k);
          if (i !== undefined) {
            next[i] = { ...next[i], hits: next[i].hits + pt.delta };
          } else {
            const fresh = {
              longitude: pt.lon,
              latitude: pt.lat,
              country_code: pt.cc,
              city_name: pt.city,
              hits: pt.delta,
            };
            idx.set(k, next.length);
            next.push(fresh);
          }
        }
        return next;
      });
    });
    onCleanup(() => unsub());
  });

  const unresolvedList = () => unresolved() ?? [];
  const unresolvedTotal = () => unresolvedList().reduce((a, d) => a + d.hits, 0);

  return (
    <>
      <div class="home-canvas">
        <GeoipMapPanel data={data()} loading={loading()} events={events()} view={view()} />
      </div>

      <div role="tablist" aria-label={settings.t("dashboard.geoMap.toggle")} class="home-view-toggle">
        <For each={["2d", "3d"] as const}>
          {(m) => {
            const active = () => view() === m;
            return (
              <button
                type="button"
                role="tab"
                aria-selected={active()}
                onClick={() => setView(m)}
                class={`home-view-tab ${active() ? "active" : ""}`}
              >
                {m === "2d" ? settings.t("dashboard.geoMap.view2d") : settings.t("dashboard.geoMap.view3d")}
              </button>
            );
          }}
        </For>
      </div>

      <Show when={unresolvedList().length > 0}>
        <aside class="home-settings">
          <div class="home-settings-section">
            <label class="home-settings-label">
              {unresolvedList().length} {settings.t("dashboard.unresolvedIP")}{unresolvedList().length === 1 ? "" : "s"} · {unresolvedTotal().toLocaleString()} {settings.t("dashboard.hit")}{unresolvedTotal() === 1 ? "" : "s"}
            </label>
            <div class="home-settings-unresolved">
              <For each={unresolvedList().slice(0, 8)}>
                {(d) => {
                  const cls = classifyUnresolvedIp(d.ip);
                  return (
                    <div title={cls.reason} class="home-settings-unresolved-row">
                      <span class="home-settings-ip">{d.ip}</span>
                      <span class="home-settings-tag">{cls.kind}</span>
                      <span class="home-settings-count">{d.hits.toLocaleString()}</span>
                    </div>
                  );
                }}
              </For>
            </div>
          </div>
        </aside>
      </Show>
    </>
  );
}
