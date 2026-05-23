import { useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  Connection,
  GeoipMapPoint,
  UnresolvedIp,
  SecurityEvent,
} from "../api/client";
import { useSettings } from "../context/SettingsContext";
import { EmptyState } from "../components/charts/chart-utils";
import GeoipGlobe from "../components/GeoipGlobe";
import Geoip2DMap from "../components/Geoip2DMap";
import { injectionLabel } from "../utils/ruleNames";
import { subscribe, type GeoipMapDelta } from "../realtime/client";

interface EnrichedGeoPoint extends GeoipMapPoint {
  topIp?: string;
  topAttacks?: string[];
}

type TimeUnit = "minutes" | "hours" | "days";
type View = "2d" | "3d";

const UNITS: { value: TimeUnit; labelKey: string; multiplier: number }[] = [
  { value: "minutes", labelKey: "dashboard.ui.minutes", multiplier: 1 / 60 },
  { value: "hours", labelKey: "dashboard.ui.hours", multiplier: 1 },
  { value: "days", labelKey: "dashboard.ui.days", multiplier: 24 },
];

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

function GeoipMapPanel({
  data,
  loading,
  events,
  view,
}: {
  data: GeoipMapPoint[] | null;
  loading: boolean;
  events: SecurityEvent[] | null;
  view: View;
}) {
  const { theme, t } = useSettings();
  const isLight = theme === "light";

  const enriched = useMemo<EnrichedGeoPoint[]>(() => {
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
  }, [data, events]);

  const mapBg = isLight ? "#f5f6fa" : "#0b0f1e";

  if (!data || data.length === 0) {
    if (loading) return <EmptyState loading={true} message="" />;
    return (
      <div style={{ width: "100%", height: "100%", background: mapBg, display: "flex", alignItems: "center", justifyContent: "center", color: isLight ? "#1a1d2e" : "#e8ecf4", fontFamily: "var(--font-display)", fontSize: 18, padding: 24, textAlign: "center" }}>
        {t("dashboard.empty.noGeoData")}
      </div>
    );
  }

  if (view === "3d") {
    return <GeoipGlobe data={enriched} theme={theme} requestsLabel={t("dashboard.tooltip.requests")} />;
  }

  return <Geoip2DMap data={enriched} theme={theme} requestsLabel={t("dashboard.tooltip.requests")} />;
}

export default function Home() {
  const { t } = useSettings();
  const [connections, setConnections] = useState<Connection[]>([]);
  const [connectionId, setConnectionId] = useState<number | null>(null);
  const [timeUnit, setTimeUnit] = useState<TimeUnit>("hours");
  const [timeValue, setTimeValue] = useState<number>(24);
  const [view, setView] = useState<View>("3d");
  const [data, setData] = useState<GeoipMapPoint[] | null>(null);
  const [unresolved, setUnresolved] = useState<UnresolvedIp[] | null>(null);
  const [events, setEvents] = useState<SecurityEvent[] | null>(null);
  const [loading, setLoading] = useState(true);
  const cancelledRef = useRef(false);

  const hours = useMemo(() => {
    const m = UNITS.find((u) => u.value === timeUnit)?.multiplier ?? 1;
    return Math.max(1, Math.round(timeValue * m));
  }, [timeUnit, timeValue]);

  useEffect(() => {
    api.getConnections().then(setConnections).catch(() => {});
  }, []);

  useEffect(() => {
    cancelledRef.current = false;
    let initial = true;
    const fetchAll = async () => {
      try {
        const [m, u, ev] = await Promise.all([
          api.getGeoipMap(hours, connectionId),
          api.getGeoipUnresolved(hours, connectionId),
          api.getEvents(50, "all", hours, connectionId),
        ]);
        if (cancelledRef.current) return;
        setData(m);
        setUnresolved(u);
        setEvents(ev);
      } catch {
        // keep last good data
      } finally {
        if (initial && !cancelledRef.current) {
          setLoading(false);
          initial = false;
        }
      }
    };
    fetchAll();
    // Fallback poll: re-fetch snapshot every 60s so the time-windowed view
    // (`hours=24`) stays accurate even after live deltas accumulate. Live
    // updates from Centrifugo arrive every ~500ms (see subscribe below).
    const id = setInterval(fetchAll, 60_000);
    return () => {
      cancelledRef.current = true;
      clearInterval(id);
    };
  }, [hours, connectionId]);

  // ── Real-time map deltas via Centrifugo ──
  // Backend aggregates raw geoip events into 500ms-batched deltas and
  // publishes to `dashboard:map`. We merge them into existing state so the
  // map lights up new attacks immediately without waiting for the next
  // fallback poll.
  useEffect(() => {
    const unsub = subscribe<GeoipMapDelta>("dashboard:map", (delta) => {
      if (cancelledRef.current) return;
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
    return unsub;
  }, []);

  const unresolvedList = unresolved ?? [];
  const unresolvedTotal = unresolvedList.reduce((a, d) => a + d.hits, 0);

  return (
    <>
      <div className="home-canvas">
        <GeoipMapPanel data={data} loading={loading} events={events} view={view} />
      </div>

      <div role="tablist" aria-label={t("dashboard.geoMap.toggle")} className="home-view-toggle">
        {(["2d", "3d"] as const).map((m) => {
          const active = view === m;
          return (
            <button
              key={m}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setView(m)}
              className={`home-view-tab ${active ? "active" : ""}`}
            >
              {m === "2d" ? t("dashboard.geoMap.view2d") : t("dashboard.geoMap.view3d")}
            </button>
          );
        })}
      </div>

      <aside className="home-settings">
        <div className="home-settings-section">
          <label className="home-settings-label">{t("dashboard.ui.timeRange")}</label>
          <div className="home-settings-row">
            <input
              type="number"
              min={1}
              value={timeValue}
              onChange={(e) => setTimeValue(Math.max(1, Number(e.target.value) || 1))}
              className="home-settings-input"
            />
            <select
              value={timeUnit}
              onChange={(e) => setTimeUnit(e.target.value as TimeUnit)}
              className="home-settings-select"
            >
              {UNITS.map((u) => (
                <option key={u.value} value={u.value}>{t(u.labelKey)}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="home-settings-section">
          <label className="home-settings-label">{t("dashboard.ui.domain")}</label>
          <select
            value={connectionId ?? ""}
            onChange={(e) => setConnectionId(e.target.value === "" ? null : Number(e.target.value))}
            className="home-settings-select"
            style={{ width: "100%" }}
          >
            <option value="">{t("dashboard.ui.allDomains")}</option>
            {connections.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
        </div>

        {unresolvedList.length > 0 && (
          <>
            <div className="home-settings-divider" />
            <div className="home-settings-section">
              <label className="home-settings-label">
                {unresolvedList.length} {t("dashboard.unresolvedIP")}{unresolvedList.length === 1 ? "" : "s"} · {unresolvedTotal.toLocaleString()} {t("dashboard.hit")}{unresolvedTotal === 1 ? "" : "s"}
              </label>
              <div className="home-settings-unresolved">
                {unresolvedList.slice(0, 8).map((d) => {
                  const cls = classifyUnresolvedIp(d.ip);
                  return (
                    <div key={d.ip} title={cls.reason} className="home-settings-unresolved-row">
                      <span className="home-settings-ip">{d.ip}</span>
                      <span className="home-settings-tag">{cls.kind}</span>
                      <span className="home-settings-count">{d.hits.toLocaleString()}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </>
        )}
      </aside>
    </>
  );
}
