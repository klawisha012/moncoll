import { createEffect, createMemo, createSignal, onCleanup, onMount, For, Show } from "solid-js";
import { TestTube, Play, AlertTriangle, ShieldAlert, ShieldOff, Clock, ShieldCheck } from "lucide-solid";
import { api } from "../api/client";
import type {
  Connection,
  CrowdsecRunResult,
  CrowdsecScenario,
  TestCase,
  TestFamily,
  TestRunResult,
  TestResultStatus,
  TestTrafficResponse,
  TrafficDataPoint,
} from "../api/client";
import { useSettings } from "../context/SettingsContext";
import TrafficChart from "../components/charts/TrafficChart";
import { injectionLabel, injectionName } from "../utils/ruleNames";

type SubTab = "modsec" | "crowdsec";

const FAMILY_ORDER: TestFamily[] = [
  "xss",
  "sqli",
  "rce",
  "lfi",
  "rfi",
  "scanner",
  "protocol_attack",
  "protocol_enforce",
  "method",
  "multipart",
  "java",
  "php",
  "session_fixation",
  "generic",
  "blocking",
  "blocking",
];

const STATUS_COLOR: Record<TestResultStatus, string> = {
  blocked: "var(--red)",
  "fired-but-not-blocked": "var(--amber, #f59e0b)",
  passed: "var(--ok)",
  timeout: "var(--text-muted)",
};

const getStatusIcon = (status: TestResultStatus) => {
  if (status === "blocked") return <ShieldOff size={14} />;
  if (status === "fired-but-not-blocked") return <ShieldAlert size={14} />;
  if (status === "passed") return <ShieldCheck size={14} />;
  return <Clock size={14} />;
};

export default function Tests() {
  const settings = useSettings();
  const [activeSub, setActiveSub] = createSignal<SubTab>("modsec");
  const [catalog, setCatalog] = createSignal<TestCase[] | null>(null);
  const [catalogError, setCatalogError] = createSignal<string | null>(null);

  const [connections, setConnections] = createSignal<Connection[]>([]);
  const [connectionId, setConnectionId] = createSignal<number | null>(null);

  const [runningId, setRunningId] = createSignal<string | null>(null);
  const [lastResult, setLastResult] = createSignal<TestRunResult | null>(null);
  const [runError, setRunError] = createSignal<string | null>(null);
  const [traffic, setTraffic] = createSignal<TrafficDataPoint[] | null>(null);
  const [markerTraffic, setMarkerTraffic] = createSignal<TestTrafficResponse | null>(null);

  // ── Fetchers ────────────────────────────────────────────
  onMount(() => {
    let cancelled = false;
    api
      .getTestsCatalog()
      .then((res) => {
        if (!cancelled) setCatalog(res.tests);
      })
      .catch((e) => {
        if (!cancelled) setCatalogError(e instanceof Error ? e.message : String(e));
      });
    api
      .getConnections()
      .then((res) => {
        if (cancelled) return;
        const enabled = res.filter((c) => c.enabled);
        setConnections(enabled);
        if (enabled.length > 0) setConnectionId(enabled[0].id);
      })
      .catch(() => {
        // Connections API may fail in dev — fall back to localhost-only.
      });
    onCleanup(() => {
      cancelled = true;
    });
  });

  // Refresh traffic chart every 10s — the chart is the proof the test fired.
  // The marker overlay relies on this polling to actually show the spike
  // once Vector flushes the new audit row into ClickHouse.
  createEffect(() => {
    const connId = connectionId();
    let cancelled = false;
    const run = () =>
      api
        .getTraffic(1, connId)
        .then((res) => {
          if (!cancelled) setTraffic(res);
        })
        .catch(() => {
          if (!cancelled) setTraffic([]);
        });
    run();
    const id = setInterval(run, 10_000);
    onCleanup(() => {
      cancelled = true;
      clearInterval(id);
    });
  });

  // After a Run, poll the marker endpoint until rows land (or 8s expires).
  createEffect(() => {
    const result = lastResult();
    if (!result || !result.marker) return;
    let cancelled = false;
    let attempts = 0;
    const tick = async () => {
      attempts += 1;
      try {
        const data = await api.getTestTrafficByMarker(result.marker);
        if (cancelled) return;
        setMarkerTraffic(data);
        if (data.events.length > 0 || attempts >= 8) return;
      } catch {
        // 400 = bad marker (shouldn't happen — server-generated UUID); stop.
        return;
      }
      if (!cancelled && attempts < 8) setTimeout(tick, 1000);
    };
    tick();
    onCleanup(() => {
      cancelled = true;
    });
  });

  const onRun = async (test: TestCase) => {
    if (runningId()) return;
    setRunningId(test.id);
    setRunError(null);
    setMarkerTraffic(null);
    try {
      const res = await api.runTest({
        test_id: test.id,
        connection_id: connectionId(),
      });
      setLastResult(res);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes("rate limit")) {
        setRunError(settings.t("tests.rateLimit"));
      } else if (msg.includes("unknown test_id")) {
        setRunError(settings.t("tests.unknownTest"));
      } else {
        setRunError(settings.t("tests.runError").replace("{msg}", msg));
      }
    } finally {
      setRunningId(null);
    }
  };

  // Group catalog by family — render families in fixed order.
  const grouped = createMemo(() => {
    const map = new Map<TestFamily, TestCase[]>();
    const cat = catalog();
    if (!cat) return map;
    for (const test of cat) {
      const existing = map.get(test.family) ?? [];
      existing.push(test);
      map.set(test.family, existing);
    }
    return map;
  });

  const markerTimes = createMemo(() => markerTraffic()?.timestamps ?? []);

  return (
    <div class="page">
      <header class="page-header">
        <div class="page-title-row">
          <h1 class="page-title">
            <TestTube size={22} style={{ "margin-right": "10px", "vertical-align": "-3px" }} />
            {settings.t("tests.title")}
          </h1>
        </div>
        <p class="page-subtitle">{settings.t("tests.subtitle")}</p>
      </header>

      {/* Warning banner */}
      <div
        class="card"
        style={{
          padding: "12px 14px",
          "margin-bottom": "16px",
          display: "flex",
          "align-items": "flex-start",
          gap: "10px",
          "border-left": "6px solid var(--amber, #f59e0b)",
        }}
      >
        <AlertTriangle size={18} style={{ color: "var(--amber, #f59e0b)", "flex-shrink": 0, "margin-top": "2px" }} />
        <div style={{ "font-size": "13px", "line-height": 1.45, color: "var(--text-secondary)" }}>{settings.t("tests.warning")}</div>
      </div>

      {/* Sub-tab switcher */}
      <div style={{ display: "flex", gap: "0", "margin-bottom": "16px", "border-bottom": "2px solid var(--ink)" }}>
        <For each={["modsec", "crowdsec"] as SubTab[]}>
          {(sub) => {
            const active = () => activeSub() === sub;
            return (
              <button
                onClick={() => setActiveSub(sub)}
                style={{
                  padding: "10px 22px",
                  background: active() ? "var(--ink)" : "transparent",
                  color: active() ? "var(--cream)" : "var(--text-secondary)",
                  border: "none",
                  "border-radius": "0",
                  cursor: "pointer",
                  "font-family": "var(--font-cond)",
                  "font-size": "12px",
                  "font-weight": 700,
                  "letter-spacing": "0.14em",
                  "text-transform": "uppercase",
                }}
              >
                {sub === "modsec" ? settings.t("tests.tab.modsec") : settings.t("tests.tab.crowdsec")}
              </button>
            );
          }}
        </For>
      </div>

      {/* Target connection picker */}
      <div
        class="card"
        style={{
          padding: "14px 16px",
          "margin-bottom": "16px",
          display: "flex",
          "align-items": "center",
          gap: "14px",
          "flex-wrap": "wrap",
        }}
      >
        <label
          for="tests-target"
          style={{
            "font-family": "var(--font-cond)",
            "font-weight": 700,
            "font-size": "12px",
            "letter-spacing": "0.12em",
            "text-transform": "uppercase",
            color: "var(--text-secondary)",
          }}
        >
          {settings.t("tests.target")}
        </label>
        <select
          id="tests-target"
          value={connectionId() ?? ""}
          onChange={(e) => setConnectionId(e.currentTarget.value ? Number(e.currentTarget.value) : null)}
          style={{
            padding: "8px 12px",
            border: "2px solid var(--ink)",
            "border-radius": "0",
            background: "var(--card-bg)",
            color: "var(--text-primary)",
            "font-family": "var(--font-mono)",
            "font-size": "13px",
            "min-width": "260px",
          }}
        >
          <For each={connections()}>
            {(c) => (
              <option value={c.id}>
                {c.name} {c.domain ? `(${c.domain})` : ""}
              </option>
            )}
          </For>
        </select>
        <span style={{ "font-size": "12px", color: "var(--text-muted)", flex: 1, "min-width": "200px" }}>{settings.t("tests.target.help")}</span>
      </div>

      {/* Last result panel */}
      <Show when={lastResult()}>
        {(res) => (
          <ResultPanel result={res()} translate={settings.t} markerEvents={markerTraffic()?.events ?? []} />
        )}
      </Show>
      
      <Show when={runError()}>
        <div
          class="card"
          style={{
            padding: "10px 14px",
            "margin-bottom": "16px",
            background: "var(--red)",
            color: "var(--cream)",
            "border-color": "var(--ink)",
            "font-family": "var(--font-mono)",
            "font-size": "13px",
          }}
        >
          {runError()}
        </div>
      </Show>

      {/* Live impact chart */}
      <div
        class="card"
        style={{ "margin-bottom": "16px" }}
      >
        <div class="card-header" style={{ display: "flex", "align-items": "center", gap: "10px", "justify-content": "space-between" }}>
          <h2 style={{ "font-size": "15px", margin: "0" }}>{settings.t("tests.impact.title")}</h2>
          <span style={{ "font-size": "11px", color: "var(--text-muted)", "font-family": "var(--font-mono)" }}>{settings.t("tests.impact.help")}</span>
        </div>
        <div style={{ padding: "8px 4px" }}>
          <TrafficChart data={traffic()} loading={traffic() === null} markerTimes={markerTimes()} />
        </div>
      </div>

      {/* Catalog */}
      <Show when={activeSub() === "modsec"}>
        <ModSecCatalog
          grouped={grouped()}
          familyOrder={FAMILY_ORDER}
          runningId={runningId()}
          onRun={onRun}
          catalogError={catalogError()}
          catalog={catalog()}
          translate={settings.t}
        />
      </Show>

      <Show when={activeSub() === "crowdsec"}>
        <CrowdsecCatalog translate={settings.t} />
      </Show>
    </div>
  );
}

function CrowdsecCatalog(props: { translate: (key: string) => string }) {
  const [scenarios, setScenarios] = createSignal<CrowdsecScenario[] | null>(null);
  const [runningId, setRunningId] = createSignal<string | null>(null);
  const [lastResult, setLastResult] = createSignal<CrowdsecRunResult | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  onMount(() => {
    let cancelled = false;
    api
      .getCrowdsecTestCatalog()
      .then((res) => {
        if (!cancelled) setScenarios(res.scenarios);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    onCleanup(() => {
      cancelled = true;
    });
  });

  const onRun = async (s: CrowdsecScenario) => {
    if (runningId()) return;
    setRunningId(s.id);
    setError(null);
    try {
      const res = await api.runCrowdsecScenario(s.id);
      setLastResult(res);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes("rate limit")) {
        setError(props.translate("tests.rateLimit"));
      } else {
        setError(props.translate("tests.runError").replace("{msg}", msg));
      }
    } finally {
      setRunningId(null);
    }
  };

  return (
    <Show
      when={scenarios() !== null}
      fallback={
        <Show
          when={error()}
          fallback={
            <div class="card" style={{ padding: "32px", "text-align": "center", color: "var(--text-muted)" }}>
              {props.translate("tests.loading")}
            </div>
          }
        >
          <div class="card" style={{ padding: "18px", color: "var(--red)" }}>
            {error()}
          </div>
        </Show>
      }
    >
      <Show
        when={scenarios()!.length > 0}
        fallback={
          <div class="card" style={{ padding: "32px", "text-align": "center", color: "var(--text-muted)" }}>
            {props.translate("tests.crowdsec.empty")}
          </div>
        }
      >
        <div style={{ display: "flex", "flex-direction": "column", gap: "14px" }}>
          <Show when={lastResult()}>
            {(res) => (
              <div
                class="card"
                style={{
                  padding: "14px 16px",
                  "border-left": `6px solid ${res().decisions_after.length > 0 ? "var(--red)" : "var(--text-muted)"}`,
                }}
              >
                <div
                  style={{
                    "font-family": "var(--font-cond)",
                    "font-size": "12px",
                    "font-weight": 700,
                    "letter-spacing": "0.12em",
                    "text-transform": "uppercase",
                    "margin-bottom": "8px",
                    color: "var(--text-secondary)",
                  }}
                >
                  {res().scenario}
                </div>
                <div style={{ "font-size": "13px", color: "var(--text-primary)", "margin-bottom": "6px" }}>
                  {res().bursts_sent} requests sent · {props.translate("tests.crowdsec.decisions")}:{" "}
                  <b>{res().decisions_after.length}</b>
                </div>
                <Show when={res().decisions_after.length > 0}>
                  <div style={{ "font-family": "var(--font-mono)", "font-size": "12px", color: "var(--text-secondary)" }}>
                    {res().decisions_after.join(", ")}
                  </div>
                </Show>
                <div
                  style={{
                    "margin-top": "6px",
                    "font-size": "11px",
                    color: "var(--text-muted)",
                    "font-family": "var(--font-mono)",
                  }}
                >
                  {props.translate("tests.crowdsec.window")} · target {res().target_url}
                </div>
              </div>
            )}
          </Show>
          
          <Show when={error()}>
            <div
              class="card"
              style={{
                padding: "10px 14px",
                background: "var(--red)",
                color: "var(--cream)",
                "font-family": "var(--font-mono)",
                "font-size": "13px",
              }}
            >
              {error()}
            </div>
          </Show>
          
          <div
            style={{
              display: "grid",
              "grid-template-columns": "repeat(auto-fill, minmax(280px, 1fr))",
              gap: "12px",
            }}
          >
            <For each={scenarios()}>
              {(s) => (
                <div
                  style={{
                    border: "2px solid var(--ink)",
                    background: "var(--card-bg)",
                    padding: "12px 14px",
                    "box-shadow": "var(--shadow-offset-sm)",
                    display: "flex",
                    "flex-direction": "column",
                    gap: "8px",
                  }}
                >
                  <div style={{ "font-family": "var(--font-mono)", "font-weight": 700, "font-size": "12px" }}>
                    {s.scenario}
                  </div>
                  <div style={{ "font-size": "12px", color: "var(--text-secondary)", "line-height": 1.4 }}>
                    {s.description}
                  </div>
                  <div style={{ "font-size": "11px", color: "var(--text-muted)", "font-family": "var(--font-mono)" }}>
                    burst = {s.burst_size} requests
                  </div>
                  <button
                    onClick={() => onRun(s)}
                    disabled={runningId() !== null}
                    style={{
                      "margin-top": "auto",
                      padding: "6px 10px",
                      background: runningId() === s.id ? "var(--red)" : runningId() ? "var(--card-bg)" : "var(--ink)",
                      color: "var(--cream)",
                      border: "2px solid var(--ink)",
                      "font-family": "var(--font-cond)",
                      "font-weight": 700,
                      "font-size": "11px",
                      "letter-spacing": "0.12em",
                      "text-transform": "uppercase",
                      cursor: runningId() !== null ? "not-allowed" : "pointer",
                      display: "inline-flex",
                      "align-items": "center",
                      "justify-content": "center",
                      gap: "6px",
                    }}
                  >
                    <Play size={11} />
                    {runningId() === s.id ? props.translate("tests.running") : props.translate("tests.run")}
                  </button>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>
    </Show>
  );
}

// ── Sub-components ─────────────────────────────────────────────

function ResultPanel(props: {
  result: TestRunResult;
  markerEvents: { timestamp: string; rule_id: string; severity: string; uri: string }[];
  translate: (key: string) => string;
}) {
  const color = () => STATUS_COLOR[props.result.status];
  return (
    <div
      class="card"
      style={{
        padding: "14px 16px",
        "margin-bottom": "16px",
        "border-left": `6px solid ${color()}`,
      }}
    >
      <div style={{ display: "flex", "align-items": "center", gap: "12px", "margin-bottom": "8px" }}>
        <span
          style={{
            display: "inline-flex",
            "align-items": "center",
            gap: "6px",
            background: color(),
            color: "var(--cream)",
            padding: "4px 10px",
            border: "2px solid var(--ink)",
            "font-family": "var(--font-cond)",
            "font-size": "11px",
            "font-weight": 700,
            "letter-spacing": "0.14em",
            "text-transform": "uppercase",
          }}
        >
          {getStatusIcon(props.result.status)}
          {props.translate(`tests.status.${props.result.status}`)}
        </span>
        <Show when={props.result.blocked_by}>
          <span style={{ "font-family": "var(--font-mono)", "font-size": "12px", color: "var(--text-secondary)" }}>
            {injectionLabel(props.result.blocked_by!)}
          </span>
        </Show>
        <Show when={props.result.http_code !== null}>
          <span style={{ "font-family": "var(--font-mono)", "font-size": "12px", color: "var(--text-secondary)" }}>
            HTTP {props.result.http_code}
          </span>
        </Show>
        <Show when={props.result.latency_ms !== null}>
          <span style={{ "font-family": "var(--font-mono)", "font-size": "12px", color: "var(--text-muted)" }}>
            {props.result.latency_ms}ms
          </span>
        </Show>
      </div>
      <div style={{ "font-size": "12px", color: "var(--text-secondary)", "margin-bottom": "8px" }}>
        {props.translate(`tests.status.${props.result.status}.desc`)}
      </div>
      <div style={{ "font-family": "var(--font-mono)", "font-size": "11px", color: "var(--text-muted)" }}>
        marker={props.result.marker}
      </div>
      <Show when={props.markerEvents.length > 0}>
        <div style={{ "margin-top": "12px" }}>
          <div
            style={{
              "font-family": "var(--font-cond)",
              "font-size": "11px",
              "letter-spacing": "0.12em",
              "text-transform": "uppercase",
              color: "var(--text-secondary)",
              "margin-bottom": "6px",
              "border-bottom": "1px solid var(--border-subtle)",
              "padding-bottom": "4px",
            }}
          >
            {props.translate("tests.events.title")}
          </div>
          <table style={{ width: "100%", "border-collapse": "collapse", "font-size": "12px" }}>
            <thead>
              <tr style={{ "text-align": "left", color: "var(--text-muted)" }}>
                <th style={thStyle}>{props.translate("tests.events.col.time")}</th>
                <th style={thStyle}>{props.translate("tests.events.col.rule")}</th>
                <th style={thStyle}>{props.translate("tests.events.col.severity")}</th>
                <th style={thStyle}>{props.translate("tests.events.col.uri")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={props.markerEvents.slice(0, 20)}>
                {(ev) => (
                  <tr style={{ "border-top": "1px solid var(--border-subtle)" }}>
                    <td style={tdStyle}>{new Date(ev.timestamp).toLocaleTimeString()}</td>
                    <td style={{ ...tdStyle, "font-family": "var(--font-mono)" }}>{injectionLabel(ev.rule_id)}</td>
                    <td style={tdStyle}>{ev.severity}</td>
                    <td style={{ ...tdStyle, "font-family": "var(--font-mono)", color: "var(--text-muted)" }}>{ev.uri}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </div>
  );
}

const thStyle = {
  padding: "4px 6px",
  "font-family": "var(--font-cond)",
  "font-weight": 700,
  "font-size": "10px",
  "letter-spacing": "0.12em",
  "text-transform": "uppercase",
};

const tdStyle = {
  padding: "5px 6px",
  color: "var(--text-primary)",
};

function ModSecCatalog(props: {
  grouped: Map<TestFamily, TestCase[]>;
  familyOrder: TestFamily[];
  runningId: string | null;
  onRun: (test: TestCase) => void;
  catalogError: string | null;
  catalog: TestCase[] | null;
  translate: (key: string) => string;
}) {
  const [selectedFamily, setSelectedFamily] = createSignal<string>("all");

  const uniqueFamilies = () => {
    const seen = new Set<TestFamily>();
    const list: TestFamily[] = [];
    for (const family of props.familyOrder) {
      if (!seen.has(family)) {
        seen.add(family);
        const tests = props.grouped.get(family);
        if (tests && tests.length > 0) {
          list.push(family);
        }
      }
    }
    return list;
  };

  const displayedFamilies = () => {
    const fam = selectedFamily();
    if (fam === "all") return uniqueFamilies();
    return uniqueFamilies().filter((f) => f === fam);
  };

  return (
    <Show
      when={props.catalog !== null}
      fallback={
        <Show
          when={props.catalogError}
          fallback={
            <div class="card" style={{ padding: "32px", "text-align": "center", color: "var(--text-muted)" }}>
              Loading…
            </div>
          }
        >
          <div class="card" style={{ padding: "18px", color: "var(--red)" }}>
            {props.catalogError}
          </div>
        </Show>
      }
    >
      <Show
        when={props.catalog!.length > 0}
        fallback={
          <div class="card" style={{ padding: "32px", "text-align": "center", color: "var(--text-muted)" }}>
            {props.translate("tests.empty")}
          </div>
        }
      >
        {/* Category filter */}
        <div
          class="card"
          style={{
            padding: "14px 16px",
            "margin-bottom": "16px",
            display: "flex",
            "align-items": "center",
            gap: "14px",
            "flex-wrap": "wrap",
          }}
        >
          <label
            for="tests-category"
            style={{
              "font-family": "var(--font-cond)",
              "font-weight": 700,
              "font-size": "12px",
              "letter-spacing": "0.12em",
              "text-transform": "uppercase",
              color: "var(--text-secondary)",
            }}
          >
            {props.translate("tests.category")}
          </label>
          <select
            id="tests-category"
            value={selectedFamily()}
            onChange={(e) => setSelectedFamily(e.currentTarget.value)}
            style={{
              padding: "8px 12px",
              border: "2px solid var(--ink)",
              "border-radius": "0",
              background: "var(--card-bg)",
              color: "var(--text-primary)",
              "font-family": "var(--font-mono)",
              "font-size": "13px",
              "min-width": "260px",
            }}
          >
            <option value="all">{props.translate("tests.category.all")}</option>
            <For each={uniqueFamilies()}>
              {(family) => {
                const tests = props.grouped.get(family);
                return (
                  <option value={family}>
                    {props.translate(`tests.family.${family}`)} ({tests?.length ?? 0})
                  </option>
                );
              }}
            </For>
          </select>
        </div>

        <div style={{ display: "flex", "flex-direction": "column", gap: "14px" }}>
          <For each={displayedFamilies()}>
            {(family) => {
              const tests = props.grouped.get(family);
              if (!tests || tests.length === 0) return null;
              return (
                <details class="card" open style={{ "margin-bottom": 0 }}>
                  <summary
                    style={{
                      cursor: "pointer",
                      padding: "12px 14px",
                      "font-family": "var(--font-cond)",
                      "font-weight": 700,
                      "letter-spacing": "0.1em",
                      "text-transform": "uppercase",
                      "font-size": "13px",
                      "border-bottom": "2px solid var(--ink)",
                      display: "flex",
                      "align-items": "center",
                      "justify-content": "space-between",
                    }}
                  >
                    <span>{props.translate(`tests.family.${family}`)}</span>
                    <span
                      style={{
                        "font-family": "var(--font-mono)",
                        "font-size": "11px",
                        color: "var(--text-muted)",
                        "letter-spacing": 0,
                        "text-transform": "none",
                      }}
                    >
                      {tests.length}
                    </span>
                  </summary>
                  <div
                    style={{
                      display: "grid",
                      "grid-template-columns": "repeat(auto-fill, minmax(260px, 1fr))",
                      gap: "10px",
                      padding: "14px",
                    }}
                  >
                    <For each={tests}>
                      {(test) => (
                        <TestRunCard
                          test={test}
                          busy={props.runningId !== null}
                          onRun={props.onRun}
                          runLabel={props.translate("tests.run")}
                          runningLabel={props.translate("tests.running")}
                        />
                      )}
                    </For>
                  </div>
                </details>
              );
            }}
          </For>
        </div>
      </Show>
    </Show>
  );
}

function TestRunCard(props: {
  test: TestCase;
  busy: boolean;
  onRun: (t: TestCase) => void;
  runLabel: string;
  runningLabel: string;
}) {
  return (
    <div
      style={{
        border: "2px solid var(--ink)",
        background: "var(--card-bg)",
        padding: "10px 12px",
        display: "flex",
        "flex-direction": "column",
        gap: "8px",
        "box-shadow": "var(--shadow-offset-sm)",
      }}
    >
      <div
        style={{
          display: "flex",
          "align-items": "baseline",
          gap: "8px",
        }}
      >
        <span
          style={{
            "font-family": "var(--font-cond)",
            "font-size": "14px",
            "font-weight": 700,
            "letter-spacing": "0.04em",
            color: "var(--text-primary)",
          }}
        >
          {injectionName(props.test.rule_id)}
        </span>
        <span
          style={{
            "font-family": "var(--font-mono)",
            "font-size": "11px",
            color: "var(--text-muted)",
          }}
        >
          {props.test.rule_id}
        </span>
      </div>
      <div
        style={{
          "font-size": "11px",
          color: "var(--text-muted)",
          "font-family": "var(--font-mono)",
          "word-break": "break-all",
          "min-height": "28px",
        }}
      >
        {props.test.method} {props.test.path}
        {props.test.query["param"] ? `?param=${truncate(props.test.query["param"], 32)}` : ""}
      </div>
      <button
        onClick={() => props.onRun(props.test)}
        disabled={props.busy}
        style={{
          padding: "6px 10px",
          background: props.busy ? "var(--card-bg)" : "var(--ink)",
          color: props.busy ? "var(--text-muted)" : "var(--cream)",
          border: "2px solid var(--ink)",
          "font-family": "var(--font-cond)",
          "font-weight": 700,
          "font-size": "11px",
          "letter-spacing": "0.12em",
          "text-transform": "uppercase",
          cursor: props.busy ? "not-allowed" : "pointer",
          display: "inline-flex",
          "align-items": "center",
          "justify-content": "center",
          gap: "6px",
        }}
      >
        <Play size={11} />
        {props.busy ? props.runningLabel : props.runLabel}
      </button>
    </div>
  );
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
