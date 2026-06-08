import { createEffect, createMemo, createSignal, onCleanup, onMount, For, Show } from "solid-js";
import { TestTube, Play, AlertTriangle, ShieldAlert, ShieldOff, Clock, ShieldCheck, X, Eye } from "lucide-solid";
import { api } from "../api/client";
import { subscribe, type GeoipMapDelta } from "../realtime/client";
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
import { useGlobalFilters } from "../context/GlobalFiltersContext";
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

// Extract HTML body out of a raw HTTP response structure
const extractHtmlBody = (responseRaw: string | null | undefined): string => {
  if (!responseRaw) return "<html><body style='font-family:sans-serif;padding:20px;color:#666;'><h3>No response received</h3></body></html>";
  const parts = responseRaw.split(/\r?\n\r?\n/);
  if (parts.length > 1) {
    return parts.slice(1).join("\n\n");
  }
  return responseRaw;
};

export default function Tests() {
  const settings = useSettings();
  const filters = useGlobalFilters();
  const [activeSub, setActiveSub] = createSignal<SubTab>("modsec");
  const [catalog, setCatalog] = createSignal<TestCase[] | null>(null);
  const [catalogError, setCatalogError] = createSignal<string | null>(null);

  const [runningId, setRunningId] = createSignal<string | null>(null);
  const [lastResult, setLastResult] = createSignal<TestRunResult | null>(null);
  const [runError, setRunError] = createSignal<string | null>(null);
  const [traffic, setTraffic] = createSignal<TrafficDataPoint[] | null>(null);
  const [markerTraffic, setMarkerTraffic] = createSignal<TestTrafficResponse | null>(null);

  // ── Debug Console Signals ─────────────────────────────────
  const [debugResult, setDebugResult] = createSignal<{ type: "modsec"; data: TestRunResult } | { type: "crowdsec"; data: CrowdsecRunResult } | null>(null);
  const [debugOpen, setDebugOpen] = createSignal(false);
  const [debugTab, setDebugTab] = createSignal<string>("request");

  const connectionId = () => filters.connectionId;

  const activeConnection = createMemo(() => {
    const id = filters.connectionId;
    return filters.connections.find((c) => c.id === id);
  });

  const activeConnectionText = () => {
    if (filters.connectionId !== null) {
      const conn = activeConnection();
      if (conn) return conn.domain ? `${conn.name} (${conn.domain})` : conn.name;
      return settings.t("tests.target.none");
    }
    const enabled = filters.connections.filter((c) => c.enabled);
    if (enabled.length > 0) {
      return enabled.map((c) => c.domain ? `${c.name} (${c.domain})` : c.name).join(" + ");
    }
    return settings.t("tests.target.none");
  };

  // ── Fetchers ────────────────────────────────────────────
  onMount(() => {
    let cancelled = false;
    api
      .getTestsCatalog()
      .then((res) => {
        if (!cancelled) setCatalog(res.tests ?? []);
      })
      .catch((e) => {
        if (!cancelled) setCatalogError(e instanceof Error ? e.message : String(e));
      });
  });

  const [realtimeTrigger, setRealtimeTrigger] = createSignal(0);

  // Fetch initial traffic chart data
  createEffect(() => {
    const connId = connectionId();
    realtimeTrigger(); // track reactively
    let cancelled = false;
    api
      .getTraffic(1, connId)
      .then((res) => {
        if (!cancelled) setTraffic(res);
      })
      .catch(() => {
        if (!cancelled) setTraffic([]);
      });
    onCleanup(() => {
      cancelled = true;
    });
  });

  // Poll marker endpoint after a test run until rows land
  // Reacts immediately to real-time events to display spikes without delay!
  createEffect(() => {
    const result = lastResult();
    if (!result || !result.marker) return;
    realtimeTrigger(); // track reactively
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
        return;
      }
      if (!cancelled && attempts < 8) setTimeout(tick, 1000);
    };
    tick();
    onCleanup(() => {
      cancelled = true;
    });
  });

  onMount(() => {
    let lastRefresh = 0;
    const unsubMap = subscribe<GeoipMapDelta>("dashboard:map", (delta) => {
      const now = Date.now();
      // Throttle slightly to prevent rapid polling
      if (now - lastRefresh >= 1500) {
        lastRefresh = now;
        setRealtimeTrigger((t) => t + 1);
      }
    });

    const unsubTraffic = subscribe<{ traffic: any }>("dashboard:traffic:1.0", (payload) => {
      if (payload && payload.traffic) {
        setTraffic(payload.traffic);
      }
    });

    onCleanup(() => {
      unsubMap();
      unsubTraffic();
    });
  });

  const [clientIp, setClientIp] = createSignal<string>("");

  const onRun = async (test: TestCase) => {
    if (runningId()) return;
    setRunningId(test.id);
    setRunError(null);
    setMarkerTraffic(null);
    try {
      const res = await api.runTest({
        test_id: test.id,
        connection_id: connectionId(),
        ip: clientIp().trim() || undefined,
      });
      setLastResult(res);
      // Automatically open the debug drawer console
      setDebugResult({ type: "modsec", data: res });
      // If WAF blocks or returns HTML content, select preview tab directly, else response
      if (res.response_raw && res.response_raw.toLowerCase().includes("content-type: text/html")) {
        setDebugTab("preview");
      } else {
        setDebugTab("response");
      }
      setDebugOpen(true);
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
    <div class="page" style={{ "padding-bottom": debugOpen() ? "470px" : "40px", "transition": "padding-bottom 0.3s ease" }}>
      <header class="page-header">
        <div class="page-title-row">
          <h1 class="page-title">
            <TestTube size={22} style={{ "margin-right": "10px", "vertical-align": "-3px" }} />
            {settings.t("tests.title")}
          </h1>
        </div>
        <p class="page-subtitle">{settings.t("tests.subtitle")}</p>
      </header>

      {/* Target connection status info */}
      <div
        class="card"
        style={{
          padding: "12px 14px",
          "margin-bottom": "16px",
          display: "flex",
          "align-items": "center",
          gap: "10px",
          background: "var(--bg-elevated)",
          border: "2px dashed var(--ink)",
          "flex-wrap": "wrap",
        }}
      >
        <span style={{ "font-family": "var(--font-cond)", "font-weight": 700, "font-size": "12px", "text-transform": "uppercase", color: "var(--text-secondary)" }}>
          {settings.t("tests.target")}:
        </span>
        <span style={{ "font-family": "var(--font-mono)", "font-size": "13px", "font-weight": 700, color: "var(--text-primary)" }}>
          {activeConnectionText()}
        </span>
        <span style={{ "font-size": "11px", color: "var(--text-muted)", "margin-left": "auto" }}>
          {settings.t("tests.target.globalInfo")}
        </span>
      </div>

      {/* Last result panel */}
      <Show when={lastResult()}>
        {(res) => (
          <div style={{ position: "relative" }}>
            <ResultPanel result={res()} translate={settings.t} markerEvents={markerTraffic()?.events ?? []} />
            <button
              onClick={() => {
                setDebugResult({ type: "modsec", data: res() });
                setDebugTab("response");
                setDebugOpen(true);
              }}
              class="btn btn-sm"
              style={{
                position: "absolute",
                top: "14px",
                right: "16px",
                padding: "4px 10px",
                "font-family": "var(--font-mono)",
                "font-size": "11px",
                border: "2px solid var(--ink)",
                background: "var(--cream)",
                color: "var(--ink)",
                "box-shadow": "2px 2px 0 var(--ink)",
                cursor: "pointer",
              }}
            >
              [ {settings.t("tests.showDebug")} ]
            </button>
          </div>
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
      <div class="card" style={{ "margin-bottom": "16px" }}>
        <div class="card-header" style={{ display: "flex", "align-items": "center", gap: "10px", "justify-content": "space-between" }}>
          <h2 style={{ "font-size": "15px", margin: "0" }}>{settings.t("tests.impact.title")}</h2>
          <span style={{ "font-size": "11px", color: "var(--text-muted)", "font-family": "var(--font-mono)" }}>{settings.t("tests.impact.help")}</span>
        </div>
        <div style={{ padding: "8px 4px" }}>
          <TrafficChart data={traffic()} loading={traffic() === null} markerTimes={markerTimes()} />
        </div>
      </div>

      {/* Switcher & Catalog */}
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

      <Show when={activeSub() === "modsec"}>
        <ModSecCatalog
          grouped={grouped()}
          familyOrder={FAMILY_ORDER}
          runningId={runningId()}
          onRun={onRun}
          catalogError={catalogError()}
          catalog={catalog()}
          translate={settings.t}
          clientIp={clientIp()}
          onClientIpChange={setClientIp}
        />
      </Show>

      <Show when={activeSub() === "crowdsec"}>
        <CrowdsecCatalog
          connectionId={connectionId()}
          translate={settings.t}
          onResult={(res) => {
            setDebugResult({ type: "crowdsec", data: res });
            setDebugTab("decisions");
            setDebugOpen(true);
          }}
        />
      </Show>

      {/* Sliding Bottom Debug Drawer Panel */}
      <div
        style={{
          position: "fixed",
          bottom: 0,
          left: 0,
          right: 0,
          height: "450px",
          background: "var(--cream-2)",
          "border-top": "4px solid var(--ink)",
          "box-shadow": "0 -8px 24px rgba(0,0,0,0.15)",
          transform: debugOpen() ? "translateY(0)" : "translateY(100%)",
          transition: "transform 0.3s ease-in-out",
          "z-index": 1000,
          display: "flex",
          "flex-direction": "column",
        }}
      >
        {/* Drawer Header */}
        <div
          style={{
            padding: "10px 16px",
            background: "var(--ink)",
            color: "var(--cream)",
            display: "flex",
            "align-items": "center",
            "justify-content": "space-between",
          }}
        >
          <div style={{ display: "flex", "align-items": "center", gap: "8px" }}>
            <span style={{
              display: "inline-block",
              width: "8px",
              height: "8px",
              background: "#10b981",
              "border-radius": "50%",
              "box-shadow": "0 0 8px #10b981",
            }} />
            <span style={{
              "font-family": "var(--font-cond)",
              "font-weight": 700,
              "font-size": "12px",
              "letter-spacing": "0.14em",
              "text-transform": "uppercase",
            }}>
              {settings.t("tests.debug.console")}
            </span>
          </div>
          <button
            onClick={() => setDebugOpen(false)}
            style={{
              background: "transparent",
              border: "none",
              color: "var(--cream)",
              cursor: "pointer",
              display: "flex",
              "align-items": "center",
              "font-family": "var(--font-mono)",
              "font-size": "12px",
              "font-weight": 700,
              padding: "2px 6px",
            }}
            onMouseEnter={(e) => e.currentTarget.style.color = "var(--red)"}
            onMouseLeave={(e) => e.currentTarget.style.color = "var(--cream)"}
          >
            [ CLOSE ]
          </button>
        </div>

        {/* Drawer Tabs Toolbar */}
        <div
          style={{
            padding: "6px 14px",
            background: "var(--cream-3)",
            "border-bottom": "2px solid var(--ink)",
            display: "flex",
            gap: "8px",
          }}
        >
          <Show when={debugResult()?.type === "modsec"}>
            <button
              class={`btn btn-sm ${debugTab() === "request" ? "active" : ""}`}
              onClick={() => setDebugTab("request")}
              style={tabStyle(debugTab() === "request")}
            >
              HTTP Request Payload
            </button>
            <button
              class={`btn btn-sm ${debugTab() === "response" ? "active" : ""}`}
              onClick={() => setDebugTab("response")}
              style={tabStyle(debugTab() === "response")}
            >
              HTTP Server Response
            </button>
            <button
              class={`btn btn-sm ${debugTab() === "preview" ? "active" : ""}`}
              onClick={() => setDebugTab("preview")}
              style={tabStyle(debugTab() === "preview")}
            >
              Page Preview
            </button>
          </Show>

          <Show when={debugResult()?.type === "crowdsec"}>
            <button
              class={`btn btn-sm ${debugTab() === "decisions" ? "active" : ""}`}
              onClick={() => setDebugTab("decisions")}
              style={tabStyle(debugTab() === "decisions")}
            >
              CrowdSec Decisions Diff
            </button>
            <button
              class={`btn btn-sm ${debugTab() === "timeline" ? "active" : ""}`}
              onClick={() => setDebugTab("timeline")}
              style={tabStyle(debugTab() === "timeline")}
            >
              Test Action Timeline
            </button>
          </Show>
        </div>

        {/* Drawer Content */}
        <div
          style={{
            flex: 1,
            padding: "16px",
            overflow: "auto",
            background: "var(--cream)",
            color: "var(--ink)",
            "font-size": "12px",
            "line-height": "1.6",
          }}
        >
          <Show when={debugResult()} fallback={
            <div style={{ display: "flex", "align-items": "center", "justify-content": "center", height: "100%", color: "var(--text-muted)" }}>
              No debug session active. Run a test to inspect details.
            </div>
          }>
            {(session) => {
              const res = session();
              if (res.type === "modsec") {
                const data = res.data as TestRunResult;
                return (
                  <Show when={debugTab() === "request"} fallback={
                    <Show when={debugTab() === "response"} fallback={
                      <div>
                        <div style={{ "margin-bottom": "8px", "display": "flex", "align-items": "center", "justify-content": "space-between" }}>
                          <div style={{ "font-weight": 700, "font-family": "var(--font-cond)", "text-transform": "uppercase", "color": "var(--text-secondary)" }}>
                            Rendered HTML Page Preview:
                          </div>
                          <div style={{
                            "font-family": "var(--font-mono)",
                            "font-size": "10px",
                            "background": "var(--ink)",
                            "color": "var(--cream)",
                            "padding": "2px 6px",
                            "border-radius": "2px",
                            "text-transform": "uppercase",
                            "letter-spacing": "0.05em",
                          }}>
                            Secured Sandbox iframe
                          </div>
                        </div>
                        <iframe
                          srcdoc={extractHtmlBody(data.response_raw)}
                          sandbox=""
                          style={{
                            width: "100%",
                            height: "320px",
                            background: "#ffffff",
                            border: "2px solid var(--ink)",
                            "box-shadow": "4px 4px 0 var(--ink)",
                            margin: 0,
                          }}
                        />
                      </div>
                    }>
                      <div>
                        <div style={{ "margin-bottom": "8px", "font-weight": 700, "font-family": "var(--font-cond)", "text-transform": "uppercase", "color": "var(--text-secondary)" }}>
                          Raw HTTP Response:
                        </div>
                        <pre style={{
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--border-subtle)",
                          padding: "12px",
                          overflow: "auto",
                          "max-height": "320px",
                          margin: 0,
                          "white-space": "pre-wrap",
                          "font-family": "var(--font-mono)",
                          "font-size": "11.5px",
                        }}>
                          {formatHttpResponse(data.response_raw || "No response received (Request failed/timed out).")}
                        </pre>
                      </div>
                    </Show>
                  }>
                    <div>
                      <div style={{ "margin-bottom": "8px", "font-weight": 700, "font-family": "var(--font-cond)", "text-transform": "uppercase", "color": "var(--text-secondary)" }}>
                        Raw HTTP Request:
                      </div>
                      <pre style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--border-subtle)",
                        padding: "12px",
                        overflow: "auto",
                        "max-height": "320px",
                        margin: 0,
                        "white-space": "pre-wrap",
                        "font-family": "var(--font-mono)",
                        "font-size": "11.5px",
                      }}>
                        {formatHttpRequest(data.request_raw || "Failed to format request.")}
                      </pre>
                    </div>
                  </Show>
                );
              } else {
                const data = res.data as CrowdsecRunResult;
                return (
                  <Show when={debugTab() === "decisions"} fallback={
                    <div>
                      <div style={{ "margin-bottom": "8px", "font-weight": 700, "font-family": "var(--font-cond)", "text-transform": "uppercase", "color": "var(--text-secondary)" }}>
                        E2E Test Execution Timeline:
                      </div>
                      <div style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--border-subtle)",
                        padding: "12px",
                        "font-family": "var(--font-mono)",
                        "font-size": "11.5px",
                      }}>
                        {renderTimeline(data, settings.t)}
                      </div>
                    </div>
                  }>
                    <div>
                      <div style={{ "margin-bottom": "8px", "font-weight": 700, "font-family": "var(--font-cond)", "text-transform": "uppercase", "color": "var(--text-secondary)" }}>
                        CrowdSec Active Decisions snapshot (Before vs After):
                      </div>
                      {renderDecisionsDiff(data, settings.t)}
                    </div>
                  </Show>
                );
              }
            }}
          </Show>
        </div>
      </div>
    </div>
  );
}

function CrowdsecCatalog(props: {
  connectionId: number | null;
  translate: (key: string) => string;
  onResult: (res: CrowdsecRunResult) => void;
}) {
  const [scenarios, setScenarios] = createSignal<CrowdsecScenario[] | null>(null);
  const [runningId, setRunningId] = createSignal<string | null>(null);
  const [lastResult, setLastResult] = createSignal<CrowdsecRunResult | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  const [selectedCategory, setSelectedCategory] = createSignal<string>("");
  const [clientIp, setClientIp] = createSignal<string>("");

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
  });

  const uniqueCategories = createMemo(() => {
    const scens = scenarios();
    if (!scens) return [];
    const seen = new Set<string>();
    const list: string[] = [];
    for (const s of scens) {
      if (s.category && !seen.has(s.category)) {
        seen.add(s.category);
        list.push(s.category);
      }
    }
    return list;
  });

  // Set default selected category to the first available once loaded
  createEffect(() => {
    const cats = uniqueCategories();
    if (cats.length > 0 && (!selectedCategory() || !cats.includes(selectedCategory()))) {
      setSelectedCategory(cats[0]);
    }
  });

  const filteredScenarios = createMemo(() => {
    const cat = selectedCategory();
    const scens = scenarios();
    if (!scens) return [];
    if (!cat) return scens;
    return scens.filter((s) => s.category === cat);
  });

  const onRun = async (s: CrowdsecScenario) => {
    if (runningId()) return;
    setRunningId(s.id);
    setError(null);
    try {
      const res = await api.runCrowdsecScenario(s.id, props.connectionId, clientIp().trim() || undefined);
      setLastResult(res);
      props.onResult(res);
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
          {/* Category & IP filter card */}
          <div
            class="card"
            style={{
              padding: "14px 16px",
              "margin-bottom": "8px",
              display: "flex",
              "align-items": "center",
              gap: "14px",
              "flex-wrap": "wrap",
              background: "var(--bg-elevated)",
            }}
          >
            <div style={{ display: "flex", "align-items": "center", gap: "10px", "flex": 1, "min-width": "260px" }}>
              <label
                for="crowdsec-tests-category"
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
                id="crowdsec-tests-category"
                value={selectedCategory()}
                onChange={(e) => setSelectedCategory(e.currentTarget.value)}
                style={{
                  padding: "8px 12px",
                  border: "2px solid var(--ink)",
                  "border-radius": "0",
                  background: "var(--card-bg)",
                  color: "var(--text-primary)",
                  "font-family": "var(--font-mono)",
                  "font-size": "13px",
                  "min-width": "200px",
                  "flex": 1,
                }}
              >
                <For each={uniqueCategories()}>
                  {(category) => {
                    const count = scenarios()?.filter((s) => s.category === category).length ?? 0;
                    return (
                      <option value={category}>
                        {props.translate(`tests.crowdsec.category.${category}`)} ({count})
                      </option>
                    );
                  }}
                </For>
              </select>
            </div>

            <div style={{ display: "flex", "align-items": "center", gap: "10px", "flex": 1, "min-width": "260px" }}>
              <label
                for="crowdsec-tests-ip"
                style={{
                  "font-family": "var(--font-cond)",
                  "font-weight": 700,
                  "font-size": "12px",
                  "letter-spacing": "0.12em",
                  "text-transform": "uppercase",
                  color: "var(--text-secondary)",
                }}
              >
                {props.translate("tests.ip")}
              </label>
              <input
                id="crowdsec-tests-ip"
                type="text"
                placeholder={props.translate("tests.ipPlaceholder")}
                value={clientIp()}
                onInput={(e) => setClientIp(e.currentTarget.value)}
                style={{
                  padding: "8px 12px",
                  border: "2px solid var(--ink)",
                  "border-radius": "0",
                  background: "var(--card-bg)",
                  color: "var(--text-primary)",
                  "font-family": "var(--font-mono)",
                  "font-size": "13px",
                  "flex": 1,
                }}
              />
            </div>
          </div>

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
                    {res().decisions_after.map((d: any) => typeof d === 'object' ? `${d.value} (${d.reason})` : String(d)).join(", ")}
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
            <For each={filteredScenarios()}>
              {(s) => (
                <div
                  title={`${s.scenario} · ${s.description} · burst=${s.burst_size}`}
                  style={{
                    border: "2px solid var(--ink)",
                    background: "var(--card-bg)",
                    padding: "12px 14px",
                    "box-shadow": "var(--shadow-offset-sm)",
                    display: "flex",
                    "flex-direction": "column",
                    gap: "8px",
                    cursor: "help",
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
  clientIp: string;
  onClientIpChange: (ip: string) => void;
}) {
  const [selectedFamily, setSelectedFamily] = createSignal<string>("");

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

  // Set default selected category to the first active WAF category once loaded
  createEffect(() => {
    const families = uniqueFamilies();
    if (families.length > 0 && (!selectedFamily() || !families.includes(selectedFamily() as TestFamily))) {
      setSelectedFamily(families[0]);
    }
  });

  const displayedFamilies = () => {
    const fam = selectedFamily();
    if (!fam) return [];
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
        {/* Category & Search filter card */}
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
          <div style={{ display: "flex", "align-items": "center", gap: "10px", "flex": 1, "min-width": "260px" }}>
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
                "min-width": "200px",
                "flex": 1,
              }}
            >
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

          <div style={{ display: "flex", "align-items": "center", gap: "10px", "flex": 1, "min-width": "260px" }}>
            <label
              for="tests-ip"
              style={{
                "font-family": "var(--font-cond)",
                "font-weight": 700,
                "font-size": "12px",
                "letter-spacing": "0.12em",
                "text-transform": "uppercase",
                color: "var(--text-secondary)",
              }}
            >
              {props.translate("tests.ip")}
            </label>
            <input
              id="tests-ip"
              type="text"
              placeholder={props.translate("tests.ipPlaceholder")}
              value={props.clientIp}
              onInput={(e) => props.onClientIpChange(e.currentTarget.value)}
              style={{
                padding: "8px 12px",
                border: "2px solid var(--ink)",
                "border-radius": "0",
                background: "var(--card-bg)",
                color: "var(--text-primary)",
                "font-family": "var(--font-mono)",
                "font-size": "13px",
                "flex": 1,
              }}
            />
          </div>
        </div>

        <div style={{ display: "flex", "flex-direction": "column", gap: "14px" }}>
          <For each={displayedFamilies()}>
            {(family) => {
              const tests = props.grouped.get(family) ?? [];
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
  const fullPayload = () => {
    const param = props.test.query ? props.test.query["param"] : null;
    return `${props.test.method} ${props.test.path}${param ? `?param=${param}` : ""}`;
  };

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
        title={fullPayload()}
        style={{
          "font-size": "11px",
          color: "var(--text-muted)",
          "font-family": "var(--font-mono)",
          "word-break": "break-all",
          "min-height": "28px",
          cursor: "help",
        }}
      >
        {props.test.method} {props.test.path}
        {props.test.query && props.test.query["param"] ? `?param=${truncate(props.test.query["param"], 32)}` : ""}
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

const tabStyle = (active: boolean) => ({
  background: active ? "var(--ink)" : "var(--cream)",
  color: active ? "var(--cream)" : "var(--ink)",
  "border-color": "var(--ink)",
  "box-shadow": active ? "none" : "2px 2px 0 var(--ink)",
  transform: active ? "translate(1px, 1px)" : "none",
  "font-family": "var(--font-mono)",
  "padding": "4px 10px",
  "font-size": "11px",
  "letter-spacing": "0",
  "text-transform": "none",
  "cursor": "pointer",
  "transition": "background 0.15s, color 0.15s, transform 0.1s, box-shadow 0.1s"
});

function formatHttpRequest(raw: string) {
  if (!raw) return "No request data.";
  const lines = raw.split("\n");
  return (
    <For each={lines}>
      {(line, idx) => {
        if (idx() === 0) {
          const parts = line.split(" ");
          return (
            <div>
              <span style={{ color: "var(--red)", "font-weight": "bold" }}>{parts[0]}</span>{" "}
              <span style={{ color: "var(--text-primary)" }}>{parts.slice(1).join(" ")}</span>
            </div>
          );
        }
        if (line.includes(": ")) {
          const sep = line.indexOf(": ");
          const name = line.slice(0, sep);
          const value = line.slice(sep + 2);
          return (
            <div>
              <span style={{ color: "var(--text-muted)" }}>{name}:</span>{" "}
              <span style={{ color: "var(--text-primary)" }}>{value}</span>
            </div>
          );
        }
        return <div>{line}</div>;
      }}
    </For>
  );
}

function formatHttpResponse(raw: string) {
  if (!raw) return "No response data.";
  const lines = raw.split("\n");
  return (
    <For each={lines}>
      {(line, idx) => {
        if (idx() === 0) {
          const parts = line.split(" ");
          const status = Number(parts[1]);
          const isBlocked = status === 403;
          const statusColor = isBlocked ? "var(--red)" : (status < 400 ? "var(--ok)" : "var(--amber)");
          return (
            <div>
              <span style={{ color: "var(--text-muted)" }}>{parts[0]}</span>{" "}
              <span style={{ color: statusColor, "font-weight": "bold" }}>{parts.slice(1).join(" ")}</span>
            </div>
          );
        }
        if (line.includes(": ")) {
          const sep = line.indexOf(": ");
          const name = line.slice(0, sep);
          const value = line.slice(sep + 2);
          return (
            <div>
              <span style={{ color: "var(--text-muted)" }}>{name}:</span>{" "}
              <span style={{ color: "var(--text-primary)" }}>{value}</span>
            </div>
          );
        }
        return <div>{line}</div>;
      }}
    </For>
  );
}

function renderTimeline(data: CrowdsecRunResult, t: (key: string) => string) {
  const steps = [
    { time: "0.0s", text: `[1/5] Snapshotting CrowdSec decisions before test (found ${data.decisions_before.length} active bans).`, color: "var(--text-secondary)" },
    { time: "0.2s", text: `[2/5] Firing burst of ${data.bursts_sent} attack requests to internal target: ${data.target_url}`, color: "var(--text-primary)" },
    { time: "1.2s", text: `[3/5] Requests finished. Sleeping for 4.0s to allow CrowdSec to parse logs and register decisions...`, color: "var(--text-muted)" },
    { time: "5.2s", text: `[4/5] Snapshotting decisions after test (found ${data.decisions_after.length} active bans).`, color: "var(--text-secondary)" },
  ];

  const beforeIps = new Set(data.decisions_before.map(d => d.value));
  const newDecisions = data.decisions_after.filter(d => !beforeIps.has(d.value));

  if (newDecisions.length > 0) {
    steps.push({
      time: "5.3s",
      text: `[5/5] SUCCESS! CrowdSec successfully blocked ${newDecisions.length} IP address(es): ${newDecisions.map(d => `${d.value} via scenario ${d.reason}`).join(", ")}`,
      color: "var(--ok)",
    });
  } else {
    steps.push({
      time: "5.3s",
      text: `[5/5] WARNING: No new IP bans registered. Verify that the connection has 'crowdsec_active: true' or that the CrowdSec service parser is configured correctly.`,
      color: "var(--amber)",
    });
  }

  return (
    <div style={{ display: "flex", "flex-direction": "column", gap: "8px" }}>
      <For each={steps}>
        {(step) => (
          <div style={{ display: "flex", gap: "12px" }}>
            <span style={{ color: "var(--text-muted)", "min-width": "45px" }}>+{step.time}</span>
            <span style={{ color: step.color }}>{step.text}</span>
          </div>
        )}
      </For>
    </div>
  );
}

function renderDecisionsDiff(data: CrowdsecRunResult, t: (key: string) => string) {
  const beforeIps = new Set(data.decisions_before.map(d => d.value));
  
  const allDecisions = [...data.decisions_after];
  data.decisions_before.forEach(b => {
    if (!allDecisions.some(a => a.value === b.value)) {
      allDecisions.push({ ...b, type: "unbanned" });
    }
  });

  return (
    <div style={{ overflow: "auto" }}>
      <table style={{ width: "100%", "border-collapse": "collapse", "font-family": "var(--font-mono)", "font-size": "11.5px" }}>
        <thead>
          <tr style={{ "border-bottom": "2px solid var(--ink)", "text-align": "left", color: "var(--text-muted)" }}>
            <th style={{ padding: "6px" }}>IP Address</th>
            <th style={{ padding: "6px" }}>Scenario / Reason</th>
            <th style={{ padding: "6px" }}>Scope</th>
            <th style={{ padding: "6px" }}>Duration</th>
            <th style={{ padding: "6px" }}>Status Change</th>
          </tr>
        </thead>
        <tbody>
          <Show when={allDecisions.length > 0} fallback={
            <tr>
              <td colspan="5" style={{ padding: "12px", "text-align": "center", color: "var(--text-muted)" }}>
                No active decisions before or after this run.
              </td>
            </tr>
          }>
            <For each={allDecisions}>
              {(dec) => {
                const isNew = !beforeIps.has(dec.value) && dec.type !== "unbanned";
                const bg = isNew ? "rgba(44, 122, 61, 0.12)" : (dec.type === "unbanned" ? "rgba(214, 54, 42, 0.08)" : "transparent");
                const border = isNew ? "1px dashed var(--ok)" : "1px solid var(--border-subtle)";
                const statusText = isNew ? "BANNED (NEW)" : (dec.type === "unbanned" ? "UNBANNED" : "ACTIVE (PRE-EXISTING)");
                const statusColor = isNew ? "var(--ok)" : (dec.type === "unbanned" ? "var(--red)" : "var(--text-secondary)");
                
                return (
                  <tr style={{ background: bg, "border-bottom": border }}>
                    <td style={{ padding: "6px", "font-weight": isNew ? "bold" : "normal" }}>{dec.value}</td>
                    <td style={{ padding: "6px", color: "var(--text-secondary)" }}>{dec.reason}</td>
                    <td style={{ padding: "6px", "text-transform": "uppercase" }}>{dec.scope}</td>
                    <td style={{ padding: "6px" }}>{dec.duration || "permanent"}</td>
                    <td style={{ padding: "6px", color: statusColor, "font-weight": "bold" }}>
                      {statusText}
                    </td>
                  </tr>
                );
              }}
            </For>
          </Show>
        </tbody>
      </table>
    </div>
  );
}
