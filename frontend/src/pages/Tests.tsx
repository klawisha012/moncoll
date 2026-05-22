import { useCallback, useEffect, useMemo, useState } from "react";
import { TestTube, Play, AlertTriangle, ShieldAlert, ShieldOff, Clock, ShieldCheck } from "lucide-react";
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
];

const STATUS_ICON: Record<TestResultStatus, React.ReactNode> = {
  blocked: <ShieldOff size={14} />,
  "fired-but-not-blocked": <ShieldAlert size={14} />,
  passed: <ShieldCheck size={14} />,
  timeout: <Clock size={14} />,
};

const STATUS_COLOR: Record<TestResultStatus, string> = {
  blocked: "var(--red)",
  "fired-but-not-blocked": "var(--amber, #f59e0b)",
  passed: "var(--ok)",
  timeout: "var(--text-muted)",
};


export default function Tests() {
  const { t } = useSettings();
  const [activeSub, setActiveSub] = useState<SubTab>("modsec");
  const [catalog, setCatalog] = useState<TestCase[] | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);

  const [connections, setConnections] = useState<Connection[]>([]);
  const [connectionId, setConnectionId] = useState<number | null>(null);

  const [runningId, setRunningId] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<TestRunResult | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [traffic, setTraffic] = useState<TrafficDataPoint[] | null>(null);
  const [markerTraffic, setMarkerTraffic] = useState<TestTrafficResponse | null>(null);

  // ── Fetchers ────────────────────────────────────────────
  useEffect(() => {
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
    return () => {
      cancelled = true;
    };
  }, []);

  // Refresh traffic chart every 10s — the chart is the proof the test fired.
  // The marker overlay relies on this polling to actually show the spike
  // once Vector flushes the new audit row into ClickHouse.
  useEffect(() => {
    let cancelled = false;
    const run = () =>
      api
        .getTraffic(1, connectionId)
        .then((res) => {
          if (!cancelled) setTraffic(res);
        })
        .catch(() => {
          if (!cancelled) setTraffic([]);
        });
    run();
    const id = setInterval(run, 10_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [connectionId]);

  // After a Run, poll the marker endpoint until rows land (or 8s expires).
  useEffect(() => {
    if (!lastResult || !lastResult.marker) return;
    let cancelled = false;
    let attempts = 0;
    const tick = async () => {
      attempts += 1;
      try {
        const data = await api.getTestTrafficByMarker(lastResult.marker);
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
    return () => {
      cancelled = true;
    };
  }, [lastResult]);

  const onRun = useCallback(
    async (test: TestCase) => {
      if (runningId) return;
      setRunningId(test.id);
      setRunError(null);
      setMarkerTraffic(null);
      try {
        const res = await api.runTest({
          test_id: test.id,
          connection_id: connectionId,
        });
        setLastResult(res);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        if (msg.includes("rate limit")) {
          setRunError(t("tests.rateLimit"));
        } else if (msg.includes("unknown test_id")) {
          setRunError(t("tests.unknownTest"));
        } else {
          setRunError(t("tests.runError").replace("{msg}", msg));
        }
      } finally {
        setRunningId(null);
      }
    },
    [runningId, connectionId, t],
  );

  // Group catalog by family — render families in fixed order.
  const grouped = useMemo(() => {
    const map = new Map<TestFamily, TestCase[]>();
    if (!catalog) return map;
    for (const test of catalog) {
      const existing = map.get(test.family) ?? [];
      existing.push(test);
      map.set(test.family, existing);
    }
    return map;
  }, [catalog]);

  const markerTimes = useMemo(() => markerTraffic?.timestamps ?? [], [markerTraffic]);

  // ── Render ──────────────────────────────────────────────
  return (
    <div className="page">
      <header className="page-header">
        <div className="page-title-row">
          <h1 className="page-title">
            <TestTube size={22} style={{ marginRight: 10, verticalAlign: "-3px" }} />
            {t("tests.title")}
          </h1>
        </div>
        <p className="page-subtitle">{t("tests.subtitle")}</p>
      </header>

      {/* Warning banner */}
      <div
        className="card"
        style={{
          padding: "12px 14px",
          marginBottom: 16,
          display: "flex",
          alignItems: "flex-start",
          gap: 10,
          borderLeft: "6px solid var(--amber, #f59e0b)",
        }}
      >
        <AlertTriangle size={18} style={{ color: "var(--amber, #f59e0b)", flexShrink: 0, marginTop: 2 }} />
        <div style={{ fontSize: 13, lineHeight: 1.45, color: "var(--text-secondary)" }}>{t("tests.warning")}</div>
      </div>

      {/* Sub-tab switcher */}
      <div style={{ display: "flex", gap: 0, marginBottom: 16, borderBottom: "2px solid var(--ink)" }}>
        {(["modsec", "crowdsec"] as SubTab[]).map((sub) => (
          <button
            key={sub}
            onClick={() => setActiveSub(sub)}
            style={{
              padding: "10px 22px",
              background: activeSub === sub ? "var(--ink)" : "transparent",
              color: activeSub === sub ? "var(--cream)" : "var(--text-secondary)",
              border: "none",
              borderRadius: 0,
              cursor: "pointer",
              fontFamily: "var(--font-cond)",
              fontSize: 12,
              fontWeight: 700,
              letterSpacing: "0.14em",
              textTransform: "uppercase",
            }}
          >
            {sub === "modsec" ? t("tests.tab.modsec") : t("tests.tab.crowdsec")}
          </button>
        ))}
      </div>

      {/* Target connection picker */}
      <div
        className="card"
        style={{
          padding: "14px 16px",
          marginBottom: 16,
          display: "flex",
          alignItems: "center",
          gap: 14,
          flexWrap: "wrap",
        }}
      >
        <label
          htmlFor="tests-target"
          style={{
            fontFamily: "var(--font-cond)",
            fontWeight: 700,
            fontSize: 12,
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            color: "var(--text-secondary)",
          }}
        >
          {t("tests.target")}
        </label>
        <select
          id="tests-target"
          value={connectionId ?? ""}
          onChange={(e) => setConnectionId(e.target.value ? Number(e.target.value) : null)}
          style={{
            padding: "8px 12px",
            border: "2px solid var(--ink)",
            borderRadius: 0,
            background: "var(--card-bg)",
            color: "var(--text-primary)",
            fontFamily: "var(--font-mono)",
            fontSize: 13,
            minWidth: 260,
          }}
        >
          <option value="">{t("tests.target.localhost")}</option>
          {connections.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name} {c.domains.length ? `(${c.domains[0]})` : ""}
            </option>
          ))}
        </select>
        <span style={{ fontSize: 12, color: "var(--text-muted)", flex: 1, minWidth: 200 }}>{t("tests.target.help")}</span>
      </div>

      {/* Last result panel */}
      {lastResult && (
        <ResultPanel result={lastResult} translate={t} markerEvents={markerTraffic?.events ?? []} />
      )}
      {runError && (
        <div
          className="card"
          style={{
            padding: "10px 14px",
            marginBottom: 16,
            background: "var(--red)",
            color: "var(--cream)",
            borderColor: "var(--ink)",
            fontFamily: "var(--font-mono)",
            fontSize: 13,
          }}
        >
          {runError}
        </div>
      )}

      {/* Live impact chart */}
      <div
        className="card"
        style={{ marginBottom: 16 }}
      >
        <div className="card-header" style={{ display: "flex", alignItems: "center", gap: 10, justifyContent: "space-between" }}>
          <h2 style={{ fontSize: 15, margin: 0 }}>{t("tests.impact.title")}</h2>
          <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{t("tests.impact.help")}</span>
        </div>
        <div style={{ padding: "8px 4px" }}>
          <TrafficChart data={traffic} loading={traffic === null} markerTimes={markerTimes} />
        </div>
      </div>

      {/* Catalog */}
      {activeSub === "modsec" && (
        <ModSecCatalog
          grouped={grouped}
          familyOrder={FAMILY_ORDER}
          runningId={runningId}
          onRun={onRun}
          catalogError={catalogError}
          catalog={catalog}
          translate={t}
        />
      )}

      {activeSub === "crowdsec" && <CrowdsecCatalog translate={t} />}
    </div>
  );
}

function CrowdsecCatalog({ translate }: { translate: (key: string) => string }) {
  const [scenarios, setScenarios] = useState<CrowdsecScenario[] | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<CrowdsecRunResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getCrowdsecTestCatalog()
      .then((res) => {
        if (!cancelled) setScenarios(res.scenarios);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const onRun = async (s: CrowdsecScenario) => {
    if (runningId) return;
    setRunningId(s.id);
    setError(null);
    try {
      const res = await api.runCrowdsecScenario(s.id);
      setLastResult(res);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes("rate limit")) {
        setError(translate("tests.rateLimit"));
      } else {
        setError(translate("tests.runError").replace("{msg}", msg));
      }
    } finally {
      setRunningId(null);
    }
  };

  if (error && !scenarios) {
    return (
      <div className="card" style={{ padding: 18, color: "var(--red)" }}>
        {error}
      </div>
    );
  }
  if (scenarios === null) {
    return (
      <div className="card" style={{ padding: 32, textAlign: "center", color: "var(--text-muted)" }}>
        {translate("tests.loading")}
      </div>
    );
  }
  if (scenarios.length === 0) {
    return (
      <div className="card" style={{ padding: 32, textAlign: "center", color: "var(--text-muted)" }}>
        {translate("tests.crowdsec.empty")}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {lastResult && (
        <div
          className="card"
          style={{
            padding: "14px 16px",
            borderLeft: `6px solid ${lastResult.decisions_after.length > 0 ? "var(--red)" : "var(--text-muted)"}`,
          }}
        >
          <div
            style={{
              fontFamily: "var(--font-cond)",
              fontSize: 12,
              fontWeight: 700,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              marginBottom: 8,
              color: "var(--text-secondary)",
            }}
          >
            {lastResult.scenario}
          </div>
          <div style={{ fontSize: 13, color: "var(--text-primary)", marginBottom: 6 }}>
            {lastResult.bursts_sent} requests sent · {translate("tests.crowdsec.decisions")}:{" "}
            <b>{lastResult.decisions_after.length}</b>
          </div>
          {lastResult.decisions_after.length > 0 && (
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-secondary)" }}>
              {lastResult.decisions_after.join(", ")}
            </div>
          )}
          <div
            style={{
              marginTop: 6,
              fontSize: 11,
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
            }}
          >
            {translate("tests.crowdsec.window")} · target {lastResult.target_url}
          </div>
        </div>
      )}
      {error && (
        <div
          className="card"
          style={{
            padding: "10px 14px",
            background: "var(--red)",
            color: "var(--cream)",
            fontFamily: "var(--font-mono)",
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
          gap: 12,
        }}
      >
        {scenarios.map((s) => (
          <div
            key={s.id}
            style={{
              border: "2px solid var(--ink)",
              background: "var(--card-bg)",
              padding: "12px 14px",
              boxShadow: "var(--shadow-offset-sm)",
              display: "flex",
              flexDirection: "column",
              gap: 8,
            }}
          >
            <div style={{ fontFamily: "var(--font-mono)", fontWeight: 700, fontSize: 12 }}>
              {s.scenario}
            </div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.4 }}>
              {s.description}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              burst = {s.burst_size} requests
            </div>
            <button
              onClick={() => onRun(s)}
              disabled={runningId !== null}
              style={{
                marginTop: "auto",
                padding: "6px 10px",
                background: runningId === s.id ? "var(--red)" : runningId ? "var(--card-bg)" : "var(--ink)",
                color: runningId ? "var(--cream)" : "var(--cream)",
                border: "2px solid var(--ink)",
                fontFamily: "var(--font-cond)",
                fontWeight: 700,
                fontSize: 11,
                letterSpacing: "0.12em",
                textTransform: "uppercase",
                cursor: runningId !== null ? "not-allowed" : "pointer",
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 6,
              }}
            >
              <Play size={11} />
              {runningId === s.id ? translate("tests.running") : translate("tests.run")}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────

function ResultPanel({
  result,
  markerEvents,
  translate,
}: {
  result: TestRunResult;
  markerEvents: { timestamp: string; rule_id: string; severity: string; uri: string }[];
  translate: (key: string) => string;
}) {
  const color = STATUS_COLOR[result.status];
  return (
    <div
      className="card"
      style={{
        padding: "14px 16px",
        marginBottom: 16,
        borderLeft: `6px solid ${color}`,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            background: color,
            color: "var(--cream)",
            padding: "4px 10px",
            border: "2px solid var(--ink)",
            fontFamily: "var(--font-cond)",
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: "0.14em",
            textTransform: "uppercase",
          }}
        >
          {STATUS_ICON[result.status]}
          {translate(`tests.status.${result.status}`)}
        </span>
        {result.blocked_by && (
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-secondary)" }}>
            {injectionLabel(result.blocked_by)}
          </span>
        )}
        {result.http_code !== null && (
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-secondary)" }}>
            HTTP {result.http_code}
          </span>
        )}
        {result.latency_ms !== null && (
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-muted)" }}>
            {result.latency_ms}ms
          </span>
        )}
      </div>
      <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 8 }}>
        {translate(`tests.status.${result.status}.desc`)}
      </div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
        marker={result.marker}
      </div>
      {markerEvents.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div
            style={{
              fontFamily: "var(--font-cond)",
              fontSize: 11,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              color: "var(--text-secondary)",
              marginBottom: 6,
              borderBottom: "1px solid var(--border-subtle)",
              paddingBottom: 4,
            }}
          >
            {translate("tests.events.title")}
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--text-muted)" }}>
                <th style={thStyle}>{translate("tests.events.col.time")}</th>
                <th style={thStyle}>{translate("tests.events.col.rule")}</th>
                <th style={thStyle}>{translate("tests.events.col.severity")}</th>
                <th style={thStyle}>{translate("tests.events.col.uri")}</th>
              </tr>
            </thead>
            <tbody>
              {markerEvents.slice(0, 20).map((ev, i) => (
                <tr key={i} style={{ borderTop: "1px solid var(--border-subtle)" }}>
                  <td style={tdStyle}>{new Date(ev.timestamp).toLocaleTimeString()}</td>
                  <td style={{ ...tdStyle, fontFamily: "var(--font-mono)" }}>{injectionLabel(ev.rule_id)}</td>
                  <td style={tdStyle}>{ev.severity}</td>
                  <td style={{ ...tdStyle, fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>{ev.uri}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const thStyle: React.CSSProperties = {
  padding: "4px 6px",
  fontFamily: "var(--font-cond)",
  fontWeight: 700,
  fontSize: 10,
  letterSpacing: "0.12em",
  textTransform: "uppercase",
};

const tdStyle: React.CSSProperties = {
  padding: "5px 6px",
  color: "var(--text-primary)",
};

function ModSecCatalog({
  grouped,
  familyOrder,
  runningId,
  onRun,
  catalogError,
  catalog,
  translate,
}: {
  grouped: Map<TestFamily, TestCase[]>;
  familyOrder: TestFamily[];
  runningId: string | null;
  onRun: (test: TestCase) => void;
  catalogError: string | null;
  catalog: TestCase[] | null;
  translate: (key: string) => string;
}) {
  if (catalogError) {
    return (
      <div className="card" style={{ padding: 18, color: "var(--red)" }}>
        {catalogError}
      </div>
    );
  }
  if (catalog === null) {
    return (
      <div className="card" style={{ padding: 32, textAlign: "center", color: "var(--text-muted)" }}>
        Loading…
      </div>
    );
  }
  if (catalog.length === 0) {
    return (
      <div className="card" style={{ padding: 32, textAlign: "center", color: "var(--text-muted)" }}>
        {translate("tests.empty")}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {familyOrder.map((family) => {
        const tests = grouped.get(family);
        if (!tests || tests.length === 0) return null;
        return (
          <details key={family} className="card" open style={{ marginBottom: 0 }}>
            <summary
              style={{
                cursor: "pointer",
                padding: "12px 14px",
                fontFamily: "var(--font-cond)",
                fontWeight: 700,
                letterSpacing: "0.1em",
                textTransform: "uppercase",
                fontSize: 13,
                borderBottom: "2px solid var(--ink)",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <span>{translate(`tests.family.${family}`)}</span>
              <span
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: 11,
                  color: "var(--text-muted)",
                  letterSpacing: 0,
                  textTransform: "none",
                }}
              >
                {tests.length}
              </span>
            </summary>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))",
                gap: 10,
                padding: 14,
              }}
            >
              {tests.map((test) => (
                <TestRunCard
                  key={test.id}
                  test={test}
                  busy={runningId !== null}
                  onRun={onRun}
                  runLabel={translate("tests.run")}
                  runningLabel={translate("tests.running")}
                />
              ))}
            </div>
          </details>
        );
      })}
    </div>
  );
}

function TestRunCard({
  test,
  busy,
  onRun,
  runLabel,
  runningLabel,
}: {
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
        flexDirection: "column",
        gap: 8,
        boxShadow: "var(--shadow-offset-sm)",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "baseline",
          gap: 8,
        }}
      >
        <span
          style={{
            fontFamily: "var(--font-cond)",
            fontSize: 14,
            fontWeight: 700,
            letterSpacing: "0.04em",
            color: "var(--text-primary)",
          }}
        >
          {injectionName(test.rule_id)}
        </span>
        <span
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            color: "var(--text-muted)",
          }}
        >
          {test.rule_id}
        </span>
      </div>
      <div
        style={{
          fontSize: 11,
          color: "var(--text-muted)",
          fontFamily: "var(--font-mono)",
          wordBreak: "break-all",
          minHeight: 28,
        }}
      >
        {test.method} {test.path}
        {test.query["param"] ? `?param=${truncate(test.query["param"], 32)}` : ""}
      </div>
      <button
        onClick={() => onRun(test)}
        disabled={busy}
        style={{
          padding: "6px 10px",
          background: busy ? "var(--card-bg)" : "var(--ink)",
          color: busy ? "var(--text-muted)" : "var(--cream)",
          border: "2px solid var(--ink)",
          fontFamily: "var(--font-cond)",
          fontWeight: 700,
          fontSize: 11,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          cursor: busy ? "not-allowed" : "pointer",
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 6,
        }}
      >
        <Play size={11} />
        {busy ? runningLabel : runLabel}
      </button>
    </div>
  );
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
