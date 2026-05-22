import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  Shield,
  Ban,
  Unlock,
  RefreshCw,
  Plus,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Globe,
  Package,
  HardDrive,
  Power,
  PowerOff,
  ToggleLeft,
  ToggleRight,
  Search,
  ChevronDown,
  ChevronUp,
  X,
  Cog,
} from "lucide-react";
import { api, CrowdSecStatus, DecisionItem, ScenarioInfo, AlertItem, Connection } from "../api/client";
import { useSettings } from "../context/SettingsContext";

interface ManualBlockLog {
  timestamp: string;
  action: string;
  ip: string;
  duration: string;
  reason: string;
  source: string;
}

interface HubScenario {
  name: string;
  description: string;
  author: string;
  labels: string[];
  installed: boolean;
}

type PanelKey = "status" | "blocks" | "scenarios" | "alerts";

const ALL_PANELS: PanelKey[] = ["status", "blocks", "scenarios", "alerts"];

type TimeUnit = "minutes" | "hours" | "days";

const TIME_UNITS: { value: TimeUnit; label: string; multiplier: number }[] = [
  { value: "minutes", label: "Minutes", multiplier: 1 / 60 },
  { value: "hours", label: "Hours", multiplier: 1 },
  { value: "days", label: "Days", multiplier: 24 },
];

const MAX_HOURS = 8760;

export default function CrowdSec() {
  const { t } = useSettings();
  const [status, setStatus] = useState<CrowdSecStatus | null>(null);
  const [decisions, setDecisions] = useState<DecisionItem[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [hubScenarios, setHubScenarios] = useState<HubScenario[]>([]);
  const [manualLog, setManualLog] = useState<ManualBlockLog[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [serviceEnabled, setServiceEnabled] = useState(true);
  const [scenarioSearch, setScenarioSearch] = useState("");
  const [hubExpanded, setHubExpanded] = useState(false);
  const [expandedCards, setExpandedCards] = useState<Set<string>>(new Set());
  const [visiblePanels, setVisiblePanels] = useState<Set<PanelKey>>(new Set(ALL_PANELS));
  const [gearOpen, setGearOpen] = useState(false);

  // Time range for alerts + manual block history (mirrors Dashboard's picker)
  const [timeValue, setTimeValue] = useState<number>(24);
  const [timeUnit, setTimeUnit] = useState<TimeUnit>("hours");

  const unitMultiplier = TIME_UNITS.find((u) => u.value === timeUnit)?.multiplier ?? 1;
  const selectedHours = +(timeValue * unitMultiplier).toFixed(4);
  const maxValue = Math.floor(MAX_HOURS / unitMultiplier);

  // Block form state
  const [blockIp, setBlockIp] = useState("");
  const [blockDuration, setBlockDuration] = useState("4h");
  const [blockReason, setBlockReason] = useState("manual block");
  const [blockConnectionIds, setBlockConnectionIds] = useState<number[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [domainDropdownOpen, setDomainDropdownOpen] = useState(false);
  const domainDropdownRef = useRef<HTMLDivElement>(null);

  const [toast, setToast] = useState<{
    message: string;
    type: "success" | "error" | "info";
  } | null>(null);

  function showToast(
    message: string,
    type: "success" | "error" | "info"
  ) {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  }

  function toggleCard(card: string) {
    setExpandedCards((prev) => {
      const next = new Set(prev);
      if (next.has(card)) {
        next.delete(card);
      } else {
        next.add(card);
        // Load data on expand
        if (card === "alerts" && alerts.length === 0) {
          loadAlerts();
        } else if (card === "scenarios" && hubScenarios.length === 0) {
          loadHubScenarios();
        }
      }
      return next;
    });
  }

  function isExpanded(card: string) {
    return expandedCards.has(card);
  }

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [s, d, sc, ml, svc, conns] = await Promise.all([
        api.getCrowdSecStatus(),
        api.getCrowdSecDecisions(),
        api.getCrowdSecScenarios(),
        api.getCrowdSecManualBlocks(50, selectedHours),
        api.getCrowdSecServiceStatus().catch(() => ({ enabled: true })),
        api.getConnections().catch(() => [] as Connection[]),
      ]);
      setStatus(s);
      setDecisions(d);
      setScenarios(sc);
      setManualLog(ml);
      setServiceEnabled(svc.enabled);
      setConnections(conns);
    } catch {
      showToast(t("crowdsec.error.loadFailed"), "error");
    } finally {
      setLoading(false);
    }
  }, [selectedHours]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Refresh alerts panel when time window changes (only if user has opened it)
  useEffect(() => {
    if (expandedCards.has("alerts")) {
      loadAlerts();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedHours]);

  async function loadAlerts() {
    try {
      const items = await api.getCrowdSecAlerts(selectedHours);
      setAlerts(items);
    } catch (e: any) {
      showToast(e.message, "error");
    }
  }

  async function handleBlock() {
    if (!blockIp.trim()) {
      showToast(t("crowdsec.input.ipRequired"), "error");
      return;
    }
    setActionLoading("block");
    try {
      const payload: any = {
        ip: blockIp.trim(),
        duration: blockDuration,
        reason: blockReason,
        type: "ban",
      };
      if (blockConnectionIds.length > 0) {
        payload.connection_ids = blockConnectionIds;
      }
      const result = await api.addCrowdSecDecision(payload);
      if (result.success) {
        const domainInfo = blockConnectionIds.length > 0
          ? ` on ${blockConnectionIds.length} domain(s)`
          : " on all domains";
        showToast(t("crowdsec.toast.ipBlocked", { ip: blockIp, domainInfo }), "success");
        setBlockIp("");
        setBlockReason("manual block");
        setBlockConnectionIds([]);
        loadData();
      } else {
        showToast(result.message || t("crowdsec.toast.blockFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || t("crowdsec.toast.blockFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleUnblock(ip: string) {
    setActionLoading(`unblock-${ip}`);
    try {
      const result = await api.deleteCrowdSecDecision(ip);
      if (result.success) {
        showToast(t("crowdsec.toast.ipUnblocked", { ip }), "success");
        loadData();
      } else {
        showToast(result.message || t("crowdsec.toast.unblockFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || t("crowdsec.toast.unblockFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleDeleteAllDecisions() {
    setActionLoading("deleteAll");
    try {
      const result = await api.deleteAllCrowdSecDecisions();
      if (result.success) {
        showToast(t("crowdsec.toast.allRemoved"), "success");
        loadData();
      } else {
        showToast(result.message || t("crowdsec.toast.removeAllFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || t("crowdsec.toast.removeAllFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleInstallScenario(name: string) {
    setActionLoading(`install-${name}`);
    try {
      const result = await api.installCrowdSecScenario(name);
      showToast(
        result.success ? t("crowdsec.toast.scenarioInstalled") : result.message || t("crowdsec.toast.scenarioInstallFailed"),
        result.success ? "success" : "error"
      );
      loadData();
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleRemoveScenario(name: string) {
    setActionLoading(`remove-${name}`);
    try {
      const result = await api.removeCrowdSecScenario(name);
      showToast(
        result.success ? t("crowdsec.toast.scenarioRemoved") : result.message || t("crowdsec.toast.scenarioRemoveFailed"),
        result.success ? "success" : "error"
      );
      loadData();
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleToggleScenario(name: string) {
    setActionLoading(`toggle-${name}`);
    try {
      const result = await api.toggleCrowdSecScenario(name);
      showToast(
        result.success
          ? (result.enabled ? t("crowdsec.toast.scenarioEnabled") : t("crowdsec.toast.scenarioDisabled"))
          : result.message || t("crowdsec.toast.toggleFailed"),
        result.success ? "success" : "error"
      );
      loadData();
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleToggleService() {
    const target = !serviceEnabled;
    setActionLoading("toggleService");
    try {
      const result = await api.toggleCrowdSecService(target);
      if (result.success) {
        showToast(
          result.enabled ? t("crowdsec.toast.serviceEnabled") : t("crowdsec.toast.serviceDisabled"),
          "success"
        );
        setServiceEnabled(result.enabled);
        loadData();
      } else {
        showToast(result.message || t("crowdsec.toast.serviceToggleFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || t("crowdsec.toast.serviceToggleFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleReload() {
    setActionLoading("reload");
    try {
      const result = await api.reloadCrowdSec();
      showToast(
        result.success ? t("crowdsec.toast.reloaded") : result.message || t("crowdsec.toast.reloadFailed"),
        result.success ? "success" : "error"
      );
      loadData();
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function loadHubScenarios() {
    setActionLoading("hub");
    try {
      const items = await api.getCrowdSecScenarioHub();
      setHubScenarios(items);
      setHubExpanded(true);
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  // Filtered lists based on search
  const filteredScenarios = useMemo(() => {
    if (!scenarioSearch.trim()) return scenarios;
    const q = scenarioSearch.toLowerCase();
    return scenarios.filter(
      (s) =>
        (s.name || "").toLowerCase().includes(q) ||
        (s.description || "").toLowerCase().includes(q) ||
        (s.labels || []).some((l) => l.toLowerCase().includes(q))
    );
  }, [scenarios, scenarioSearch]);

  const filteredHubScenarios = useMemo(() => {
    if (!scenarioSearch.trim()) return hubScenarios;
    const q = scenarioSearch.toLowerCase();
    return hubScenarios.filter(
      (s) =>
        (s.name || "").toLowerCase().includes(q) ||
        (s.description || "").toLowerCase().includes(q) ||
        (s.author || "").toLowerCase().includes(q)
    );
  }, [hubScenarios, scenarioSearch]);

  // ── Gear popover ref + outside-click ──
  const gearPopoverRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!gearOpen) return;
    function handleClick(e: MouseEvent) {
      if (gearPopoverRef.current && !gearPopoverRef.current.contains(e.target as Node)) {
        setGearOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [gearOpen]);

  useEffect(() => {
    if (!gearOpen) return;
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") setGearOpen(false);
    }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [gearOpen]);

  // Close domain dropdown on outside click
  useEffect(() => {
    if (!domainDropdownOpen) return;
    function handleClick(e: MouseEvent) {
      if (domainDropdownRef.current && !domainDropdownRef.current.contains(e.target as Node)) {
        setDomainDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [domainDropdownOpen]);

  if (loading) {
    return (
      <div className="page-wrapper" style={{ padding: "32px" }}>
        <div className="loading-spinner">{t("crowdsec.loading")}</div>
      </div>
    );
  }

  // ── Reusable Card Header ──
  function CardChevron({ card }: { card: string }) {
    return isExpanded(card) ? (
      <ChevronUp size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
    ) : (
      <ChevronDown size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
    );
  }

  function togglePanel(key: PanelKey) {
    setVisiblePanels((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  }

  const PANEL_META: { key: PanelKey; icon: React.ReactNode; labelKey: string }[] = [
    { key: "status", icon: <Shield size={14} />, labelKey: "crowdsec.panel.status" },
    { key: "blocks", icon: <Ban size={14} />, labelKey: "crowdsec.panel.blocks" },
    { key: "scenarios", icon: <Package size={14} />, labelKey: "crowdsec.panel.scenarios" },
    { key: "alerts", icon: <HardDrive size={14} />, labelKey: "crowdsec.panel.alerts" },
  ];

  return (
    <div className="page-wrapper" style={{ padding: "24px 32px" }}>
      {/* Toast */}
      {toast && (
        <div
          className={`toast toast-${toast.type}`}
          style={{
            position: "fixed",
            top: "20px",
            right: "20px",
            zIndex: 9999,
            padding: "12px 18px",
            borderRadius: "var(--radius-md)",
            background:
              toast.type === "success"
                ? "rgba(16,185,129,0.15)"
                : toast.type === "error"
                ? "rgba(244,63,94,0.15)"
                : "rgba(56,189,248,0.15)",
            color:
              toast.type === "success"
                ? "var(--success)"
                : toast.type === "error"
                ? "var(--danger)"
                : "var(--info)",
            border: "1px solid",
            borderColor:
              toast.type === "success"
                ? "rgba(16,185,129,0.3)"
                : toast.type === "error"
                ? "rgba(244,63,94,0.3)"
                : "rgba(56,189,248,0.3)",
            display: "flex",
            alignItems: "center",
            gap: "8px",
            fontSize: "13px",
            fontWeight: 500,
          }}
        >
          {toast.type === "success" ? (
            <CheckCircle2 size={16} />
          ) : toast.type === "error" ? (
            <XCircle size={16} />
          ) : (
            <AlertTriangle size={16} />
          )}
          {toast.message}
        </div>
      )}

      {/* Header */}
      <div className="page-header">
        <div>
          <h1>CrowdSec</h1>
          <p>{t("crowdsec.subtitle")}</p>
        </div>
      </div>

      {/* ── Time range + Gear ── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          marginBottom: "16px",
          padding: "10px 16px",
          background: "var(--card-bg, #1a1a2e)",
          borderRadius: "var(--radius-md, 8px)",
          border: "1px solid var(--border-color, #2a2a2a)",
          flexWrap: "wrap",
        }}
      >
        {/* Time range selector (same UX as the Dashboard native panels) */}
        <span style={{ fontSize: "13px", color: "var(--text-secondary, #888)", fontWeight: 500 }}>
          {t("dashboard.ui.timeRange")}
        </span>
        <input
          type="number"
          data-testid="crowdsec-time-value"
          min={1}
          max={maxValue}
          value={timeValue}
          onChange={(e) => {
            const v = parseInt(e.target.value, 10);
            if (!isNaN(v) && v >= 1 && v <= maxValue) setTimeValue(v);
          }}
          style={{
            width: "80px",
            padding: "6px 10px",
            fontSize: "13px",
            border: "1px solid var(--border-color, #2a2a2a)",
            borderRadius: "var(--radius-sm, 6px)",
            background: "var(--input-bg, #0d0d1a)",
            color: "var(--text-primary, #e0e0e0)",
            outline: "none",
          }}
        />
        <select
          data-testid="crowdsec-time-unit"
          value={timeUnit}
          onChange={(e) => setTimeUnit(e.target.value as TimeUnit)}
          style={{
            padding: "6px 10px",
            fontSize: "13px",
            border: "1px solid var(--border-color, #2a2a2a)",
            borderRadius: "var(--radius-sm, 6px)",
            background: "var(--input-bg, #0d0d1a)",
            color: "var(--text-primary, #e0e0e0)",
            outline: "none",
            cursor: "pointer",
          }}
        >
          {TIME_UNITS.map((unit) => (
            <option key={unit.value} value={unit.value}>
              {unit.label}
            </option>
          ))}
        </select>
        <span style={{ fontSize: "12px", color: "var(--text-secondary, #666)" }}>
          {t("crowdsec.subtitle.range", {
            n: timeValue,
            unit: timeUnit === "minutes" ? "min" : timeUnit === "hours" ? "hr" : "day",
          })}
        </span>

        {/* Gear button */}
        <div style={{ position: "relative", marginLeft: "auto" }}>
          <button
            className="settings-gear-btn"
            onClick={() => setGearOpen(!gearOpen)}
            title={t("crowdsec.panels.title")}
            style={{ width: "32px", height: "32px" }}
          >
            <Cog size={16} />
          </button>

          {/* Gear popover */}
          {gearOpen && (
            <div
              ref={gearPopoverRef}
              style={{
                position: "absolute",
                top: "calc(100% + 8px)",
                right: "0",
                background: "var(--bg-elevated)",
                border: "1px solid var(--border-default)",
                borderRadius: "var(--radius-md)",
                padding: "6px",
                boxShadow: "0 16px 48px rgba(0, 0, 0, 0.5), 0 0 0 1px var(--border-subtle)",
                zIndex: 50,
                minWidth: "220px",
                animation: "scaleIn var(--duration-fast) var(--ease-out)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  padding: "10px 10px 8px",
                  fontSize: "13px",
                  fontWeight: 600,
                  color: "var(--text-primary)",
                  borderBottom: "1px solid var(--border-subtle)",
                  marginBottom: "4px",
                }}
              >
                <Cog size={14} style={{ color: "var(--accent-1)" }} />
                {t("crowdsec.panels.title")}
              </div>
              {PANEL_META.map((p) => (
                <div
                  key={p.key}
                  className="checkbox-row"
                  onClick={() => togglePanel(p.key)}
                  style={{ padding: "8px 10px" }}
                >
                  <div
                    style={{
                      width: "32px",
                      height: "24px",
                      borderRadius: "12px",
                      background: visiblePanels.has(p.key)
                        ? "var(--accent-1)"
                        : "var(--border-strong)",
                      position: "relative",
                      transition: "background var(--duration-fast) var(--ease-out)",
                      cursor: "pointer",
                      flexShrink: 0,
                    }}
                  >
                    <div
                      style={{
                        position: "absolute",
                        top: "2px",
                        left: visiblePanels.has(p.key) ? "10px" : "2px",
                        width: "20px",
                        height: "20px",
                        borderRadius: "50%",
                        background: "#fff",
                        transition: "left var(--duration-fast) var(--ease-out)",
                        boxShadow: "0 1px 3px rgba(0,0,0,0.3)",
                      }}
                    />
                  </div>
                  <span style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "13px" }}>
                    {p.icon}
                    {t(p.labelKey)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Expandable Metric Cards ── */}
      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

        {/* ── Card 1: Status ── */}
        {visiblePanels.has("status") && (
        <div
          className="card"
          style={{ cursor: "pointer" }}
        >
          <div
            className="card-header"
            onClick={() => toggleCard("status")}
            style={{ userSelect: "none" }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <div className="metric-icon violet" style={{ width: "36px", height: "36px", borderRadius: "var(--radius-md)", display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(139,92,246,0.1)", color: "var(--accent-4)" }}>
                <Shield size={18} />
              </div>
              <div>
                <div className="metric-label">{t("crowdsec.panel.status")}</div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "2px" }}>
                  <span
                    className="badge"
                    style={
                      serviceEnabled && status?.running
                        ? { background: "rgba(16,185,129,0.12)", color: "var(--success)" }
                        : { background: "rgba(244,63,94,0.12)", color: "var(--danger)" }
                    }
                  >
                    {!serviceEnabled ? t("crowdsec.status.disabled") : status?.running ? t("crowdsec.status.running") : t("crowdsec.status.stopped")}
                  </span>
                  <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                    {status?.version || "Unknown"}
                  </span>
                </div>
              </div>
            </div>
            <CardChevron card="status" />
          </div>
          {isExpanded("status") && (
            <div style={{ padding: "16px 20px", borderTop: "1px solid var(--border-default)" }}>
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  className={`btn ${serviceEnabled ? "btn-danger" : "btn-success"}`}
                  onClick={(e) => { e.stopPropagation(); handleToggleService(); }}
                  disabled={actionLoading === "toggleService"}
                >
                  {actionLoading === "toggleService" ? (
                    <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} />
                  ) : serviceEnabled ? (
                    <PowerOff size={14} />
                  ) : (
                    <Power size={14} />
                  )}
                  {serviceEnabled ? t("crowdsec.btn.disable") : t("crowdsec.btn.enable")}
                </button>
                <button
                  className="btn btn-outline"
                  onClick={(e) => { e.stopPropagation(); handleReload(); }}
                  disabled={actionLoading === "reload"}
                >
                  <RefreshCw
                    size={14}
                    style={{ animation: actionLoading === "reload" ? "spin 1s linear infinite" : "none" }}
                  />
                  {t("crowdsec.btn.reload")}
                </button>
              </div>
            </div>
          )}
        </div>
        )}

        {/* ── Card 2: Active Blocks ── */}
        {visiblePanels.has("blocks") && (
        <div className="card" style={{ cursor: "pointer" }}>
          <div
            className="card-header"
            onClick={() => toggleCard("blocks")}
            style={{ userSelect: "none" }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <div className="metric-icon rose" style={{ width: "36px", height: "36px", borderRadius: "var(--radius-md)", display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(244,63,94,0.1)", color: "var(--danger)" }}>
                <Ban size={18} />
              </div>
              <div>
                <div className="metric-label">{t("crowdsec.panel.blocks")}</div>
                <div className="metric-value" style={{ margin: 0, fontSize: "18px" }}>
                  {status?.decisions_count ?? 0}
                </div>
              </div>
            </div>
            <CardChevron card="blocks" />
          </div>
          {isExpanded("blocks") && (
            <div style={{ borderTop: "1px solid var(--border-default)" }}>
              {/* Block IP Manually */}
              <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--border-default)" }}>
                <h4 style={{ fontSize: "13px", fontWeight: 600, marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <Ban size={14} style={{ color: "var(--danger)" }} />
                  {t("crowdsec.section.blockManually")}
                </h4>
                <div style={{ display: "flex", gap: "10px", alignItems: "flex-end", flexWrap: "wrap" }}>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="label" style={{ fontSize: "11px" }}>{t("crowdsec.ipAddress")}</label>
                    <input
                      type="text"
                      className="input"
                      placeholder={t("crowdsec.placeholder.ipAddr")}
                      value={blockIp}
                      onChange={(e) => setBlockIp(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleBlock()}
                      style={{ height: "34px", fontSize: "13px", width: "160px" }}
                    />
                  </div>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="label" style={{ fontSize: "11px" }}>{t("crowdsec.duration")}</label>
                    <select
                      className="input"
                      value={blockDuration}
                      onChange={(e) => setBlockDuration(e.target.value)}
                      style={{ height: "34px", fontSize: "13px", width: "130px" }}
                    >
                      <option value="30m">30 minutes</option>
                      <option value="1h">1 hour</option>
                      <option value="4h">4 hours</option>
                      <option value="12h">12 hours</option>
                      <option value="1d">1 day</option>
                      <option value="3d">3 days</option>
                      <option value="7d">7 days</option>
                      <option value="30d">30 days</option>
                      <option value="999h">Permanent</option>
                    </select>
                  </div>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="label" style={{ fontSize: "11px" }}>{t("crowdsec.reason")}</label>
                    <input
                      type="text"
                      className="input"
                      placeholder={t("crowdsec.placeholder.reason")}
                      value={blockReason}
                      onChange={(e) => setBlockReason(e.target.value)}
                      style={{ height: "34px", fontSize: "13px", width: "160px" }}
                    />
                  </div>
                  {/* Domain selector */}
                  <div className="form-group" style={{ marginBottom: 0, position: "relative" }} ref={domainDropdownRef}>
                    <label className="label" style={{ fontSize: "11px" }}>{t("crowdsec.field.domains")}</label>
                    <button
                      type="button"
                      className="input"
                      onClick={(e) => { e.stopPropagation(); setDomainDropdownOpen(!domainDropdownOpen); }}
                      style={{
                        height: "34px",
                        fontSize: "13px",
                        width: "200px",
                        textAlign: "left",
                        cursor: "pointer",
                        background: "var(--input-bg, #0d0d1a)",
                        border: "1px solid var(--border-color, #2a2a2a)",
                        borderRadius: "var(--radius-sm, 6px)",
                        color: "var(--text-primary, #e0e0e0)",
                        padding: "0 10px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                      }}
                    >
                      <span style={{
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        color: blockConnectionIds.length === 0 ? "var(--text-muted)" : "var(--text-primary)",
                      }}>
                        {blockConnectionIds.length === 0
                          ? t("crowdsec.placeholder.allDomains")
                          : t("crowdsec.domains.count", { n: blockConnectionIds.length })}
                      </span>
                      <span style={{ color: "var(--text-muted)", fontSize: "10px" }}>
                        {domainDropdownOpen ? "▲" : "▼"}
                      </span>
                    </button>
                    {domainDropdownOpen && (
                      <div
                        style={{
                          position: "absolute",
                          top: "100%",
                          left: 0,
                          zIndex: 100,
                          minWidth: "260px",
                          background: "var(--bg-elevated, #1a1a2e)",
                          border: "1px solid var(--border-color, #2a2a2a)",
                          borderRadius: "var(--radius-md, 8px)",
                          boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
                          marginTop: "4px",
                          padding: "6px",
                          maxHeight: "240px",
                          overflowY: "auto",
                        }}
                      >
                        <div
                          className="checkbox-row"
                          onClick={(e) => {
                            e.stopPropagation();
                            const enabledConns = connections.filter(c => c.enabled);
                            if (blockConnectionIds.length === enabledConns.length) {
                              setBlockConnectionIds([]);
                            } else {
                              setBlockConnectionIds(enabledConns.map(c => c.id));
                            }
                          }}
                          style={{
                            padding: "8px 10px",
                            borderBottom: "1px solid var(--border-subtle, #2a2a2a)",
                            fontWeight: 600,
                            fontSize: "12px",
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={
                              blockConnectionIds.length > 0 &&
                              blockConnectionIds.length === connections.filter(c => c.enabled).length
                            }
                            readOnly
                            style={{ marginRight: "8px", accentColor: "var(--accent-1)" }}
                          />
                          {blockConnectionIds.length === connections.filter(c => c.enabled).length
                            ? t("crowdsec.btn.deselectAll")
                            : t("crowdsec.btn.selectAll")}
                        </div>
                        {connections.length === 0 ? (
                          <div style={{ padding: "12px", fontSize: "12px", color: "var(--text-muted)", textAlign: "center" }}>
                            {t("crowdsec.empty.noConnections")}
                          </div>
                        ) : (
                          connections.filter(c => c.enabled).map(conn => (
                            <div
                              key={conn.id}
                              className="checkbox-row"
                              onClick={(e) => {
                                e.stopPropagation();
                                setBlockConnectionIds(prev =>
                                  prev.includes(conn.id)
                                    ? prev.filter(id => id !== conn.id)
                                    : [...prev, conn.id]
                                );
                              }}
                              style={{ padding: "6px 10px", fontSize: "12px" }}
                            >
                              <input
                                type="checkbox"
                                checked={blockConnectionIds.includes(conn.id)}
                                readOnly
                                style={{ marginRight: "8px", accentColor: "var(--accent-1)" }}
                              />
                              <span style={{ fontWeight: 500 }}>{conn.name}</span>
                              <span style={{ color: "var(--text-muted)", marginLeft: "6px", fontSize: "11px" }}>
                                {conn.domains?.length ? `(${conn.domains.join(", ")})` : t("crowdsec.noDomains")}
                              </span>
                            </div>
                          ))
                        )}
                      </div>
                    )}
                  </div>
                  <button
                    className="btn btn-danger"
                    onClick={(e) => { e.stopPropagation(); handleBlock(); }}
                    disabled={actionLoading === "block" || !blockIp.trim()}
                    style={{ height: "34px" }}
                  >
                    {actionLoading === "block" ? (
                      <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} />
                    ) : (
                      <Ban size={14} />
                    )}
                    {t("crowdsec.btn.blockIp")}
                  </button>
                </div>
              </div>

              {/* Active Decisions */}
              <div style={{ padding: "12px 20px", borderBottom: "1px solid var(--border-default)" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                  <h4 style={{ fontSize: "13px", fontWeight: 600, margin: 0, display: "flex", alignItems: "center", gap: "6px" }}>
                    <Globe size={14} style={{ color: "var(--accent-1)" }} />
                    {t("crowdsec.section.activeDecisions")}
                  </h4>
                  <button
                    className="btn btn-outline btn-sm"
                    onClick={(e) => { e.stopPropagation(); handleDeleteAllDecisions(); }}
                    disabled={actionLoading === "deleteAll" || decisions.length === 0}
                  >
                    <Trash2 size={11} />
                    {t("crowdsec.btn.clearAll")}
                  </button>
                </div>
                <div className="table-wrapper" style={{ maxHeight: "240px", overflowY: "auto" }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>{t("crowdsec.table.ip")}</th>
                        <th>{t("crowdsec.table.type")}</th>
                        <th>{t("crowdsec.table.reason")}</th>
                        <th>{t("crowdsec.table.blockedOn")}</th>
                        <th>{t("crowdsec.table.expires")}</th>
                        <th>{t("crowdsec.table.action")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {decisions.length === 0 ? (
                        <tr>
                          <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: "16px" }}>
                            {t("crowdsec.empty.noDecisions")}
                          </td>
                        </tr>
                      ) : (
                        decisions.map((d, i) => (
                          <tr key={d.id ?? i}>
                            <td style={{ fontFamily: "monospace", fontSize: "12px", fontWeight: 500 }}>
                              {d.value}
                            </td>
                            <td>
                              <span className={`badge ${d.type === "ban" ? "badge-danger" : "badge-warning"}`}>
                                {d.type}
                              </span>
                            </td>
                            <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                              {d.reason || "-"}
                            </td>
                            <td style={{ fontSize: "11px", color: "var(--text-secondary)", maxWidth: "180px" }}>
                              {d.blocked_on?.length > 0
                                ? d.blocked_on.map((name, idx) => {
                                    const conn = connections.find(c => c.name === name);
                                    const domains = conn?.domains?.join(", ") || "";
                                    return (
                                      <span key={name}>
                                        <span
                                          className="badge badge-primary"
                                          style={{ fontSize: "10px", cursor: "help" }}
                                          title={domains || name}
                                        >
                                          {name}
                                        </span>
                                        {idx < d.blocked_on.length - 1 ? " " : null}
                                      </span>
                                    );
                                  })
                                : <span style={{ color: "var(--text-muted)", fontStyle: "italic" }}>{t("crowdsec.all")}</span>
                              }
                            </td>
                            <td style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                              {d.until || d.duration || "-"}
                            </td>
                            <td>
                              <button
                                className="btn btn-outline btn-sm"
                                onClick={(e) => { e.stopPropagation(); handleUnblock(d.value); }}
                                disabled={actionLoading === `unblock-${d.value}`}
                                style={{ color: "var(--success)", borderColor: "rgba(16,185,129,0.3)" }}
                              >
                                <Unlock size={11} />
                                {t("crowdsec.btn.unblock")}
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Manual Block History */}
              <div style={{ padding: "12px 20px" }}>
                <h4 style={{ fontSize: "13px", fontWeight: 600, marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <Clock size={14} style={{ color: "var(--accent-2)" }} />
                  {t("crowdsec.section.manualHistory")}
                </h4>
                <div className="table-wrapper" style={{ maxHeight: "240px", overflowY: "auto" }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>{t("crowdsec.table.time")}</th>
                        <th>{t("crowdsec.table.action")}</th>
                        <th>{t("crowdsec.table.ip")}</th>
                        <th>{t("crowdsec.table.duration")}</th>
                        <th>{t("crowdsec.table.reason")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {manualLog.length === 0 ? (
                        <tr>
                          <td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: "16px" }}>
                            {t("crowdsec.empty.noManual")}
                          </td>
                        </tr>
                      ) : (
                        manualLog.map((entry, i) => (
                          <tr key={i}>
                            <td style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                              {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "-"}
                            </td>
                            <td>
                              <span className={`badge ${entry.action === "block" ? "badge-danger" : "badge-success"}`}>
                                {entry.action}
                              </span>
                            </td>
                            <td style={{ fontFamily: "monospace", fontSize: "12px" }}>{entry.ip}</td>
                            <td style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                              {entry.duration || "-"}
                            </td>
                            <td style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                              {entry.reason || "-"}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
        )}

        {/* ── Card 3: Scenarios ── */}
        {visiblePanels.has("scenarios") && (
        <div className="card" style={{ cursor: "pointer" }}>
          <div
            className="card-header"
            onClick={() => toggleCard("scenarios")}
            style={{ userSelect: "none" }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <div className="metric-icon cyan" style={{ width: "36px", height: "36px", borderRadius: "var(--radius-md)", display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(6,182,212,0.1)", color: "var(--accent-3)" }}>
                <Package size={18} />
              </div>
              <div>
                <div className="metric-label">{t("crowdsec.panel.scenarios")}</div>
                <div className="metric-value" style={{ margin: 0, fontSize: "18px" }}>
                  {status?.scenarios_count ?? 0}
                </div>
              </div>
            </div>
            <CardChevron card="scenarios" />
          </div>
          {isExpanded("scenarios") && (
            <div style={{ borderTop: "1px solid var(--border-default)" }}>
              {/* Search + Browse Hub toolbar */}
              <div style={{ padding: "12px 20px", display: "flex", alignItems: "center", gap: "8px", borderBottom: "1px solid var(--border-default)" }}>
                <div style={{ position: "relative", flex: 1 }}>
                  <Search
                    size={14}
                    style={{
                      position: "absolute",
                      left: "8px",
                      top: "50%",
                      transform: "translateY(-50%)",
                      color: "var(--text-muted)",
                      pointerEvents: "none",
                    }}
                  />
                  <input
                    type="text"
                    className="input"
                    placeholder={t("crowdsec.placeholder.searchScenarios")}
                    value={scenarioSearch}
                    onChange={(e) => setScenarioSearch(e.target.value)}
                    onClick={(e) => e.stopPropagation()}
                    style={{
                      paddingLeft: "28px",
                      paddingRight: scenarioSearch ? "28px" : "8px",
                      height: "32px",
                      fontSize: "12px",
                      width: "100%",
                    }}
                  />
                  {scenarioSearch && (
                    <button
                      onClick={(e) => { e.stopPropagation(); setScenarioSearch(""); }}
                      style={{
                        position: "absolute",
                        right: "4px",
                        top: "50%",
                        transform: "translateY(-50%)",
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                        color: "var(--text-muted)",
                        padding: "2px",
                        display: "flex",
                      }}
                    >
                      <X size={12} />
                    </button>
                  )}
                </div>
                <button
                  className="btn btn-outline btn-sm"
                  onClick={(e) => { e.stopPropagation(); loadHubScenarios(); }}
                  disabled={actionLoading === "hub"}
                  style={{ whiteSpace: "nowrap" }}
                >
                  <Plus size={12} />
                  {t("crowdsec.btn.browseHub")}
                </button>
              </div>

              {/* Installed scenarios */}
              <div style={{ padding: "8px 20px 4px" }}>
                <h4 style={{ fontSize: "12px", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", margin: 0 }}>
                  {t("crowdsec.installedScenarios")}
                </h4>
              </div>
              <div className="table-wrapper" style={{ maxHeight: "260px", overflowY: "auto" }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>{t("crowdsec.table.name")}</th>
                      <th>{t("crowdsec.table.description")}</th>
                      <th>{t("crowdsec.table.type")}</th>
                      <th>{t("crowdsec.panel.status")}</th>
                      <th>{t("crowdsec.table.labels")}</th>
                      <th>{t("crowdsec.table.action")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scenarios.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: "20px" }}>
                          {t("crowdsec.empty.noInstalled")}
                        </td>
                      </tr>
                    ) : filteredScenarios.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: "20px" }}>
                          {t("crowdsec.empty.noMatch", { query: scenarioSearch })}
                        </td>
                      </tr>
                    ) : (
                      filteredScenarios.map((s, i) => (
                        <tr key={s.name ?? i}>
                          <td style={{ fontFamily: "monospace", fontSize: "11px", fontWeight: 500 }}>
                            {s.name}
                          </td>
                          <td style={{ fontSize: "11px", color: "var(--text-secondary)", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {s.description || "-"}
                          </td>
                          <td>
                            <span className="badge badge-secondary" style={{ fontSize: "10px" }}>{s.type || t("crowdsec.badge.scenario")}</span>
                          </td>
                          <td>
                            <span
                              className={`badge ${s.loaded ? "badge-success" : "badge-secondary"}`}
                              style={{ fontSize: "10px" }}
                            >
                              {s.loaded ? t("crowdsec.active") : t("crowdsec.inactive")}
                            </span>
                          </td>
                          <td>
                            {s.labels?.length > 0
                              ? s.labels.map((lbl) => (
                                  <span
                                    key={lbl}
                                    className="badge badge-primary"
                                    style={{ marginRight: "3px", fontSize: "10px" }}
                                  >
                                    {lbl}
                                  </span>
                                ))
                              : "-"}
                          </td>
                          <td>
                            <div style={{ display: "flex", gap: "4px" }}>
                              <button
                                className="btn btn-outline btn-sm"
                                onClick={(e) => { e.stopPropagation(); handleToggleScenario(s.name); }}
                                disabled={actionLoading === `toggle-${s.name}`}
                                style={{
                                  color: s.loaded ? "var(--warning)" : "var(--success)",
                                  borderColor: s.loaded ? "rgba(245,158,11,0.3)" : "rgba(16,185,129,0.3)",
                                  fontSize: "10px",
                                  padding: "2px 6px",
                                }}
                                title={s.loaded ? t("crowdsec.btn.disable") : t("crowdsec.btn.enable")}
                              >
                                {actionLoading === `toggle-${s.name}` ? (
                                  <RefreshCw size={10} style={{ animation: "spin 1s linear infinite" }} />
                                ) : s.loaded ? (
                                  <ToggleRight size={10} />
                                ) : (
                                  <ToggleLeft size={10} />
                                )}
                                {s.loaded ? t("crowdsec.btn.disable") : t("crowdsec.btn.enable")}
                              </button>
                              <button
                                className="btn btn-outline btn-sm"
                                onClick={(e) => { e.stopPropagation(); handleRemoveScenario(s.name); }}
                                disabled={actionLoading === `remove-${s.name}`}
                                style={{ color: "var(--danger)", borderColor: "rgba(244,63,94,0.2)", fontSize: "10px", padding: "2px 6px" }}
                              >
                                <Trash2 size={10} />
                                {t("crowdsec.btn.remove")}
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              {/* Hub scenarios */}
              {hubScenarios.length > 0 && (
                <>
                  <div
                    style={{
                      padding: "12px 20px",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      cursor: "pointer",
                      borderTop: "1px solid var(--border-default)",
                    }}
                    onClick={(e) => { e.stopPropagation(); setHubExpanded(!hubExpanded); }}
                  >
                    <h4 style={{ fontSize: "12px", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", margin: 0 }}>
                      {t("crowdsec.section.hub", { n: filteredHubScenarios.length })}
                    </h4>
                    {hubExpanded ? <ChevronUp size={14} style={{ color: "var(--text-muted)" }} /> : <ChevronDown size={14} style={{ color: "var(--text-muted)" }} />}
                  </div>
                  {hubExpanded && (
                    <div className="table-wrapper" style={{ maxHeight: "260px", overflowY: "auto" }}>
                      <table className="table">
                        <thead>
                          <tr>
                            <th>{t("crowdsec.table.name")}</th>
                            <th>{t("crowdsec.table.description")}</th>
                            <th>Author</th>
                            <th>{t("crowdsec.table.action")}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredHubScenarios.length === 0 ? (
                            <tr>
                              <td colSpan={4} style={{ textAlign: "center", color: "var(--text-muted)", padding: "20px" }}>
                                {scenarioSearch ? t("crowdsec.empty.noHubMatch", { query: scenarioSearch }) : t("crowdsec.empty.noHub")}
                              </td>
                            </tr>
                          ) : (
                            filteredHubScenarios.map((s, i) => (
                              <tr key={s.name ?? i}>
                                <td style={{ fontFamily: "monospace", fontSize: "11px", fontWeight: 500 }}>
                                  {s.name}
                                </td>
                                <td style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                                  {s.description || "-"}
                                </td>
                                <td style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                  {s.author || "-"}
                                </td>
                                <td>
                                  {s.installed ? (
                                    <span className="badge badge-success" style={{ fontSize: "10px" }}>{t("crowdsec.installed")}</span>
                                  ) : (
                                    <button
                                      className="btn btn-outline btn-sm"
                                      onClick={(e) => { e.stopPropagation(); handleInstallScenario(s.name); }}
                                      disabled={actionLoading === `install-${s.name}`}
                                      style={{ fontSize: "10px", padding: "2px 6px" }}
                                    >
                                      <Plus size={10} />
                                      {t("crowdsec.btn.install")}
                                    </button>
                                  )}
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
        )}

        {/* ── Card 4: Alerts ── */}
        {visiblePanels.has("alerts") && (
        <div className="card" style={{ cursor: "pointer" }}>
          <div
            className="card-header"
            onClick={() => toggleCard("alerts")}
            style={{ userSelect: "none" }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <div className="metric-icon emerald" style={{ width: "36px", height: "36px", borderRadius: "var(--radius-md)", display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(16,185,129,0.1)", color: "var(--success)" }}>
                <HardDrive size={18} />
              </div>
              <div>
                <div className="metric-label">{t("crowdsec.panel.alerts")}</div>
                <div className="metric-value" style={{ margin: 0, fontSize: "18px" }}>
                  {status?.alerts_count ?? 0}
                </div>
              </div>
            </div>
            <CardChevron card="alerts" />
          </div>
          {isExpanded("alerts") && (
            <div style={{ borderTop: "1px solid var(--border-default)", padding: "12px 20px" }}>
              <div className="table-wrapper" style={{ maxHeight: "280px", overflowY: "auto" }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>{t("crowdsec.table.scenario")}</th>
                      <th>{t("crowdsec.table.message")}</th>
                      <th>{t("crowdsec.table.sourceIp")}</th>
                      <th>{t("crowdsec.table.decisions")}</th>
                      <th>{t("crowdsec.table.started")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: "24px" }}>
                          {t("crowdsec.empty.noAlerts")}
                        </td>
                      </tr>
                    ) : (
                      alerts.map((a, i) => (
                        <tr key={a.id ?? i}>
                          <td style={{ fontFamily: "monospace", fontSize: "11px", fontWeight: 500, maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {a.scenario || "-"}
                          </td>
                          <td style={{ fontSize: "11px", color: "var(--text-secondary)", maxWidth: "300px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {a.message || "-"}
                          </td>
                          <td style={{ fontFamily: "monospace", fontSize: "11px" }}>
                            {a.source_ip || "-"}
                          </td>
                          <td>
                            <span className="badge badge-warning" style={{ fontSize: "10px" }}>
                              {a.decisions_count}
                            </span>
                          </td>
                          <td style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                            {a.start_at ? new Date(a.start_at).toLocaleString() : "-"}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
        )}

      </div>
    </div>
  );
}
