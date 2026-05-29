import { createSignal, createEffect, createMemo, onMount, onCleanup, For, Show, type JSX } from "solid-js";
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
} from "lucide-solid";
import { api, CrowdSecStatus, DecisionItem, ScenarioInfo, AlertItem, Connection } from "../api/client";
import { useSettings } from "../context/SettingsContext";
import { useGlobalFilters } from "../context/GlobalFiltersContext";

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

export default function CrowdSec() {
  const settings = useSettings();
  const filters = useGlobalFilters();

  const [status, setStatus] = createSignal<CrowdSecStatus | null>(null);
  const [decisions, setDecisions] = createSignal<DecisionItem[]>([]);
  const [scenarios, setScenarios] = createSignal<ScenarioInfo[]>([]);
  const [hubScenarios, setHubScenarios] = createSignal<HubScenario[]>([]);
  const [manualLog, setManualLog] = createSignal<ManualBlockLog[]>([]);
  const [alerts, setAlerts] = createSignal<AlertItem[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [actionLoading, setActionLoading] = createSignal<string | null>(null);
  const [serviceEnabled, setServiceEnabled] = createSignal(true);
  const [scenarioSearch, setScenarioSearch] = createSignal("");
  const [hubExpanded, setHubExpanded] = createSignal(false);
  const [expandedCards, setExpandedCards] = createSignal<Set<string>>(new Set());
  const [visiblePanels, setVisiblePanels] = createSignal<Set<PanelKey>>(new Set(ALL_PANELS));
  const [gearOpen, setGearOpen] = createSignal(false);

  // Block form state
  const [blockIp, setBlockIp] = createSignal("");
  const [blockDuration, setBlockDuration] = createSignal("4h");
  const [blockReason, setBlockReason] = createSignal("manual block");
  const [blockConnectionIds, setBlockConnectionIds] = createSignal<number[]>([]);
  const [connections, setConnections] = createSignal<Connection[]>([]);
  const [domainDropdownOpen, setDomainDropdownOpen] = createSignal(false);

  let gearPopoverRef: HTMLDivElement | undefined;
  let domainDropdownRef: HTMLDivElement | undefined;

  const [toast, setToast] = createSignal<{
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
        if (card === "alerts" && alerts().length === 0) {
          loadAlerts();
        } else if (card === "scenarios" && hubScenarios().length === 0) {
          loadHubScenarios();
        }
      }
      return next;
    });
  }

  function isExpanded(card: string) {
    return expandedCards().has(card);
  }

  const loadData = async () => {
    setLoading(true);
    try {
      const connId = filters.connectionId;
      const [s, d, sc, ml, svc, conns] = await Promise.all([
        api.getCrowdSecStatus(connId),
        api.getCrowdSecDecisions(connId),
        api.getCrowdSecScenarios(),
        api.getCrowdSecManualBlocks(50, filters.selectedHours),
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
      showToast(settings.t("crowdsec.error.loadFailed"), "error");
    } finally {
      setLoading(false);
    }
  };

  createEffect(() => {
    void loadData();
  });

  // Refresh alerts panel when time window changes (only if user has opened it)
  createEffect(() => {
    // track selectedHours reactively
    const hours = filters.selectedHours;
    if (expandedCards().has("alerts")) {
      loadAlerts();
    }
  });

  async function loadAlerts() {
    try {
      const items = await api.getCrowdSecAlerts(filters.selectedHours);
      setAlerts(items);
    } catch (e: any) {
      showToast(e.message, "error");
    }
  }

  async function handleBlock() {
    if (!blockIp().trim()) {
      showToast(settings.t("crowdsec.input.ipRequired"), "error");
      return;
    }
    setActionLoading("block");
    try {
      const payload: any = {
        ip: blockIp().trim(),
        duration: blockDuration(),
        reason: blockReason(),
        type: "ban",
      };
      if (blockConnectionIds().length > 0) {
        payload.connection_ids = blockConnectionIds();
      }
      const result = await api.addCrowdSecDecision(payload);
      if (result.success) {
        const domainInfo = blockConnectionIds().length > 0
          ? ` on ${blockConnectionIds().length} domain(s)`
          : " on all domains";
        showToast(settings.t("crowdsec.toast.ipBlocked", { ip: blockIp(), domainInfo }), "success");
        setBlockIp("");
        setBlockReason("manual block");
        setBlockConnectionIds([]);
        void loadData();
      } else {
        showToast(result.message || settings.t("crowdsec.toast.blockFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || settings.t("crowdsec.toast.blockFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleUnblock(ip: string) {
    setActionLoading(`unblock-${ip}`);
    try {
      const result = await api.deleteCrowdSecDecision(ip);
      if (result.success) {
        showToast(settings.t("crowdsec.toast.ipUnblocked", { ip }), "success");
        void loadData();
      } else {
        showToast(result.message || settings.t("crowdsec.toast.unblockFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || settings.t("crowdsec.toast.unblockFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleDeleteAllDecisions() {
    setActionLoading("deleteAll");
    try {
      const result = await api.deleteAllCrowdSecDecisions();
      if (result.success) {
        showToast(settings.t("crowdsec.toast.allRemoved"), "success");
        void loadData();
      } else {
        showToast(result.message || settings.t("crowdsec.toast.removeAllFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || settings.t("crowdsec.toast.removeAllFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleInstallScenario(name: string) {
    setActionLoading(`install-${name}`);
    try {
      const result = await api.installCrowdSecScenario(name);
      showToast(
        result.success ? settings.t("crowdsec.toast.scenarioInstalled") : result.message || settings.t("crowdsec.toast.scenarioInstallFailed"),
        result.success ? "success" : "error"
      );
      void loadData();
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
        result.success ? settings.t("crowdsec.toast.scenarioRemoved") : result.message || settings.t("crowdsec.toast.scenarioRemoveFailed"),
        result.success ? "success" : "error"
      );
      void loadData();
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
          ? (result.enabled ? settings.t("crowdsec.toast.scenarioEnabled") : settings.t("crowdsec.toast.scenarioDisabled"))
          : result.message || settings.t("crowdsec.toast.toggleFailed"),
        result.success ? "success" : "error"
      );
      void loadData();
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleToggleService() {
    const target = !serviceEnabled();
    setActionLoading("toggleService");
    try {
      const result = await api.toggleCrowdSecService(target);
      if (result.success) {
        showToast(
          result.enabled ? settings.t("crowdsec.toast.serviceEnabled") : settings.t("crowdsec.toast.serviceDisabled"),
          "success"
        );
        setServiceEnabled(result.enabled);
        void loadData();
      } else {
        showToast(result.message || settings.t("crowdsec.toast.serviceToggleFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || settings.t("crowdsec.toast.serviceToggleFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleReload() {
    setActionLoading("reload");
    try {
      const result = await api.reloadCrowdSec();
      showToast(
        result.success ? settings.t("crowdsec.toast.reloaded") : result.message || settings.t("crowdsec.toast.reloadFailed"),
        result.success ? "success" : "error"
      );
      void loadData();
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
  const filteredScenarios = createMemo(() => {
    const sc = scenarios();
    const search = scenarioSearch();
    if (!search.trim()) return sc;
    const q = search.toLowerCase();
    return sc.filter(
      (s) =>
        (s.name || "").toLowerCase().includes(q) ||
        (s.description || "").toLowerCase().includes(q) ||
        (s.labels || []).some((l) => l.toLowerCase().includes(q))
    );
  });

  const filteredHubScenarios = createMemo(() => {
    const hub = hubScenarios();
    const search = scenarioSearch();
    if (!search.trim()) return hub;
    const q = search.toLowerCase();
    return hub.filter(
      (s) =>
        (s.name || "").toLowerCase().includes(q) ||
        (s.description || "").toLowerCase().includes(q) ||
        (s.author || "").toLowerCase().includes(q)
    );
  });

  // Gear and domain outside-clicks
  onMount(() => {
    function handleClick(e: MouseEvent) {
      if (gearOpen() && gearPopoverRef && !gearPopoverRef.contains(e.target as Node)) {
        setGearOpen(false);
      }
      if (domainDropdownOpen() && domainDropdownRef && !domainDropdownRef.contains(e.target as Node)) {
        setDomainDropdownOpen(false);
      }
    }

    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setGearOpen(false);
      }
    }

    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);

    onCleanup(() => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    });
  });

  // ── Reusable Card Header ──
  function CardChevron(props: { card: string }) {
    return (
      <Show
        when={isExpanded(props.card)}
        fallback={<ChevronDown size={14} style={{ color: "var(--text-muted)", "flex-shrink": 0 }} />}
      >
        <ChevronUp size={14} style={{ color: "var(--text-muted)", "flex-shrink": 0 }} />
      </Show>
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

  const PANEL_META: { key: PanelKey; icon: JSX.Element; labelKey: string }[] = [
    { key: "status", icon: <Shield size={14} />, labelKey: "crowdsec.panel.status" },
    { key: "blocks", icon: <Ban size={14} />, labelKey: "crowdsec.panel.blocks" },
    { key: "scenarios", icon: <Package size={14} />, labelKey: "crowdsec.panel.scenarios" },
    { key: "alerts", icon: <HardDrive size={14} />, labelKey: "crowdsec.panel.alerts" },
  ];

  return (
    <Show
      when={!loading()}
      fallback={
        <div class="page-wrapper" style={{ padding: "32px" }}>
          <div class="loading-spinner">{settings.t("crowdsec.loading")}</div>
        </div>
      }
    >
      <div class="page-wrapper" style={{ padding: "24px 32px" }}>
        {/* Toast */}
        <Show when={toast()}>
          <div
            class={`toast toast-${toast()!.type}`}
            style={{
              position: "fixed",
              top: "20px",
              right: "20px",
              "z-index": 9999,
              padding: "12px 18px",
              "border-radius": "var(--radius-md)",
              background:
                toast()!.type === "success"
                  ? "rgba(16,185,129,0.15)"
                  : toast()!.type === "error"
                  ? "rgba(244,63,94,0.15)"
                  : "rgba(56,189,248,0.15)",
              color:
                toast()!.type === "success"
                  ? "var(--success)"
                  : toast()!.type === "error"
                  ? "var(--danger)"
                  : "var(--info)",
              border: "1px solid",
              "border-color":
                toast()!.type === "success"
                  ? "rgba(16,185,129,0.3)"
                  : toast()!.type === "error"
                  ? "rgba(244,63,94,0.3)"
                  : "rgba(56,189,248,0.3)",
              display: "flex",
              "align-items": "center",
              gap: "8px",
              "font-size": "13px",
              "font-weight": 500,
            }}
          >
            <Show
              when={toast()!.type === "success"}
              fallback={
                <Show when={toast()!.type === "error"} fallback={<AlertTriangle size={16} />}>
                  <XCircle size={16} />
                </Show>
              }
            >
              <CheckCircle2 size={16} />
            </Show>
            {toast()!.message}
          </div>
        </Show>

        {/* Header */}
        <div class="page-header">
          <div>
            <h1>CrowdSec</h1>
            <p>{settings.t("crowdsec.subtitle")}</p>
          </div>
        </div>

        {/* ── Header row: range hint + Gear ── */}
        <div
          style={{
            display: "flex",
            "align-items": "center",
            gap: "10px",
            "margin-bottom": "16px",
            padding: "10px 16px",
            background: "var(--card-bg, #1a1a2e)",
            "border-radius": "var(--radius-md, 8px)",
            border: "1px solid var(--border-color, #2a2a2a)",
            "flex-wrap": "wrap",
          }}
        >
          <span style={{ "font-size": "12px", color: "var(--text-secondary, #666)" }}>
            {settings.t("crowdsec.subtitle.range", {
              n: filters.timeValue,
              unit: filters.timeUnit === "minutes" ? "min" : filters.timeUnit === "hours" ? "hr" : "day",
            })}
          </span>

          {/* Gear button */}
          <div style={{ position: "relative", "margin-left": "auto" }}>
            <button
              class="settings-gear-btn"
              onClick={() => setGearOpen(!gearOpen())}
              title={settings.t("crowdsec.panels.title")}
              style={{ width: "32px", height: "32px" }}
            >
              <Cog size={16} />
            </button>

            {/* Gear popover */}
            <Show when={gearOpen()}>
              <div
                ref={gearPopoverRef}
                style={{
                  position: "absolute",
                  top: "calc(100% + 8px)",
                  right: "0",
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--border-default)",
                  "border-radius": "var(--radius-md)",
                  padding: "6px",
                  "box-shadow": "0 16px 48px rgba(0, 0, 0, 0.5), 0 0 0 1px var(--border-subtle)",
                  "z-index": 50,
                  "min-width": "220px",
                  animation: "scaleIn var(--duration-fast) var(--ease-out)",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    "align-items": "center",
                    gap: "8px",
                    padding: "10px 10px 8px",
                    "font-size": "13px",
                    "font-weight": 600,
                    color: "var(--text-primary)",
                    "border-bottom": "1px solid var(--border-subtle)",
                    "margin-bottom": "4px",
                  }}
                >
                  <Cog size={14} style={{ color: "var(--accent-1)" }} />
                  {settings.t("crowdsec.panels.title")}
                </div>
                <For each={PANEL_META}>
                  {(p) => (
                    <div
                      class="checkbox-row"
                      onClick={() => togglePanel(p.key)}
                      style={{ padding: "8px 10px" }}
                    >
                      <div
                        style={{
                          width: "32px",
                          height: "24px",
                          "border-radius": "12px",
                          background: visiblePanels().has(p.key)
                            ? "var(--accent-1)"
                            : "var(--border-strong)",
                          position: "relative",
                          transition: "background var(--duration-fast) var(--ease-out)",
                          cursor: "pointer",
                          "flex-shrink": 0,
                        }}
                      >
                        <div
                          style={{
                            position: "absolute",
                            top: "2px",
                            left: visiblePanels().has(p.key) ? "10px" : "2px",
                            width: "20px",
                            height: "20px",
                            "border-radius": "50%",
                            background: "#fff",
                            transition: "left var(--duration-fast) var(--ease-out)",
                            "box-shadow": "0 1px 3px rgba(0,0,0,0.3)",
                          }}
                        />
                      </div>
                      <span style={{ display: "flex", "align-items": "center", gap: "8px", "font-size": "13px" }}>
                        {p.icon}
                        {settings.t(p.labelKey)}
                      </span>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </div>

        {/* ── Expandable Metric Cards ── */}
        <div style={{ display: "flex", "flex-direction": "column", gap: "16px" }}>

          {/* ── Card 1: Status ── */}
          <Show when={visiblePanels().has("status")}>
            <div
              class="card"
              onClick={() => toggleCard("status")}
              style={{ cursor: "pointer" }}
            >
              <div
                class="card-header"
                style={{ "user-select": "none" }}
              >
                <div style={{ display: "flex", "align-items": "center", gap: "12px" }}>
                  <div class="metric-icon violet" style={{ width: "36px", height: "36px", "border-radius": "var(--radius-md)", display: "flex", "align-items": "center", "justify-content": "center", background: "rgba(139,92,246,0.1)", color: "var(--accent-4)" }}>
                    <Shield size={18} />
                  </div>
                  <div>
                    <div class="metric-label">{settings.t("crowdsec.panel.status")}</div>
                    <div style={{ display: "flex", "align-items": "center", gap: "8px", "margin-top": "2px" }}>
                      <span
                        class="badge"
                        style={
                          serviceEnabled() && status()?.running
                            ? { background: "rgba(16,185,129,0.12)", color: "var(--success)" }
                            : { background: "rgba(244,63,94,0.12)", color: "var(--danger)" }
                        }
                      >
                        {!serviceEnabled() ? settings.t("crowdsec.status.disabled") : status()?.running ? settings.t("crowdsec.status.running") : settings.t("crowdsec.status.stopped")}
                      </span>
                      <span style={{ "font-size": "12px", color: "var(--text-muted)" }}>
                        {status()?.version || "Unknown"}
                      </span>
                    </div>
                  </div>
                </div>
                <CardChevron card="status" />
              </div>
              <Show when={isExpanded("status")}>
                <div
                  onClick={(e) => e.stopPropagation()}
                  style={{ padding: "16px 20px", "border-top": "1px solid var(--border-default)" }}
                >
                  <div style={{ display: "flex", gap: "8px" }}>
                    <button
                      class={`btn ${serviceEnabled() ? "btn-danger" : "btn-success"}`}
                      onClick={() => handleToggleService()}
                      disabled={actionLoading() === "toggleService"}
                    >
                      <Show
                        when={actionLoading() === "toggleService"}
                        fallback={serviceEnabled() ? <PowerOff size={14} /> : <Power size={14} />}
                      >
                        <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} />
                      </Show>
                      {serviceEnabled() ? settings.t("crowdsec.btn.disable") : settings.t("crowdsec.btn.enable")}
                    </button>
                    <button
                      class="btn btn-outline"
                      onClick={() => handleReload()}
                      disabled={actionLoading() === "reload"}
                    >
                      <RefreshCw
                        size={14}
                        style={{ animation: actionLoading() === "reload" ? "spin 1s linear infinite" : "none" }}
                      />
                      {settings.t("crowdsec.btn.reload")}
                    </button>
                  </div>
                </div>
              </Show>
            </div>
          </Show>

          {/* ── Card 2: Active Blocks ── */}
          <Show when={visiblePanels().has("blocks")}>
            <div class="card" style={{ cursor: "pointer" }} onClick={() => toggleCard("blocks")}>
              <div
                class="card-header"
                style={{ "user-select": "none" }}
              >
                <div style={{ display: "flex", "align-items": "center", gap: "12px" }}>
                  <div class="metric-icon rose" style={{ width: "36px", height: "36px", "border-radius": "var(--radius-md)", display: "flex", "align-items": "center", "justify-content": "center", background: "rgba(244,63,94,0.1)", color: "var(--danger)" }}>
                    <Ban size={18} />
                  </div>
                  <div>
                    <div class="metric-label">{settings.t("crowdsec.panel.blocks")}</div>
                    <div class="metric-value" style={{ margin: 0, "font-size": "18px" }}>
                      {status()?.decisions_count ?? 0}
                    </div>
                  </div>
                </div>
                <CardChevron card="blocks" />
              </div>
              <Show when={isExpanded("blocks")}>
                <div
                  onClick={(e) => e.stopPropagation()}
                  style={{ "border-top": "1px solid var(--border-default)" }}
                >
                  {/* Block IP Manually */}
                  <div style={{ padding: "16px 20px", "border-bottom": "1px solid var(--border-default)" }}>
                    <h4 style={{ "font-size": "13px", "font-weight": 600, "margin-bottom": "12px", display: "flex", "align-items": "center", gap: "6px" }}>
                      <Ban size={14} style={{ color: "var(--danger)" }} />
                      {settings.t("crowdsec.section.blockManually")}
                    </h4>
                    <div style={{ display: "flex", gap: "10px", "align-items": "flex-end", "flex-wrap": "wrap" }}>
                      <div class="form-group" style={{ "margin-bottom": 0 }}>
                        <label class="label" style={{ "font-size": "11px" }}>{settings.t("crowdsec.ipAddress")}</label>
                        <input
                          type="text"
                          class="input"
                          placeholder={settings.t("crowdsec.placeholder.ipAddr")}
                          value={blockIp()}
                          onInput={(e) => setBlockIp(e.currentTarget.value)}
                          onKeyDown={(e) => e.key === "Enter" && handleBlock()}
                          style={{ height: "34px", "font-size": "13px", width: "160px" }}
                        />
                      </div>
                      <div class="form-group" style={{ "margin-bottom": 0 }}>
                        <label class="label" style={{ "font-size": "11px" }}>{settings.t("crowdsec.duration")}</label>
                        <select
                          class="input"
                          value={blockDuration()}
                          onChange={(e) => setBlockDuration(e.currentTarget.value)}
                          style={{ height: "34px", "font-size": "13px", width: "130px" }}
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
                      <div class="form-group" style={{ "margin-bottom": 0 }}>
                        <label class="label" style={{ "font-size": "11px" }}>{settings.t("crowdsec.reason")}</label>
                        <input
                          type="text"
                          class="input"
                          placeholder={settings.t("crowdsec.placeholder.reason")}
                          value={blockReason()}
                          onInput={(e) => setBlockReason(e.currentTarget.value)}
                          style={{ height: "34px", "font-size": "13px", width: "160px" }}
                        />
                      </div>
                      {/* Domain selector */}
                      <div class="form-group" style={{ "margin-bottom": 0, position: "relative" }} ref={domainDropdownRef}>
                        <label class="label" style={{ "font-size": "11px" }}>{settings.t("crowdsec.field.domains")}</label>
                        <button
                          type="button"
                          class="input"
                          onClick={() => setDomainDropdownOpen(!domainDropdownOpen())}
                          style={{
                            height: "34px",
                            "font-size": "13px",
                            width: "200px",
                            "text-align": "left",
                            cursor: "pointer",
                            background: "var(--input-bg, #0d0d1a)",
                            border: "1px solid var(--border-color, #2a2a2a)",
                            "border-radius": "var(--radius-sm, 6px)",
                            color: "var(--text-primary, #e0e0e0)",
                            padding: "0 10px",
                            display: "flex",
                            "align-items": "center",
                            "justify-content": "space-between",
                          }}
                        >
                          <span style={{
                            overflow: "hidden",
                            "text-overflow": "ellipsis",
                            "white-space": "nowrap",
                            color: blockConnectionIds().length === 0 ? "var(--text-muted)" : "var(--text-primary)",
                          }}>
                            {blockConnectionIds().length === 0
                              ? settings.t("crowdsec.placeholder.allDomains")
                              : settings.t("crowdsec.domains.count", { n: blockConnectionIds().length })}
                          </span>
                          <span style={{ color: "var(--text-muted)", "font-size": "10px" }}>
                            {domainDropdownOpen() ? "▲" : "▼"}
                          </span>
                        </button>
                        <Show when={domainDropdownOpen()}>
                          <div
                            style={{
                              position: "absolute",
                              top: "100%",
                              left: 0,
                              "z-index": 100,
                              "min-width": "260px",
                              background: "var(--bg-elevated, #1a1a2e)",
                              border: "1px solid var(--border-color, #2a2a2a)",
                              "border-radius": "var(--radius-md, 8px)",
                              "box-shadow": "0 8px 24px rgba(0,0,0,0.4)",
                              "margin-top": "4px",
                              padding: "6px",
                              "max-height": "240px",
                              "overflow-y": "auto",
                            }}
                          >
                            <div
                              class="checkbox-row"
                              onClick={() => {
                                const enabledConns = connections().filter(c => c.enabled);
                                if (blockConnectionIds().length === enabledConns.length) {
                                  setBlockConnectionIds([]);
                                } else {
                                  setBlockConnectionIds(enabledConns.map(c => c.id));
                                }
                              }}
                              style={{
                                padding: "8px 10px",
                                "border-bottom": "1px solid var(--border-subtle, #2a2a2a)",
                                "font-weight": 600,
                                "font-size": "12px",
                              }}
                            >
                              <input
                                type="checkbox"
                                checked={
                                  blockConnectionIds().length > 0 &&
                                  blockConnectionIds().length === connections().filter(c => c.enabled).length
                                }
                                readonly
                                style={{ "margin-right": "8px", "accent-color": "var(--accent-1)", "pointer-events": "none" }}
                              />
                              {blockConnectionIds().length === connections().filter(c => c.enabled).length
                                ? settings.t("crowdsec.btn.deselectAll")
                                : settings.t("crowdsec.btn.selectAll")}
                            </div>
                            <Show
                              when={connections().length > 0}
                              fallback={
                                <div style={{ padding: "12px", "font-size": "12px", color: "var(--text-muted)", "text-align": "center" }}>
                                  {settings.t("crowdsec.empty.noConnections")}
                                </div>
                              }
                            >
                              <For each={connections().filter(c => c.enabled)}>
                                {(conn) => (
                                  <div
                                    class="checkbox-row"
                                    onClick={() => {
                                      setBlockConnectionIds(prev =>
                                        prev.includes(conn.id)
                                          ? prev.filter(id => id !== conn.id)
                                          : [...prev, conn.id]
                                      );
                                    }}
                                    style={{ padding: "6px 10px", "font-size": "12px" }}
                                  >
                                    <input
                                      type="checkbox"
                                      checked={blockConnectionIds().includes(conn.id)}
                                      readonly
                                      style={{ "margin-right": "8px", "accent-color": "var(--accent-1)", "pointer-events": "none" }}
                                    />
                                    <span style={{ "font-weight": 500 }}>{conn.name}</span>
                                    <span style={{ color: "var(--text-muted)", "margin-left": "6px", "font-size": "11px" }}>
                                      {conn.domain ? `(${conn.domain})` : settings.t("crowdsec.noDomains")}
                                    </span>
                                  </div>
                                )}
                              </For>
                            </Show>
                          </div>
                        </Show>
                      </div>
                      <button
                        class="btn btn-danger"
                        onClick={() => handleBlock()}
                        disabled={actionLoading() === "block" || !blockIp().trim()}
                        style={{ height: "34px" }}
                      >
                        <Show
                          when={actionLoading() === "block"}
                          fallback={<Ban size={14} />}
                        >
                          <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} />
                        </Show>
                        {settings.t("crowdsec.btn.blockIp")}
                      </button>
                    </div>
                  </div>

                  {/* Active Decisions */}
                  <div style={{ padding: "12px 20px", "border-bottom": "1px solid var(--border-default)" }}>
                    <div style={{ display: "flex", "align-items": "center", "justify-content": "space-between", "margin-bottom": "8px" }}>
                      <h4 style={{ "font-size": "13px", "font-weight": 600, margin: 0, display: "flex", "align-items": "center", gap: "6px" }}>
                        <Globe size={14} style={{ color: "var(--accent-1)" }} />
                        {settings.t("crowdsec.section.activeDecisions")}
                      </h4>
                      <button
                        class="btn btn-outline btn-sm"
                        onClick={() => handleDeleteAllDecisions()}
                        disabled={actionLoading() === "deleteAll" || decisions().length === 0}
                      >
                        <Trash2 size={11} />
                        {settings.t("crowdsec.btn.clearAll")}
                      </button>
                    </div>
                    <div class="table-wrapper" style={{ "max-height": "240px", "overflow-y": "auto" }}>
                      <table class="table">
                        <thead>
                          <tr>
                            <th>{settings.t("crowdsec.table.ip")}</th>
                            <th>{settings.t("crowdsec.table.type")}</th>
                            <th>{settings.t("crowdsec.table.reason")}</th>
                            <th>{settings.t("crowdsec.table.blockedOn")}</th>
                            <th>{settings.t("crowdsec.table.expires")}</th>
                            <th>{settings.t("crowdsec.table.action")}</th>
                          </tr>
                        </thead>
                        <tbody>
                          <Show
                            when={decisions().length > 0}
                            fallback={
                              <tr>
                                <td colspan={6} style={{ "text-align": "center", color: "var(--text-muted)", padding: "16px" }}>
                                  {settings.t("crowdsec.empty.noDecisions")}
                                </td>
                              </tr>
                            }
                          >
                            <For each={decisions()}>
                              {(d, i) => (
                                <tr>
                                  <td style={{ "font-family": "monospace", "font-size": "12px", "font-weight": 500 }}>
                                    {d.value}
                                  </td>
                                  <td>
                                    <span class={`badge ${d.type === "ban" ? "badge-danger" : "badge-warning"}`}>
                                      {d.type}
                                    </span>
                                  </td>
                                  <td style={{ "font-size": "12px", color: "var(--text-secondary)" }}>
                                    {d.reason || "-"}
                                  </td>
                                  <td style={{ "font-size": "11px", color: "var(--text-secondary)", "max-width": "180px" }}>
                                    <Show
                                      when={d.blocked_on?.length > 0}
                                      fallback={<span style={{ color: "var(--text-muted)", "font-style": "italic" }}>{settings.t("crowdsec.all")}</span>}
                                    >
                                      <For each={d.blocked_on}>
                                        {(name, idx) => {
                                          const conn = () => connections().find(c => c.name === name);
                                          const domains = () => conn()?.domain || "";
                                          return (
                                            <span>
                                              <span
                                                class="badge badge-primary"
                                                style={{ "font-size": "10px", cursor: "help" }}
                                                title={domains() || name}
                                              >
                                                {name}
                                              </span>
                                              <Show when={idx() < d.blocked_on.length - 1}>
                                                {" "}
                                              </Show>
                                            </span>
                                          );
                                        }}
                                      </For>
                                    </Show>
                                  </td>
                                  <td style={{ "font-size": "11px", color: "var(--text-muted)" }}>
                                    {d.until || d.duration || "-"}
                                  </td>
                                  <td>
                                    <button
                                      class="btn btn-outline btn-sm"
                                      onClick={() => handleUnblock(d.value)}
                                      disabled={actionLoading() === `unblock-${d.value}`}
                                      style={{ color: "var(--success)", "border-color": "rgba(16,185,129,0.3)" }}
                                    >
                                      <Unlock size={11} />
                                      {settings.t("crowdsec.btn.unblock")}
                                    </button>
                                  </td>
                                </tr>
                              )}
                            </For>
                          </Show>
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Manual Block History */}
                  <div style={{ padding: "12px 20px" }}>
                    <h4 style={{ "font-size": "13px", "font-weight": 600, "margin-bottom": "8px", display: "flex", "align-items": "center", gap: "6px" }}>
                      <Clock size={14} style={{ color: "var(--accent-2)" }} />
                      {settings.t("crowdsec.section.manualHistory")}
                    </h4>
                    <div class="table-wrapper" style={{ "max-height": "240px", "overflow-y": "auto" }}>
                      <table class="table">
                        <thead>
                          <tr>
                            <th>{settings.t("crowdsec.table.time")}</th>
                            <th>{settings.t("crowdsec.table.action")}</th>
                            <th>{settings.t("crowdsec.table.ip")}</th>
                            <th>{settings.t("crowdsec.table.duration")}</th>
                            <th>{settings.t("crowdsec.table.reason")}</th>
                          </tr>
                        </thead>
                        <tbody>
                          <Show
                            when={manualLog().length > 0}
                            fallback={
                              <tr>
                                <td colspan={5} style={{ "text-align": "center", color: "var(--text-muted)", padding: "16px" }}>
                                  {settings.t("crowdsec.empty.noManual")}
                                </td>
                              </tr>
                            }
                          >
                            <For each={manualLog()}>
                              {(entry) => (
                                <tr>
                                  <td style={{ "font-size": "11px", color: "var(--text-muted)" }}>
                                    {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "-"}
                                  </td>
                                  <td>
                                    <span class={`badge ${entry.action === "block" ? "badge-danger" : "badge-success"}`}>
                                      {entry.action}
                                    </span>
                                  </td>
                                  <td style={{ "font-family": "monospace", "font-size": "12px" }}>{entry.ip}</td>
                                  <td style={{ "font-size": "11px", color: "var(--text-secondary)" }}>
                                    {entry.duration || "-"}
                                  </td>
                                  <td style={{ "font-size": "11px", color: "var(--text-muted)" }}>
                                    {entry.reason || "-"}
                                  </td>
                                </tr>
                              )}
                            </For>
                          </Show>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </Show>
            </div>
          </Show>

          {/* ── Card 3: Scenarios ── */}
          <Show when={visiblePanels().has("scenarios")}>
            <div class="card" style={{ cursor: "pointer" }} onClick={() => toggleCard("scenarios")}>
              <div
                class="card-header"
                style={{ "user-select": "none" }}
              >
                <div style={{ display: "flex", "align-items": "center", gap: "12px" }}>
                  <div class="metric-icon cyan" style={{ width: "36px", height: "36px", "border-radius": "var(--radius-md)", display: "flex", "align-items": "center", "justify-content": "center", background: "rgba(6,182,212,0.1)", color: "var(--accent-3)" }}>
                    <Package size={18} />
                  </div>
                  <div>
                    <div class="metric-label">{settings.t("crowdsec.panel.scenarios")}</div>
                    <div class="metric-value" style={{ margin: 0, "font-size": "18px" }}>
                      {status()?.scenarios_count ?? 0}
                    </div>
                  </div>
                </div>
                <CardChevron card="scenarios" />
              </div>
              <Show when={isExpanded("scenarios")}>
                <div
                  onClick={(e) => e.stopPropagation()}
                  style={{ "border-top": "1px solid var(--border-default)" }}
                >
                  {/* Search + Browse Hub toolbar */}
                  <div style={{ padding: "12px 20px", display: "flex", "align-items": "center", gap: "8px", "border-bottom": "1px solid var(--border-default)" }}>
                    <div style={{ position: "relative", flex: 1 }}>
                      <Search
                        size={14}
                        style={{
                          position: "absolute",
                          left: "8px",
                          top: "50%",
                          transform: "translateY(-50%)",
                          color: "var(--text-muted)",
                          "pointer-events": "none",
                        }}
                      />
                      <input
                        type="text"
                        class="input"
                        placeholder={settings.t("crowdsec.placeholder.searchScenarios")}
                        value={scenarioSearch()}
                        onInput={(e) => setScenarioSearch(e.currentTarget.value)}
                        style={{
                          "padding-left": "28px",
                          "padding-right": scenarioSearch() ? "28px" : "8px",
                          height: "32px",
                          "font-size": "12px",
                          width: "100%",
                        }}
                      />
                      <Show when={scenarioSearch()}>
                        <button
                          onClick={() => setScenarioSearch("")}
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
                      </Show>
                    </div>
                    <button
                      class="btn btn-outline btn-sm"
                      onClick={() => loadHubScenarios()}
                      disabled={actionLoading() === "hub"}
                      style={{ "white-space": "nowrap" }}
                    >
                      <Plus size={12} />
                      {settings.t("crowdsec.btn.browseHub")}
                    </button>
                  </div>

                  {/* Installed scenarios */}
                  <div style={{ padding: "8px 20px 4px" }}>
                    <h4 style={{ "font-size": "12px", color: "var(--text-muted)", "text-transform": "uppercase", "letter-spacing": "0.05em", margin: 0 }}>
                      {settings.t("crowdsec.installedScenarios")}
                    </h4>
                  </div>
                  <div class="table-wrapper" style={{ "max-height": "260px", "overflow-y": "auto" }}>
                    <table class="table">
                      <thead>
                        <tr>
                          <th>{settings.t("crowdsec.table.name")}</th>
                          <th>{settings.t("crowdsec.table.description")}</th>
                          <th>{settings.t("crowdsec.table.type")}</th>
                          <th>{settings.t("crowdsec.panel.status")}</th>
                          <th>{settings.t("crowdsec.table.labels")}</th>
                          <th>{settings.t("crowdsec.table.action")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        <Show
                          when={scenarios().length > 0}
                          fallback={
                            <tr>
                              <td colspan={6} style={{ "text-align": "center", color: "var(--text-muted)", padding: "20px" }}>
                                {settings.t("crowdsec.empty.noInstalled")}
                              </td>
                            </tr>
                          }
                        >
                          <Show
                            when={filteredScenarios().length > 0}
                            fallback={
                              <tr>
                                <td colspan={6} style={{ "text-align": "center", color: "var(--text-muted)", padding: "20px" }}>
                                  {settings.t("crowdsec.empty.noMatch", { query: scenarioSearch() })}
                                </td>
                              </tr>
                            }
                          >
                            <For each={filteredScenarios()}>
                              {(s) => (
                                <tr>
                                  <td style={{ "font-family": "monospace", "font-size": "11px", "font-weight": 500 }}>
                                    {s.name}
                                  </td>
                                  <td style={{ "font-size": "11px", color: "var(--text-secondary)", "max-width": "200px", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }} title={s.description || ""}>
                                    {s.description || "-"}
                                  </td>
                                  <td>
                                    <span class="badge badge-secondary" style={{ "font-size": "10px" }}>{s.type || settings.t("crowdsec.badge.scenario")}</span>
                                  </td>
                                  <td>
                                    <span
                                      class={`badge ${s.loaded ? "badge-success" : "badge-secondary"}`}
                                      style={{ "font-size": "10px" }}
                                    >
                                      {s.loaded ? settings.t("crowdsec.active") : settings.t("crowdsec.inactive")}
                                    </span>
                                  </td>
                                  <td>
                                    <Show
                                      when={s.labels?.length > 0}
                                      fallback={"-"}
                                    >
                                      <For each={s.labels}>
                                        {(lbl) => (
                                          <span
                                            class="badge badge-primary"
                                            style={{ "margin-right": "3px", "font-size": "10px" }}
                                          >
                                            {lbl}
                                          </span>
                                        )}
                                      </For>
                                    </Show>
                                  </td>
                                  <td>
                                    <div style={{ display: "flex", gap: "4px" }}>
                                      <button
                                        class="btn btn-outline btn-sm"
                                        onClick={() => handleToggleScenario(s.name)}
                                        disabled={actionLoading() === `toggle-${s.name}`}
                                        style={{
                                          color: s.loaded ? "var(--warning)" : "var(--success)",
                                          "border-color": s.loaded ? "rgba(245,158,11,0.3)" : "rgba(16,185,129,0.3)",
                                          "font-size": "10px",
                                          padding: "2px 6px",
                                        }}
                                        title={s.loaded ? settings.t("crowdsec.btn.disable") : settings.t("crowdsec.btn.enable")}
                                      >
                                        <Show
                                          when={actionLoading() === `toggle-${s.name}`}
                                          fallback={s.loaded ? <ToggleRight size={10} /> : <ToggleLeft size={10} />}
                                        >
                                          <RefreshCw size={10} style={{ animation: "spin 1s linear infinite" }} />
                                        </Show>
                                        {s.loaded ? settings.t("crowdsec.btn.disable") : settings.t("crowdsec.btn.enable")}
                                      </button>
                                      <button
                                        class="btn btn-outline btn-sm"
                                        onClick={() => handleRemoveScenario(s.name)}
                                        disabled={actionLoading() === `remove-${s.name}`}
                                        style={{ color: "var(--danger)", "border-color": "rgba(244,63,94,0.2)", "font-size": "10px", padding: "2px 6px" }}
                                      >
                                        <Trash2 size={10} />
                                        {settings.t("crowdsec.btn.remove")}
                                      </button>
                                    </div>
                                  </td>
                                </tr>
                              )}
                            </For>
                          </Show>
                        </Show>
                      </tbody>
                    </table>
                  </div>

                  {/* Hub scenarios */}
                  <Show when={hubScenarios().length > 0}>
                    <>
                      <div
                        style={{
                          padding: "12px 20px",
                          display: "flex",
                          "align-items": "center",
                          "justify-content": "space-between",
                          cursor: "pointer",
                          "border-top": "1px solid var(--border-default)",
                        }}
                        onClick={() => setHubExpanded(!hubExpanded())}
                      >
                        <h4 style={{ "font-size": "12px", color: "var(--text-muted)", "text-transform": "uppercase", "letter-spacing": "0.05em", margin: 0 }}>
                          {settings.t("crowdsec.section.hub", { n: filteredHubScenarios().length })}
                        </h4>
                        <Show when={hubExpanded()} fallback={<ChevronDown size={14} style={{ color: "var(--text-muted)" }} />}>
                          <ChevronUp size={14} style={{ color: "var(--text-muted)" }} />
                        </Show>
                      </div>
                      <Show when={hubExpanded()}>
                        <div class="table-wrapper" style={{ "max-height": "260px", "overflow-y": "auto" }}>
                          <table class="table">
                            <thead>
                              <tr>
                                <th>{settings.t("crowdsec.table.name")}</th>
                                <th>{settings.t("crowdsec.table.description")}</th>
                                <th>Author</th>
                                <th>{settings.t("crowdsec.table.action")}</th>
                              </tr>
                            </thead>
                            <tbody>
                              <Show
                                when={filteredHubScenarios().length > 0}
                                fallback={
                                  <tr>
                                    <td colspan={4} style={{ "text-align": "center", color: "var(--text-muted)", padding: "20px" }}>
                                      {scenarioSearch() ? settings.t("crowdsec.empty.noHubMatch", { query: scenarioSearch() }) : settings.t("crowdsec.empty.noHub")}
                                    </td>
                                  </tr>
                                }
                              >
                                <For each={filteredHubScenarios()}>
                                  {(s) => (
                                    <tr>
                                      <td style={{ "font-family": "monospace", "font-size": "11px", "font-weight": 500 }}>
                                        {s.name}
                                      </td>
                                      <td style={{ "font-size": "11px", color: "var(--text-secondary)" }}>
                                        {s.description || "-"}
                                      </td>
                                      <td style={{ "font-size": "11px", color: "var(--text-muted)" }}>
                                        {s.author || "-"}
                                      </td>
                                      <td>
                                        <Show
                                          when={s.installed}
                                          fallback={
                                            <button
                                              class="btn btn-outline btn-sm"
                                              onClick={() => handleInstallScenario(s.name)}
                                              disabled={actionLoading() === `install-${s.name}`}
                                              style={{ "font-size": "10px", padding: "2px 6px" }}
                                            >
                                              <Plus size={10} />
                                              {settings.t("crowdsec.btn.install")}
                                            </button>
                                          }
                                        >
                                          <span class="badge badge-success" style={{ "font-size": "10px" }}>{settings.t("crowdsec.installed")}</span>
                                        </Show>
                                      </td>
                                    </tr>
                                  )}
                                </For>
                              </Show>
                            </tbody>
                          </table>
                        </div>
                      </Show>
                    </>
                  </Show>
                </div>
              </Show>
            </div>
          </Show>

          {/* ── Card 4: Alerts ── */}
          <Show when={visiblePanels().has("alerts")}>
            <div class="card" style={{ cursor: "pointer" }} onClick={() => toggleCard("alerts")}>
              <div
                class="card-header"
                style={{ "user-select": "none" }}
              >
                <div style={{ display: "flex", "align-items": "center", gap: "12px" }}>
                  <div class="metric-icon emerald" style={{ width: "36px", height: "36px", "border-radius": "var(--radius-md)", display: "flex", "align-items": "center", "justify-content": "center", background: "rgba(16,185,129,0.1)", color: "var(--success)" }}>
                    <HardDrive size={18} />
                  </div>
                  <div>
                    <div class="metric-label">{settings.t("crowdsec.panel.alerts")}</div>
                    <div class="metric-value" style={{ margin: 0, "font-size": "18px" }}>
                      {status()?.alerts_count ?? 0}
                    </div>
                  </div>
                </div>
                <CardChevron card="alerts" />
              </div>
              <Show when={isExpanded("alerts")}>
                <div
                  onClick={(e) => e.stopPropagation()}
                  style={{ "border-top": "1px solid var(--border-default)", padding: "12px 20px" }}
                >
                  <div class="table-wrapper" style={{ "max-height": "280px", "overflow-y": "auto" }}>
                    <table class="table">
                      <thead>
                        <tr>
                          <th>{settings.t("crowdsec.table.scenario")}</th>
                          <th>{settings.t("crowdsec.table.message")}</th>
                          <th>{settings.t("crowdsec.table.sourceIp")}</th>
                          <th>{settings.t("crowdsec.table.decisions")}</th>
                          <th>{settings.t("crowdsec.table.started")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        <Show
                          when={alerts().length > 0}
                          fallback={
                            <tr>
                              <td colspan={5} style={{ "text-align": "center", color: "var(--text-muted)", padding: "24px" }}>
                                {settings.t("crowdsec.empty.noAlerts")}
                              </td>
                            </tr>
                          }
                        >
                          <For each={alerts()}>
                            {(a) => (
                              <tr>
                                <td style={{ "font-family": "monospace", "font-size": "11px", "font-weight": 500, "max-width": "200px", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }} title={a.scenario || ""}>
                                  {a.scenario || "-"}
                                </td>
                                <td style={{ "font-size": "11px", color: "var(--text-secondary)", "max-width": "300px", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }} title={a.message || ""}>
                                  {a.message || "-"}
                                </td>
                                <td style={{ "font-family": "monospace", "font-size": "11px" }}>
                                  {a.source_ip || "-"}
                                </td>
                                <td>
                                  <span class="badge badge-warning" style={{ "font-size": "10px" }}>
                                    {a.decisions_count}
                                  </span>
                                </td>
                                <td style={{ "font-size": "11px", color: "var(--text-muted)" }}>
                                  {a.start_at ? new Date(a.start_at).toLocaleString() : "-"}
                                </td>
                              </tr>
                            )}
                          </For>
                        </Show>
                      </tbody>
                    </table>
                  </div>
                </div>
              </Show>
            </div>
          </Show>

        </div>
      </div>
    </Show>
  );
}
