import { useState, useEffect, useCallback, useMemo } from "react";
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
} from "lucide-react";
import { api, CrowdSecStatus, DecisionItem, ScenarioInfo, AlertItem } from "../api/client";

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

export default function CrowdSec() {
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

  // Block form state
  const [blockIp, setBlockIp] = useState("");
  const [blockDuration, setBlockDuration] = useState("4h");
  const [blockReason, setBlockReason] = useState("manual block");

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
      const [s, d, sc, ml, svc] = await Promise.all([
        api.getCrowdSecStatus(),
        api.getCrowdSecDecisions(),
        api.getCrowdSecScenarios(),
        api.getCrowdSecManualBlocks(50),
        api.getCrowdSecServiceStatus().catch(() => ({ enabled: true })),
      ]);
      setStatus(s);
      setDecisions(d);
      setScenarios(sc);
      setManualLog(ml);
      setServiceEnabled(svc.enabled);
    } catch {
      showToast("Failed to load CrowdSec data", "error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  async function loadAlerts() {
    try {
      const items = await api.getCrowdSecAlerts();
      setAlerts(items);
    } catch (e: any) {
      showToast(e.message, "error");
    }
  }

  async function handleBlock() {
    if (!blockIp.trim()) {
      showToast("Please enter an IP address", "error");
      return;
    }
    setActionLoading("block");
    try {
      const result = await api.addCrowdSecDecision({
        ip: blockIp.trim(),
        duration: blockDuration,
        reason: blockReason,
        type: "ban",
      });
      if (result.success) {
        showToast(`IP ${blockIp} blocked successfully`, "success");
        setBlockIp("");
        setBlockReason("manual block");
        loadData();
      } else {
        showToast(result.message || "Failed to block IP", "error");
      }
    } catch (e: any) {
      showToast(e.message || "Failed to block IP", "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleUnblock(ip: string) {
    setActionLoading(`unblock-${ip}`);
    try {
      const result = await api.deleteCrowdSecDecision(ip);
      if (result.success) {
        showToast(`IP ${ip} unblocked`, "success");
        loadData();
      } else {
        showToast(result.message || "Failed to unblock", "error");
      }
    } catch (e: any) {
      showToast(e.message || "Failed to unblock", "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleDeleteAllDecisions() {
    setActionLoading("deleteAll");
    try {
      const result = await api.deleteAllCrowdSecDecisions();
      if (result.success) {
        showToast("All blocks removed", "success");
        loadData();
      } else {
        showToast(result.message || "Failed", "error");
      }
    } catch (e: any) {
      showToast(e.message || "Failed to delete all", "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleInstallScenario(name: string) {
    setActionLoading(`install-${name}`);
    try {
      const result = await api.installCrowdSecScenario(name);
      showToast(
        result.success ? `Scenario installed` : result.message || "Failed",
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
        result.success ? `Scenario removed` : result.message || "Failed",
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
          ? `Scenario ${result.enabled ? "enabled" : "disabled"}`
          : result.message || "Failed to toggle scenario",
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
          `CrowdSec service ${result.enabled ? "enabled" : "disabled"}`,
          "success"
        );
        setServiceEnabled(result.enabled);
        loadData();
      } else {
        showToast(result.message || "Failed to toggle service", "error");
      }
    } catch (e: any) {
      showToast(e.message || "Failed to toggle service", "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleReload() {
    setActionLoading("reload");
    try {
      const result = await api.reloadCrowdSec();
      showToast(
        result.success ? "CrowdSec reloaded" : result.message || "Failed",
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

  if (loading) {
    return (
      <div className="page-wrapper" style={{ padding: "32px" }}>
        <div className="loading-spinner">Loading CrowdSec data...</div>
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
          <p>Manage IP blocks, scenarios, and security decisions</p>
        </div>
      </div>

      {/* ── Expandable Metric Cards ── */}
      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

        {/* ── Card 1: Status ── */}
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
                <div className="metric-label">Status</div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "2px" }}>
                  <span
                    className="badge"
                    style={
                      serviceEnabled && status?.running
                        ? { background: "rgba(16,185,129,0.12)", color: "var(--success)" }
                        : { background: "rgba(244,63,94,0.12)", color: "var(--danger)" }
                    }
                  >
                    {!serviceEnabled ? "DISABLED" : status?.running ? "RUNNING" : "STOPPED"}
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
            <div style={{ padding: "16px 20px", borderTop: "1px solid var(--border)" }}>
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
                  {serviceEnabled ? "Disable" : "Enable"}
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
                  Reload
                </button>
              </div>
            </div>
          )}
        </div>

        {/* ── Card 2: Active Blocks ── */}
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
                <div className="metric-label">Active Blocks</div>
                <div className="metric-value" style={{ margin: 0, fontSize: "18px" }}>
                  {status?.decisions_count ?? 0}
                </div>
              </div>
            </div>
            <CardChevron card="blocks" />
          </div>
          {isExpanded("blocks") && (
            <div style={{ borderTop: "1px solid var(--border)" }}>
              {/* Block IP Manually */}
              <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)" }}>
                <h4 style={{ fontSize: "13px", fontWeight: 600, marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <Ban size={14} style={{ color: "var(--danger)" }} />
                  Block IP Manually
                </h4>
                <div style={{ display: "flex", gap: "10px", alignItems: "flex-end", flexWrap: "wrap" }}>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="label" style={{ fontSize: "11px" }}>IP Address</label>
                    <input
                      type="text"
                      className="input"
                      placeholder="192.168.1.100"
                      value={blockIp}
                      onChange={(e) => setBlockIp(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleBlock()}
                      style={{ height: "34px", fontSize: "13px", width: "160px" }}
                    />
                  </div>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="label" style={{ fontSize: "11px" }}>Duration</label>
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
                    <label className="label" style={{ fontSize: "11px" }}>Reason</label>
                    <input
                      type="text"
                      className="input"
                      placeholder="Reason..."
                      value={blockReason}
                      onChange={(e) => setBlockReason(e.target.value)}
                      style={{ height: "34px", fontSize: "13px", width: "160px" }}
                    />
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
                    Block IP
                  </button>
                </div>
              </div>

              {/* Active Decisions */}
              <div style={{ padding: "12px 20px", borderBottom: "1px solid var(--border)" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                  <h4 style={{ fontSize: "13px", fontWeight: 600, margin: 0, display: "flex", alignItems: "center", gap: "6px" }}>
                    <Globe size={14} style={{ color: "var(--accent-1)" }} />
                    Active Decisions
                  </h4>
                  <button
                    className="btn btn-outline btn-sm"
                    onClick={(e) => { e.stopPropagation(); handleDeleteAllDecisions(); }}
                    disabled={actionLoading === "deleteAll" || decisions.length === 0}
                  >
                    <Trash2 size={11} />
                    Clear All
                  </button>
                </div>
                <div className="table-wrapper" style={{ maxHeight: "300px", overflowY: "auto" }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>IP</th>
                        <th>Type</th>
                        <th>Reason</th>
                        <th>Expires</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {decisions.length === 0 ? (
                        <tr>
                          <td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: "16px" }}>
                            No active decisions
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
                                Unblock
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
                  Manual Block History
                </h4>
                <div className="table-wrapper" style={{ maxHeight: "300px", overflowY: "auto" }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Action</th>
                        <th>IP</th>
                        <th>Duration</th>
                        <th>Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {manualLog.length === 0 ? (
                        <tr>
                          <td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: "16px" }}>
                            No manual blocks yet
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

        {/* ── Card 3: Scenarios ── */}
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
                <div className="metric-label">Scenarios</div>
                <div className="metric-value" style={{ margin: 0, fontSize: "18px" }}>
                  {status?.scenarios_count ?? 0}
                </div>
              </div>
            </div>
            <CardChevron card="scenarios" />
          </div>
          {isExpanded("scenarios") && (
            <div style={{ borderTop: "1px solid var(--border)" }}>
              {/* Search + Browse Hub toolbar */}
              <div style={{ padding: "12px 20px", display: "flex", alignItems: "center", gap: "8px", borderBottom: "1px solid var(--border)" }}>
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
                    placeholder="Search scenarios..."
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
                  Browse Hub
                </button>
              </div>

              {/* Installed scenarios */}
              <div style={{ padding: "8px 20px 4px" }}>
                <h4 style={{ fontSize: "12px", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", margin: 0 }}>
                  Installed Scenarios
                </h4>
              </div>
              <div className="table-wrapper" style={{ maxHeight: "400px", overflowY: "auto" }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Description</th>
                      <th>Type</th>
                      <th>Status</th>
                      <th>Labels</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scenarios.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: "20px" }}>
                          No scenarios installed
                        </td>
                      </tr>
                    ) : filteredScenarios.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: "20px" }}>
                          No scenarios match "{scenarioSearch}"
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
                            <span className="badge badge-secondary" style={{ fontSize: "10px" }}>{s.type || "scenario"}</span>
                          </td>
                          <td>
                            <span
                              className={`badge ${s.loaded ? "badge-success" : "badge-secondary"}`}
                              style={{ fontSize: "10px" }}
                            >
                              {s.loaded ? "active" : "inactive"}
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
                                title={s.loaded ? "Disable" : "Enable"}
                              >
                                {actionLoading === `toggle-${s.name}` ? (
                                  <RefreshCw size={10} style={{ animation: "spin 1s linear infinite" }} />
                                ) : s.loaded ? (
                                  <ToggleRight size={10} />
                                ) : (
                                  <ToggleLeft size={10} />
                                )}
                                {s.loaded ? "Disable" : "Enable"}
                              </button>
                              <button
                                className="btn btn-outline btn-sm"
                                onClick={(e) => { e.stopPropagation(); handleRemoveScenario(s.name); }}
                                disabled={actionLoading === `remove-${s.name}`}
                                style={{ color: "var(--danger)", borderColor: "rgba(244,63,94,0.2)", fontSize: "10px", padding: "2px 6px" }}
                              >
                                <Trash2 size={10} />
                                Remove
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
                      borderTop: "1px solid var(--border)",
                    }}
                    onClick={(e) => { e.stopPropagation(); setHubExpanded(!hubExpanded); }}
                  >
                    <h4 style={{ fontSize: "12px", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", margin: 0 }}>
                      Available in Hub ({filteredHubScenarios.length})
                    </h4>
                    {hubExpanded ? <ChevronUp size={14} style={{ color: "var(--text-muted)" }} /> : <ChevronDown size={14} style={{ color: "var(--text-muted)" }} />}
                  </div>
                  {hubExpanded && (
                    <div className="table-wrapper" style={{ maxHeight: "400px", overflowY: "auto" }}>
                      <table className="table">
                        <thead>
                          <tr>
                            <th>Name</th>
                            <th>Description</th>
                            <th>Author</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredHubScenarios.length === 0 ? (
                            <tr>
                              <td colSpan={4} style={{ textAlign: "center", color: "var(--text-muted)", padding: "20px" }}>
                                {scenarioSearch ? `No hub scenarios match "${scenarioSearch}"` : "No hub scenarios available"}
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
                                    <span className="badge badge-success" style={{ fontSize: "10px" }}>Installed</span>
                                  ) : (
                                    <button
                                      className="btn btn-outline btn-sm"
                                      onClick={(e) => { e.stopPropagation(); handleInstallScenario(s.name); }}
                                      disabled={actionLoading === `install-${s.name}`}
                                      style={{ fontSize: "10px", padding: "2px 6px" }}
                                    >
                                      <Plus size={10} />
                                      Install
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

        {/* ── Card 4: Alerts ── */}
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
                <div className="metric-label">Alerts</div>
                <div className="metric-value" style={{ margin: 0, fontSize: "18px" }}>
                  {status?.alerts_count ?? 0}
                </div>
              </div>
            </div>
            <CardChevron card="alerts" />
          </div>
          {isExpanded("alerts") && (
            <div style={{ borderTop: "1px solid var(--border)", padding: "12px 20px" }}>
              <div className="table-wrapper" style={{ maxHeight: "500px", overflowY: "auto" }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Scenario</th>
                      <th>Message</th>
                      <th>Source IP</th>
                      <th>Decisions</th>
                      <th>Started</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: "24px" }}>
                          No alerts
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

      </div>
    </div>
  );
}
