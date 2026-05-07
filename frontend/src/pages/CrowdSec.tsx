import { useState, useEffect, useCallback } from "react";
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
} from "lucide-react";
import { api, CrowdSecStatus, DecisionItem, ScenarioInfo } from "../api/client";

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
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

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

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [s, d, sc, ml] = await Promise.all([
        api.getCrowdSecStatus(),
        api.getCrowdSecDecisions(),
        api.getCrowdSecScenarios(),
        api.getCrowdSecManualBlocks(50),
      ]);
      setStatus(s);
      setDecisions(d);
      setScenarios(sc);
      setManualLog(ml);
    } catch {
      showToast("Failed to load CrowdSec data", "error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

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
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  if (loading) {
    return (
      <div className="page-wrapper" style={{ padding: "32px" }}>
        <div className="loading-spinner">Loading CrowdSec data...</div>
      </div>
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
        <button
          className="btn btn-outline"
          onClick={handleReload}
          disabled={actionLoading === "reload"}
        >
          <RefreshCw
            size={14}
            style={{
              animation:
                actionLoading === "reload" ? "spin 1s linear infinite" : "none",
            }}
          />
          Reload
        </button>
      </div>

      {/* Status cards */}
      <div className="metric-cards" style={{ marginBottom: "24px" }}>
        <div className="metric-card">
          <div className="metric-icon violet">
            <Shield size={18} />
          </div>
          <div className="metric-label">Status</div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              marginTop: "4px",
            }}
          >
            <span
              className="badge"
              style={
                status?.running
                  ? {
                      background: "rgba(16,185,129,0.12)",
                      color: "var(--success)",
                    }
                  : {
                      background: "rgba(244,63,94,0.12)",
                      color: "var(--danger)",
                    }
              }
            >
              {status?.running ? "RUNNING" : "STOPPED"}
            </span>
          </div>
          <div className="metric-change" style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "6px" }}>
            {status?.version || "Unknown"}
          </div>
        </div>
        <div className="metric-card">
          <div className="metric-icon rose">
            <Ban size={18} />
          </div>
          <div className="metric-label">Active Blocks</div>
          <div className="metric-value">{status?.decisions_count ?? 0}</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon cyan">
            <Package size={18} />
          </div>
          <div className="metric-label">Scenarios</div>
          <div className="metric-value">{status?.scenarios_count ?? 0}</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon emerald">
            <HardDrive size={18} />
          </div>
          <div className="metric-label">Alerts</div>
          <div className="metric-value">{status?.alerts_count ?? 0}</div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
        {/* ── Block IP form ── */}
        <div>
          <div className="card">
            <div className="card-header">
              <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Ban size={16} style={{ color: "var(--danger)" }} />
                Block IP Manually
              </h3>
            </div>
            <div style={{ padding: "20px", display: "flex", flexDirection: "column", gap: "12px" }}>
              <div className="form-group">
                <label className="label">IP Address</label>
                <input
                  type="text"
                  className="input"
                  placeholder="192.168.1.100"
                  value={blockIp}
                  onChange={(e) => setBlockIp(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleBlock()}
                />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                <div className="form-group">
                  <label className="label">Duration</label>
                  <select
                    className="input"
                    value={blockDuration}
                    onChange={(e) => setBlockDuration(e.target.value)}
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
                <div className="form-group">
                  <label className="label">Reason</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="Reason..."
                    value={blockReason}
                    onChange={(e) => setBlockReason(e.target.value)}
                  />
                </div>
              </div>
              <button
                className="btn btn-danger"
                onClick={handleBlock}
                disabled={actionLoading === "block" || !blockIp.trim()}
                style={{ alignSelf: "flex-start" }}
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

          {/* ── Manual block audit log ── */}
          <div className="card" style={{ marginTop: "24px" }}>
            <div className="card-header">
              <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Clock size={16} style={{ color: "var(--accent-2)" }} />
                Manual Block History
              </h3>
            </div>
            <div className="table-wrapper">
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
                      <td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: "24px" }}>
                        No manual blocks yet
                      </td>
                    </tr>
                  ) : (
                    manualLog.map((entry, i) => (
                      <tr key={i}>
                        <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                          {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "-"}
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              entry.action === "block" ? "badge-danger" : "badge-success"
                            }`}
                          >
                            {entry.action}
                          </span>
                        </td>
                        <td style={{ fontFamily: "monospace", fontSize: "13px" }}>{entry.ip}</td>
                        <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                          {entry.duration || "-"}
                        </td>
                        <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>
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

        {/* ── Active decisions ── */}
        <div>
          <div className="card">
            <div className="card-header">
              <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Globe size={16} style={{ color: "var(--accent-1)" }} />
                Active Decisions
              </h3>
              <button
                className="btn btn-outline btn-sm"
                onClick={handleDeleteAllDecisions}
                disabled={actionLoading === "deleteAll" || decisions.length === 0}
                style={{ marginLeft: "auto" }}
              >
                <Trash2 size={12} />
                Clear All
              </button>
            </div>
            <div className="table-wrapper">
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
                      <td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: "24px" }}>
                        No active decisions
                      </td>
                    </tr>
                  ) : (
                    decisions.map((d, i) => (
                      <tr key={d.id ?? i}>
                        <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 500 }}>
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
                        <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                          {d.until || d.duration || "-"}
                        </td>
                        <td>
                          <button
                            className="btn btn-outline btn-sm"
                            onClick={() => handleUnblock(d.value)}
                            disabled={actionLoading === `unblock-${d.value}`}
                            style={{ color: "var(--success)", borderColor: "rgba(16,185,129,0.3)" }}
                          >
                            <Unlock size={12} />
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
        </div>
      </div>

      {/* ── Scenarios ── */}
      <div className="card" style={{ marginTop: "24px" }}>
        <div className="card-header">
          <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Package size={16} style={{ color: "var(--accent-3)" }} />
            Scenarios
          </h3>
          <button
            className="btn btn-outline btn-sm"
            onClick={loadHubScenarios}
            disabled={actionLoading === "hub"}
            style={{ marginLeft: "auto" }}
          >
            <Plus size={12} />
            Browse Hub
          </button>
        </div>

        {/* Installed scenarios */}
        <div style={{ padding: "8px 20px" }}>
          <h4 style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "8px", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Installed Scenarios
          </h4>
        </div>
        <div className="table-wrapper">
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
                  <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: "24px" }}>
                    No scenarios installed
                  </td>
                </tr>
              ) : (
                scenarios.map((s, i) => (
                  <tr key={s.name ?? i}>
                    <td style={{ fontFamily: "monospace", fontSize: "12px", fontWeight: 500 }}>
                      {s.name}
                    </td>
                    <td style={{ fontSize: "12px", color: "var(--text-secondary)", maxWidth: "250px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {s.description || "-"}
                    </td>
                    <td>
                      <span className="badge badge-secondary">{s.type || "scenario"}</span>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          s.loaded ? "badge-success" : "badge-secondary"
                        }`}
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
                              style={{ marginRight: "4px" }}
                            >
                              {lbl}
                            </span>
                          ))
                        : "-"}
                    </td>
                    <td>
                      <button
                        className="btn btn-outline btn-sm"
                        onClick={() => handleRemoveScenario(s.name)}
                        disabled={actionLoading === `remove-${s.name}`}
                        style={{ color: "var(--danger)", borderColor: "rgba(244,63,94,0.2)" }}
                      >
                        <Trash2 size={11} />
                        Remove
                      </button>
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
            <div style={{ padding: "16px 20px 8px" }}>
              <h4 style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "8px", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                Available in Hub
              </h4>
            </div>
            <div className="table-wrapper">
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
                  {hubScenarios.map((s, i) => (
                    <tr key={s.name ?? i}>
                      <td style={{ fontFamily: "monospace", fontSize: "12px", fontWeight: 500 }}>
                        {s.name}
                      </td>
                      <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                        {s.description || "-"}
                      </td>
                      <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                        {s.author || "-"}
                      </td>
                      <td>
                        {s.installed ? (
                          <span className="badge badge-success">Installed</span>
                        ) : (
                          <button
                            className="btn btn-outline btn-sm"
                            onClick={() => handleInstallScenario(s.name)}
                            disabled={actionLoading === `install-${s.name}`}
                          >
                            <Plus size={11} />
                            Install
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
