import { useState, useEffect, useRef } from "react";
import {
  api,
  Connection,
  ConnectionCreate,
  ConnectionUpdate,
} from "../api/client";
import { Plus, Edit2, Trash2, RefreshCw, X, Shield } from "lucide-react";

export default function Connections() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [toast, setToast] = useState<{
    message: string;
    type: "success" | "error" | "info";
  } | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [formData, setFormData] = useState<ConnectionCreate>({
    name: "",
    domains: [],
    mode: "static",
    backend_url: "",
    static_dir: null,
    enabled: true,
    ssl_enabled: true,
    ssl_cert_path: null,
    ssl_key_path: null,
    preserve_host: true,
    custom_nginx_config: null,
  });

  useEffect(() => {
    loadConnections();
  }, []);

  async function loadConnections() {
    setLoading(true);
    try {
      const data = await api.getConnections();
      setConnections(data);
    } catch {
      showToast("Failed to load connections", "error");
    } finally {
      setLoading(false);
    }
  }

  function showToast(
    message: string,
    type: "success" | "error" | "info"
  ) {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  }

  function resetForm() {
    setFormData({
      name: "",
      domains: [],
      mode: "static",
      backend_url: "",
      static_dir: null,
      enabled: true,
      ssl_enabled: true,
      ssl_cert_path: null,
      ssl_key_path: null,
      preserve_host: true,
      custom_nginx_config: null,
    });
    setEditingId(null);
    setShowForm(false);
    const dirInput = document.getElementById("dirInputHidden") as HTMLInputElement;
    if (dirInput) dirInput.value = "";
  }

  function handleEdit(conn: Connection) {
    setEditingId(conn.id);
    setFormData({
      name: conn.name,
      domains: conn.domains,
      mode: conn.mode || "static",
      backend_url: conn.backend_url || "",
      static_dir: conn.static_dir,
      enabled: conn.enabled,
      ssl_enabled: true,
      ssl_cert_path: null,
      ssl_key_path: null,
      preserve_host: true,
      custom_nginx_config: null,
    });
    setShowForm(true);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      if (editingId !== null) {
        await api.updateConnection(editingId, formData);
        showToast("Connection updated successfully", "success");
      } else {
        await api.createConnection(formData);
        showToast("Connection created successfully", "success");
      }
      resetForm();
      loadConnections();
    } catch {
      showToast("Failed to save connection", "error");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: number) {
    if (!confirm("Are you sure you want to delete this connection?")) return;
    try {
      await api.deleteConnection(id);
      showToast("Connection deleted", "success");
      loadConnections();
    } catch {
      showToast("Failed to delete connection", "error");
    }
  }

  async function handleToggleEnabled(conn: Connection) {
    try {
      await api.updateConnection(conn.id, { enabled: !conn.enabled });
      loadConnections();
      showToast(
        conn.enabled ? "Connection disabled" : "Connection enabled",
        "success"
      );
    } catch {
      showToast("Failed to toggle connection", "error");
    }
  }

  async function handleReload() {
    setReloading(true);
    try {
      const result = await api.reloadAngie();
      if (result.success) {
        showToast("Angie reloaded successfully", "success");
      } else {
        showToast(`Reload failed: ${result.message}`, "error");
      }
    } catch {
      showToast("Failed to reload Angie", "error");
    } finally {
      setReloading(false);
    }
  }

  function updateFormField<K extends keyof ConnectionCreate>(
    key: K,
    value: ConnectionCreate[K]
  ) {
    setFormData((prev) => ({ ...prev, [key]: value }));
  }

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
        Loading connections…
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Connections</h1>
          <p>Manage site connections proxied through the WAF</p>
        </div>
        <div className="header-actions">
          <button
            className="btn btn-success"
            onClick={handleReload}
            disabled={reloading}
          >
            <RefreshCw size={16} />
            {reloading ? "Reloading…" : "Reload Nginx"}
          </button>
          <button
            className="btn btn-primary"
            onClick={() => setShowForm(true)}
          >
            <Plus size={16} />
            Add Connection
          </button>
        </div>
      </div>

      {connections.length === 0 ? (
        <div className="card">
          <div style={{ textAlign: "center", padding: "48px 24px" }}>
            <Shield
              size={48}
              style={{ color: "var(--text-muted)", marginBottom: "16px" }}
            />
            <p style={{ fontSize: "16px", fontWeight: 600, marginBottom: "8px" }}>
              No connections configured
            </p>
            <p className="text-muted">
              Add a connection to start proxying traffic through the WAF.
            </p>
          </div>
        </div>
      ) : (
        <div className="connections-grid">
          {connections.map((conn) => (
            <div
              key={conn.id}
              className={`card connection-card ${
                conn.enabled ? "" : "disabled"
              }`}
            >
              <div className="card-header">
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <h3>{conn.name}</h3>
                  <button
                    type="button"
                    className={`btn btn-sm ${conn.enabled ? "btn-success" : "btn-secondary"}`}
                    onClick={() => handleToggleEnabled(conn)}
                    title={conn.enabled ? "Click to disable" : "Click to enable"}
                    style={{
                      padding: "4px 12px",
                      fontSize: "12px",
                      fontWeight: 600,
                      borderRadius: "var(--radius-sm)",
                      transition: "all 0.2s",
                    }}
                  >
                    {conn.enabled ? "ON" : "OFF"}
                  </button>
                </div>
                <div style={{ display: "flex", gap: "4px" }}>
                  <button
                    className="btn-icon"
                    onClick={() => handleEdit(conn)}
                    title="Edit"
                  >
                    <Edit2 size={15} />
                  </button>
                  <button
                    className="btn-icon danger"
                    onClick={() => handleDelete(conn.id)}
                    title="Delete"
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>

              <div className="connection-details">
                <div className="detail-row">
                  <strong>Domains</strong>
                  <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                    {conn.domains.length > 0 ? (
                      conn.domains.map((d) => (
                        <span key={d} className="badge badge-secondary">
                          {d}
                        </span>
                      ))
                    ) : (
                      <span className="text-muted">(catch all)</span>
                    )}
                  </div>
                </div>

                {conn.static_dir && (
                  <div className="detail-row">
                    <strong>Static Dir</strong>
                    <code className="codeblock">{conn.static_dir}</code>
                  </div>
                )}

                <div className="detail-row">
                  <strong>SSL</strong>
                  <span className="badge badge-primary">Auto</span>
                </div>

                <div className="detail-row">
                  <strong>Updated</strong>
                  <span className="text-muted">
                    {new Date(conn.updated_at).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Modal ── */}
      {showForm && (
        <div
          className="modal-overlay"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) {
              (e.currentTarget as HTMLElement).dataset.mousedownTarget = "overlay";
            }
          }}
          onMouseUp={(e) => {
            const overlay = e.currentTarget as HTMLElement;
            if (overlay.dataset.mousedownTarget === "overlay" && e.target === e.currentTarget) {
              resetForm();
            }
            delete overlay.dataset.mousedownTarget;
          }}
        >
          <div className="modal">
            <div className="modal-header">
              <h2>{editingId ? "Edit Connection" : "New Connection"}</h2>
              <button className="btn-icon" onClick={resetForm}>
                <X size={20} />
              </button>
            </div>

            <form onSubmit={handleSubmit}>
              {/* ── Name + Enabled toggle in one row ── */}
              <div className="form-group">
                <label>Name *</label>
                <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => updateFormField("name", e.target.value)}
                    placeholder="My Web App"
                    required
                    style={{ flex: 1 }}
                  />
                  <button
                    type="button"
                    className={`toggle-btn ${formData.enabled ? "active" : ""}`}
                    onClick={() => updateFormField("enabled", !formData.enabled)}
                    title={formData.enabled ? "Enabled — click to disable" : "Disabled — click to enable"}
                  >
                    <span className="toggle-track">
                      <span className="toggle-thumb" />
                    </span>
                    <span className="toggle-label">
                      {formData.enabled ? "ON" : "OFF"}
                    </span>
                  </button>
                </div>
              </div>

              <div className="form-group">
                <label>Domain Names (one per line)</label>
                <textarea
                  className="normal-font"
                  value={formData.domains.join("\n")}
                  onChange={(e) =>
                    updateFormField(
                      "domains",
                      e.target.value.split("\n").filter(Boolean)
                    )
                  }
                  placeholder="example.com&#10;www.example.com"
                  rows={3}
                />
              </div>

              <div className="form-group">
                <label>Static Files Directory (Angie container path)</label>
                <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                  <input
                    type="text"
                    value={formData.static_dir || ""}
                    onChange={(e) =>
                      updateFormField("static_dir", e.target.value || null)
                    }
                    placeholder="/usr/share/angie/html"
                    style={{ flex: 1, minWidth: "200px" }}
                  />
                  <button
                    type="button"
                    className="btn btn-outline btn-sm"
                    onClick={() => {
                      const input = document.getElementById("dirInputHidden") as HTMLInputElement;
                      input?.click();
                    }}
                    title="Browse for index.html — the directory will be used"
                  >
                    Browse index.html
                  </button>
                  <input
                    type="file"
                    id="dirInputHidden"
                    style={{ display: "none" }}
                    accept=".html,.htm"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) {
                        const fileName = file.name;
                        if ((file as any).path) {
                          const rawPath = (file as any).path;
                          if (/^[A-Za-z]:[\\/]/.test(rawPath) || rawPath.includes("\\")) {
                            showToast(
                              `⚠️ Selected "${fileName}" from local disk. Mount this directory into Angie via docker-compose volumes, then enter the container path above.`,
                              "error"
                            );
                          } else {
                            const dirPath = rawPath.replace(/\/[^/]+$/, "");
                            updateFormField("static_dir", dirPath);
                            showToast(`📁 Directory: ${dirPath}`, "info");
                          }
                        } else {
                          showToast(
                            `📄 Selected "${fileName}". Enter the container directory path above (e.g. /usr/share/angie/html).`,
                            "info"
                          );
                        }
                        e.target.value = "";
                      }
                    }}
                  />
                </div>
                <small>
                  Container path inside Angie (e.g. <code>/usr/share/angie/html</code>).
                  Mount host files via <code>docker-compose.yml volumes:</code>, then use the
                  container path here.
                  <br />
                  <strong>Not a Windows path!</strong> Use <code>/var/www/...</code> style paths.
                </small>
              </div>

              <div className="modal-actions">
                <button
                  type="button"
                  className="btn btn-outline"
                  onClick={resetForm}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={saving}
                >
                  {saving
                    ? "Saving…"
                    : editingId
                    ? "Update"
                    : "Create"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {toast && (
        <div className={`toast toast-${toast.type}`}>{toast.message}</div>
      )}
    </div>
  );
}
