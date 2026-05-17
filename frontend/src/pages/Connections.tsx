import { useState, useEffect, useRef, useCallback } from "react";
import {
  api,
  Connection,
  ConnectionCreate,
  SourceType,
} from "../api/client";
import { Plus, Edit2, Trash2, RefreshCw, X, Shield } from "lucide-react";

const SOURCE_TYPES: { value: SourceType; label: string; hint: string }[] = [
  {
    value: "nginx_config",
    label: "Nginx config",
    hint: "Deploy an existing nginx .conf (includes are expanded).",
  },
  {
    value: "static_generate",
    label: "Static site",
    hint: "Generate config from index.html + domain list.",
  },
  {
    value: "container",
    label: "Container / Service",
    hint: "Reverse-proxy to host:port of a container or k8s service.",
  },
];

const DEFAULT_FORM: ConnectionCreate = {
  name: "",
  domains: [],
  source_type: "static_generate",
  nginx_config_path: null,
  static_dir: null,
  backend_url: "",
  enabled: true,
  ssl_enabled: false,
  ssl_cert_path: null,
  ssl_key_path: null,
  preserve_host: true,
  custom_nginx_config: null,
};

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
  const [formData, setFormData] = useState<ConnectionCreate>(DEFAULT_FORM);
  const [domainsInput, setDomainsInput] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const nginxConfigInputRef = useRef<HTMLInputElement | null>(null);
  const setNginxConfigRef = useCallback((el: HTMLInputElement | null) => {
    nginxConfigInputRef.current = el;
    if (el) {
      el.setAttribute("webkitdirectory", "");
      el.setAttribute("directory", "");
    }
  }, []);

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
    setFormData(DEFAULT_FORM);
    setDomainsInput("");
    setEditingId(null);
    setShowForm(false);
    if (fileInputRef.current) fileInputRef.current.value = "";
    if (nginxConfigInputRef.current) nginxConfigInputRef.current.value = "";
  }

  function handleEdit(conn: Connection) {
    setEditingId(conn.id);
    setFormData({
      name: conn.name,
      domains: conn.domains,
      source_type: conn.source_type,
      nginx_config_path: conn.nginx_config_path,
      static_dir: conn.static_dir,
      backend_url: conn.backend_url,
      enabled: conn.enabled,
      ssl_enabled: conn.ssl_enabled,
      ssl_cert_path: conn.ssl_cert_path,
      ssl_key_path: conn.ssl_key_path,
      preserve_host: conn.preserve_host,
      custom_nginx_config: conn.custom_nginx_config,
    });
    setDomainsInput(conn.domains.join(", "));
    setShowForm(true);
  }

  function parseDomains(text: string): string[] {
    return text
      .split(/[,\s]+/)
      .map((d) => d.trim())
      .filter(Boolean);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const payload: ConnectionCreate = {
        ...formData,
        domains: parseDomains(domainsInput),
      };
      if (editingId !== null) {
        await api.updateConnection(editingId, payload);
        showToast("Connection updated successfully", "success");
      } else {
        await api.createConnection(payload);
        showToast("Connection created successfully", "success");
      }
      resetForm();
      loadConnections();
    } catch (err: any) {
      showToast(err?.message || "Failed to save connection", "error");
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

  const sourceType = formData.source_type ?? "static_generate";

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
              data-testid={`connection-card-${conn.id}`}
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
                  <strong>Source</strong>
                  <span className="badge badge-primary">
                    {conn.source_type}
                  </span>
                </div>
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

                {conn.source_type === "nginx_config" && conn.nginx_config_path && (
                  <div className="detail-row">
                    <strong>Config</strong>
                    <code className="codeblock">{conn.nginx_config_path}</code>
                  </div>
                )}
                {conn.source_type === "static_generate" && conn.static_dir && (
                  <div className="detail-row">
                    <strong>Static Dir</strong>
                    <code className="codeblock">{conn.static_dir}</code>
                  </div>
                )}
                {conn.source_type === "container" && conn.backend_url && (
                  <div className="detail-row">
                    <strong>Backend</strong>
                    <code className="codeblock">{conn.backend_url}</code>
                  </div>
                )}

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
              <div className="form-group">
                <label>Connection type *</label>
                <div
                  role="tablist"
                  style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}
                >
                  {SOURCE_TYPES.map((opt) => {
                    const active = sourceType === opt.value;
                    return (
                      <button
                        key={opt.value}
                        type="button"
                        role="tab"
                        aria-selected={active}
                        data-testid={`source-type-${opt.value}`}
                        className={`btn btn-sm ${active ? "btn-primary" : "btn-outline"}`}
                        onClick={() => updateFormField("source_type", opt.value)}
                      >
                        {opt.label}
                      </button>
                    );
                  })}
                </div>
                <small>
                  {SOURCE_TYPES.find((o) => o.value === sourceType)?.hint}
                </small>
              </div>

              <div className="form-group">
                <label>Name *</label>
                <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                  <input
                    type="text"
                    data-testid="conn-name"
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
                <label>
                  Domains
                  {sourceType === "static_generate" || sourceType === "container"
                    ? " *"
                    : ""}
                </label>
                <input
                  type="text"
                  data-testid="conn-domains"
                  value={domainsInput}
                  onChange={(e) => setDomainsInput(e.target.value)}
                  placeholder="example.com, www.example.com"
                />
                <small>
                  {sourceType === "nginx_config"
                    ? <>Auto-populated from <code>server_name</code> in the uploaded nginx.conf. Leave empty or edit after upload.</>
                    : "Comma- or space-separated."}
                </small>
              </div>

              {sourceType === "nginx_config" && (
                <div className="form-group">
                  <label>Nginx config folder *</label>
                  <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={() => nginxConfigInputRef.current?.click()}
                      title="Select a folder containing nginx.conf and related files"
                    >
                      Select config folder
                    </button>
                    {formData.nginx_config_path && (
                      <code className="codeblock" style={{ fontSize: "12px" }}>
                        {formData.nginx_config_path}
                      </code>
                    )}
                    <input
                      type="file"
                      ref={setNginxConfigRef}
                      style={{ display: "none" }}
                      multiple
                      onChange={async (e) => {
                        const files = e.target.files;
                        if (!files || files.length === 0) return;
                        try {
                          const result = await api.uploadNginxConfig(files);
                          updateFormField("nginx_config_path", result.path);
                          showToast(
                            `Uploaded ${files.length} file(s) from folder → ${result.filename}`,
                            "success"
                          );
                          // Auto-fill domains & backend_url from parsed nginx.conf
                          try {
                            const parsed = await api.parseNginxConfig(result.path);
                            if (parsed.domains.length > 0) {
                              setDomainsInput(parsed.domains.join(", "));
                              updateFormField("domains", parsed.domains);
                            }
                            if (parsed.backend_url && !formData.backend_url) {
                              updateFormField("backend_url", parsed.backend_url);
                            }
                          } catch {
                            // parse failure is non-fatal — user can fill manually
                          }
                        } catch (err: any) {
                          const msg =
                            typeof err.message === "string"
                              ? err.message
                              : JSON.stringify(err.message || err);
                          showToast(`Upload failed: ${msg}`, "error");
                        }
                        e.target.value = "";
                      }}
                    />
                  </div>
                  <small>
                    Select the <strong>folder</strong> containing <code>nginx.conf</code>.
                    All files (locations, includes, index.html, …) are uploaded together.
                    Domains and backend URL are parsed automatically.
                  </small>
                </div>
              )}

              {sourceType === "static_generate" && (
                <div className="form-group">
                  <label>Path to static directory or index.html *</label>
                  <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                    <input
                      type="text"
                      data-testid="conn-static-dir"
                      value={formData.static_dir || ""}
                      onChange={(e) =>
                        updateFormField("static_dir", e.target.value || null)
                      }
                      placeholder="examples  or  /app/site-templates/mysite"
                      style={{ flex: 1, minWidth: "200px" }}
                      required
                    />
                    <button
                      type="button"
                      className="btn btn-outline btn-sm"
                      onClick={() => fileInputRef.current?.click()}
                      title="Upload an index.html"
                    >
                      Upload index.html
                    </button>
                    <input
                      type="file"
                      ref={fileInputRef}
                      style={{ display: "none" }}
                      accept=".html,.htm"
                      onChange={async (e) => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        try {
                          const result = await api.uploadStaticFile(file);
                          updateFormField("static_dir", result.path);
                          showToast(
                            `Uploaded ${result.filename} → ${result.path}`,
                            "success"
                          );
                        } catch (err: any) {
                          showToast(
                            `Upload failed: ${err.message || "Unknown error"}`,
                            "error"
                          );
                        }
                        e.target.value = "";
                      }}
                    />
                  </div>
                  <small>
                    Backend-accessible path. Relative names resolve under{" "}
                    <code>/app/site-templates/</code>. Pointing to an{" "}
                    <code>index.html</code> uses its parent directory.
                  </small>
                </div>
              )}

              {sourceType === "container" && (
                <div className="form-group">
                  <label>Backend host:port *</label>
                  <input
                    type="text"
                    data-testid="conn-backend-url"
                    value={formData.backend_url || ""}
                    onChange={(e) =>
                      updateFormField("backend_url", e.target.value)
                    }
                    placeholder="myservice:8080  or  http://service.ns.svc:80"
                    required
                  />
                  <small>
                    Container name + port (docker compose default network) or
                    k8s service DNS. <code>http://</code> is added automatically
                    if omitted.
                  </small>
                </div>
              )}

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
                  data-testid="conn-submit"
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
