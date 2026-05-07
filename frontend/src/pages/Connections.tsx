import { useState, useEffect, useRef } from "react";
import {
  api,
  Connection,
  ConnectionCreate,
  ConnectionUpdate,
  CertificateStatus,
} from "../api/client";
import {
  Plus,
  Edit2,
  Trash2,
  RefreshCw,
  X,
  Shield,
  CheckCircle,
  XCircle,
} from "lucide-react";

export default function Connections() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [generatingCert, setGeneratingCert] = useState(false);
  const [generatingCertId, setGeneratingCertId] = useState<number | null>(null);
  const [certStatuses, setCertStatuses] = useState<
    Record<number, CertificateStatus>
  >({});
  const [toast, setToast] = useState<{
    message: string;
    type: "success" | "error" | "info";
  } | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [formData, setFormData] = useState<ConnectionCreate>({
    name: "",
    domains: [],
    backend_url: "",
    enabled: true,
    ssl_enabled: false,
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
      const statuses: Record<number, CertificateStatus> = {};
      await Promise.all(
        data
          .filter((c) => c.ssl_enabled)
          .map(async (c) => {
            try {
              const status = await api.getCertificateStatus(c.id);
              statuses[c.id] = status;
            } catch {
              // ignore
            }
          })
      );
      setCertStatuses(statuses);
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
      backend_url: "",
      enabled: true,
      ssl_enabled: false,
      ssl_cert_path: null,
      ssl_key_path: null,
      preserve_host: true,
      custom_nginx_config: null,
    });
    setEditingId(null);
    setShowForm(false);
    setCertStatuses({});
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }

  function handleEdit(conn: Connection) {
    setEditingId(conn.id);
    setFormData({
      name: conn.name,
      domains: conn.domains,
      backend_url: conn.backend_url,
      enabled: conn.enabled,
      ssl_enabled: conn.ssl_enabled,
      ssl_cert_path: conn.ssl_cert_path,
      ssl_key_path: conn.ssl_key_path,
      preserve_host: conn.preserve_host,
      custom_nginx_config: conn.custom_nginx_config,
    });
    setShowForm(true);
    loadCertificateStatus(conn.id);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      if (editingId !== null) {
        await api.updateConnection(editingId, formData);
        showToast("Connection updated successfully", "success");
        resetForm();
        loadConnections();
      } else {
        const newConnection = await api.createConnection(formData);
        showToast("Connection created successfully", "success");
        if (formData.ssl_enabled) {
          setEditingId(newConnection.id);
          loadCertificateStatus(newConnection.id);
        } else {
          resetForm();
        }
        loadConnections();
      }
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

  async function loadCertificateStatus(connectionId: number) {
    try {
      const status = await api.getCertificateStatus(connectionId);
      setCertStatuses((prev) => ({ ...prev, [connectionId]: status }));
      return status;
    } catch {
      setCertStatuses((prev) => {
        const next = { ...prev };
        delete next[connectionId];
        return next;
      });
      return null;
    }
  }

  async function handleGenerateCertificate() {
    if (editingId === null) return;
    setGeneratingCert(true);
    try {
      const result = await api.requestCertificate(editingId, formData.domains);
      if (result.success) {
        showToast(result.message || "Certificate request initiated", "success");
        const certPath = `/etc/angie/http.d/${editingId}.crt`;
        const keyPath = `/etc/angie/http.d/${editingId}.key`;
        updateFormField("ssl_cert_path", certPath);
        updateFormField("ssl_key_path", keyPath);
        setTimeout(() => loadCertificateStatus(editingId), 2000);
      } else {
        showToast(`Certificate request failed: ${result.message}`, "error");
      }
    } catch (err: any) {
      showToast(`Certificate request error: ${err.message}`, "error");
    } finally {
      setGeneratingCert(false);
    }
  }

  async function handleRegenerateCertificate() {
    if (editingId === null) return;
    if (
      !confirm(
        "Regenerate certificate? This will invalidate the current certificate."
      )
    )
      return;
    setGeneratingCert(true);
    try {
      const result = await api.regenerateCertificate(editingId);
      if (result.success) {
        showToast(
          result.message || "Certificate regeneration initiated",
          "success"
        );
        setTimeout(() => loadCertificateStatus(editingId), 2000);
      } else {
        showToast(`Regeneration failed: ${result.message}`, "error");
      }
    } catch (err: any) {
      showToast(`Regeneration error: ${err.message}`, "error");
    } finally {
      setGeneratingCert(false);
    }
  }

  async function handleQuickGenerate(conn: Connection) {
    if (!conn.ssl_enabled || !conn.domains.length) {
      showToast("SSL must be enabled and domains must be set", "error");
      return;
    }
    setGeneratingCertId(conn.id);
    try {
      const result = await api.requestCertificate(conn.id, conn.domains);
      if (result.success) {
        showToast(
          result.message || "Certificate requested successfully",
          "success"
        );
        setTimeout(() => loadConnections(), 3000);
      } else {
        showToast(`Failed: ${result.message}`, "error");
      }
    } catch (err: any) {
      showToast(`Error: ${err.message}`, "error");
    } finally {
      setGeneratingCertId(null);
    }
  }

  function updateFormField<K extends keyof ConnectionCreate>(
    key: K,
    value: ConnectionCreate[K]
  ) {
    setFormData((prev) => ({ ...prev, [key]: value }));
  }

  function handleFileChange(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      updateFormField("custom_nginx_config", content);
      event.target.value = "";
    };
    reader.onerror = () => {
      showToast("Failed to read file", "error");
    };
    reader.readAsText(file);
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
          <h1>Connections / Proxy</h1>
          <p>Manage site connections and reverse proxy rules for the WAF</p>
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
                  <span
                    className={`badge ${
                      conn.enabled ? "badge-success" : "badge-secondary"
                    }`}
                  >
                    {conn.enabled ? "Enabled" : "Disabled"}
                  </span>
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

                <div className="detail-row">
                  <strong>Backend</strong>
                  <code className="codeblock">{conn.backend_url}</code>
                </div>

                {conn.ssl_enabled && (
                  <div className="detail-row">
                    <strong>SSL</strong>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                        flexWrap: "wrap",
                      }}
                    >
                      <span className="badge badge-primary">Enabled</span>
                      {certStatuses[conn.id] ? (
                        certStatuses[conn.id].certificate_exists &&
                        certStatuses[conn.id].key_exists ? (
                          <span
                            className="badge badge-success"
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "4px",
                            }}
                          >
                            <Shield size={12} /> Certificate Ready
                          </span>
                        ) : (
                          <span
                            className="badge badge-warning"
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "4px",
                            }}
                          >
                            <XCircle size={12} /> Pending
                          </span>
                        )
                      ) : (
                        <span className="badge badge-secondary">
                          Not Checked
                        </span>
                      )}
                      <button
                        type="button"
                        className="btn btn-outline btn-sm"
                        onClick={() => handleQuickGenerate(conn)}
                        disabled={generatingCertId === conn.id}
                      >
                        {generatingCertId === conn.id
                          ? "Generating…"
                          : certStatuses[conn.id]?.certificate_exists
                          ? "Regenerate"
                          : "Generate"}
                      </button>
                      {conn.ssl_cert_path && (
                        <span className="text-muted" style={{ fontSize: "11px" }}>
                          {conn.ssl_cert_path}
                        </span>
                      )}
                    </div>
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

      {/* ── Modal ── */}
      {showForm && (
        <div
          className="modal-overlay"
          onClick={(e) => e.target === e.currentTarget && resetForm()}
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
                <label>Name *</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => updateFormField("name", e.target.value)}
                  placeholder="My Web App"
                  required
                />
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
                <label>Backend URL *</label>
                <input
                  type="text"
                  value={formData.backend_url}
                  onChange={(e) =>
                    updateFormField("backend_url", e.target.value)
                  }
                  placeholder="http://backend:3000"
                  required
                />
              </div>

              <div className="form-group">
                <label
                  className="checkbox-row"
                  onClick={() =>
                    updateFormField("enabled", !formData.enabled)
                  }
                >
                  <input
                    type="checkbox"
                    checked={formData.enabled}
                    onChange={() => {}}
                  />
                  <span>Enabled</span>
                </label>
                <label
                  className="checkbox-row"
                  onClick={() =>
                    updateFormField("ssl_enabled", !formData.ssl_enabled)
                  }
                >
                  <input
                    type="checkbox"
                    checked={formData.ssl_enabled}
                    onChange={() => {}}
                  />
                  <span>Enable SSL / TLS</span>
                </label>
                <label
                  className="checkbox-row"
                  onClick={() =>
                    updateFormField("preserve_host", !formData.preserve_host)
                  }
                >
                  <input
                    type="checkbox"
                    checked={formData.preserve_host}
                    onChange={() => {}}
                  />
                  <span>Preserve Host Header</span>
                </label>
              </div>

              {formData.ssl_enabled && (
                <div className="form-group">
                  <label>SSL Certificate Path</label>
                  <input
                    type="text"
                    value={formData.ssl_cert_path || ""}
                    onChange={(e) =>
                      updateFormField("ssl_cert_path", e.target.value || null)
                    }
                    placeholder="/etc/angie/http.d/cert.pem"
                  />
                </div>
              )}

              {formData.ssl_enabled && (
                <div className="form-group">
                  <label>SSL Key Path</label>
                  <input
                    type="text"
                    value={formData.ssl_key_path || ""}
                    onChange={(e) =>
                      updateFormField("ssl_key_path", e.target.value || null)
                    }
                    placeholder="/etc/angie/http.d/key.pem"
                  />
                </div>
              )}

              {formData.ssl_enabled && editingId && (
                <div className="form-group">
                  <label>SSL Certificate Management</label>
                  <div
                    style={{
                      display: "flex",
                      gap: "10px",
                      flexWrap: "wrap",
                      alignItems: "center",
                    }}
                  >
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={handleGenerateCertificate}
                      disabled={generatingCert}
                    >
                      <Shield size={16} />
                      {generatingCert ? "Requesting…" : "Generate Certificate"}
                    </button>
                    {editingId && certStatuses[editingId] && (
                      <>
                        {certStatuses[editingId].certificate_exists &&
                        certStatuses[editingId].key_exists ? (
                          <span
                            className="badge badge-success"
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "4px",
                            }}
                          >
                            <CheckCircle size={14} />
                            Certificate Ready
                          </span>
                        ) : (
                          <span
                            className="badge badge-warning"
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "4px",
                            }}
                          >
                            <XCircle size={14} />
                            Pending Generation
                          </span>
                        )}
                        <button
                          type="button"
                          className="btn btn-outline btn-sm"
                          onClick={handleRegenerateCertificate}
                          disabled={generatingCert}
                        >
                          Regenerate
                        </button>
                      </>
                    )}
                  </div>
                  <small>
                    Generates a self-signed certificate for testing. Certificate
                    will be saved to /etc/angie/http.d/{editingId}.crt and .key
                  </small>
                </div>
              )}

              <div className="form-group">
                <label>Custom Nginx Configuration (optional)</label>
                <textarea
                  value={formData.custom_nginx_config || ""}
                  onChange={(e) =>
                    updateFormField(
                      "custom_nginx_config",
                      e.target.value || null
                    )
                  }
                  placeholder="proxy_buffering off;&#10;proxy_cache off;"
                  rows={4}
                />
                <div style={{ marginTop: "8px" }}>
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    style={{ display: "none" }}
                    accept=".html,.htm,.conf,.txt,.nginx,.cfg"
                  />
                  <button
                    type="button"
                    className="btn btn-outline btn-sm"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    Upload config file
                  </button>
                </div>
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
