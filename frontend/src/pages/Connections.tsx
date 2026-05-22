import { useState, useEffect, useRef, useCallback } from "react";
import {
  api,
  Connection,
  ConnectionCreate,
  SourceType,
} from "../api/client";
import { Plus, Edit2, Trash2, RefreshCw, X, Shield } from "lucide-react";
import { useSettings } from "../context/SettingsContext";

const SOURCE_TYPES: { value: SourceType; labelKey: string; hintKey: string }[] = [
  {
    value: "nginx_config",
    labelKey: "connections.sourceType.nginx_config.label",
    hintKey: "connections.sourceType.nginx_config.hint",
  },
  {
    value: "static_generate",
    labelKey: "connections.sourceType.static_generate.label",
    hintKey: "connections.sourceType.static_generate.hint",
  },
  {
    value: "container",
    labelKey: "connections.sourceType.container.label",
    hintKey: "connections.sourceType.container.hint",
  },
  {
    value: "docker_compose",
    labelKey: "connections.sourceType.docker_compose.label",
    hintKey: "connections.sourceType.docker_compose.hint",
  },
];

const DEFAULT_COMPOSE_YAML = `services:
  app:
    image: nginx:alpine
    expose:
      - "80"
`;

const DEFAULT_FORM: ConnectionCreate = {
  name: "",
  domains: [],
  source_type: "static_generate",
  nginx_config_path: null,
  static_dir: null,
  backend_url: "",
  compose_yaml: null,
  compose_service: null,
  compose_port: null,
  http_versions: "h1,h2,h3",
  compression_algo: "auto",
  enabled: true,
  ssl_enabled: false,
  ssl_cert_path: null,
  ssl_key_path: null,
  preserve_host: true,
  custom_nginx_config: null,
};

export default function Connections() {
  const { t } = useSettings();
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
  const staticDirInputRef = useRef<HTMLInputElement | null>(null);
  const setStaticDirRef = useCallback((el: HTMLInputElement | null) => {
    staticDirInputRef.current = el;
    if (el) {
      el.setAttribute("webkitdirectory", "");
      el.setAttribute("directory", "");
    }
  }, []);

  useEffect(() => {
    loadConnections();
  }, []);

  useEffect(() => {
    if (!showForm) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") resetForm();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [showForm]);

  async function loadConnections() {
    setLoading(true);
    try {
      const data = await api.getConnections();
      setConnections(data);
    } catch {
      showToast(t("connections.toast.loadFailed"), "error");
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
    if (staticDirInputRef.current) staticDirInputRef.current.value = "";
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
      compose_yaml: conn.compose_yaml,
      compose_service: conn.compose_service,
      compose_port: conn.compose_port,
      http_versions: conn.http_versions || "h1,h2,h3",
      compression_algo: conn.compression_algo || "auto",
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
        showToast(t("connections.toast.updated"), "success");
      } else {
        await api.createConnection(payload);
        showToast(t("connections.toast.created"), "success");
      }
      resetForm();
      loadConnections();
    } catch (err: any) {
      showToast(err?.message || t("connections.toast.saveFailed"), "error");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: number) {
    if (!confirm(t("connections.confirmDelete"))) return;
    try {
      await api.deleteConnection(id);
      showToast(t("connections.toast.deleted"), "success");
      loadConnections();
    } catch {
      showToast(t("connections.toast.deleteFailed"), "error");
    }
  }

  async function handleToggleEnabled(conn: Connection) {
    try {
      await api.updateConnection(conn.id, { enabled: !conn.enabled });
      loadConnections();
      showToast(
        conn.enabled ? t("connections.toast.disabled") : t("connections.toast.enabled"),
        "success"
      );
    } catch {
      showToast(t("connections.toast.toggleFailed"), "error");
    }
  }

  async function handleReload() {
    setReloading(true);
    try {
      const result = await api.reloadAngie();
      if (result.success) {
        showToast(t("connections.toast.reloaded"), "success");
      } else {
        showToast(t("connections.toast.reloadFailedMsg", { msg: result.message }), "error");
      }
    } catch {
      showToast(t("connections.toast.reloadFailed"), "error");
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
        {t("connections.loading")}
      </div>
    );
  }

  const sourceType = formData.source_type ?? "static_generate";

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>{t("connections.title")}</h1>
          <p>{t("connections.subtitle")}</p>
        </div>
        <div className="header-actions">
          <button
            className="btn btn-success"
            onClick={handleReload}
            disabled={reloading}
          >
            <RefreshCw size={16} />
            {reloading ? t("connections.reloading") : t("connections.reload")}
          </button>
          <button
            className="btn btn-primary"
            onClick={() => setShowForm(true)}
          >
            <Plus size={16} />
            {t("connections.add")}
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
              {t("connections.empty")}
            </p>
            <p className="text-muted">
              {t("connections.emptyDesc")}
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
                    title={conn.enabled ? t("connections.clickToDisable") : t("connections.clickToEnable")}
                    style={{
                      padding: "4px 12px",
                      fontSize: "12px",
                      fontWeight: 600,
                      borderRadius: "var(--radius-sm)",
                    }}
                  >
                    {conn.enabled ? t("connections.on") : t("connections.off")}
                  </button>
                </div>
                <div style={{ display: "flex", gap: "4px" }}>
                  <button
                    className="btn-icon"
                    onClick={() => handleEdit(conn)}
                    title={t("connections.edit")}
                  >
                    <Edit2 size={15} />
                  </button>
                  <button
                    className="btn-icon danger"
                    onClick={() => handleDelete(conn.id)}
                    title={t("connections.delete")}
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>

              <div className="connection-details">
                <div className="detail-row">
                  <strong>{t("connections.detail.source")}</strong>
                  <span className="badge badge-primary">
                    {conn.source_type}
                  </span>
                </div>
                <div className="detail-row">
                  <strong>{t("connections.detail.domains")}</strong>
                  <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                    {conn.domains.length > 0 ? (
                      conn.domains.map((d) => (
                        <span key={d} className="badge badge-secondary">
                          {d}
                        </span>
                      ))
                    ) : (
                      <span className="text-muted">{t("connections.detail.catchAll")}</span>
                    )}
                  </div>
                </div>

                {conn.source_type === "nginx_config" && conn.nginx_config_path && (
                  <div className="detail-row">
                    <strong>{t("connections.detail.config")}</strong>
                    <code className="codeblock">{conn.nginx_config_path}</code>
                  </div>
                )}
                {conn.source_type === "static_generate" && conn.static_dir && (
                  <div className="detail-row">
                    <strong>{t("connections.detail.staticDir")}</strong>
                    <code className="codeblock">{conn.static_dir}</code>
                  </div>
                )}
                {conn.source_type === "container" && conn.backend_url && (
                  <div className="detail-row">
                    <strong>{t("connections.detail.backend")}</strong>
                    <code className="codeblock">{conn.backend_url}</code>
                  </div>
                )}
                {conn.source_type === "docker_compose" && (
                  <>
                    {conn.compose_service && (
                      <div className="detail-row">
                        <strong>{t("connections.detail.service")}</strong>
                        <code className="codeblock">
                          {conn.compose_service}
                          {conn.compose_port ? `:${conn.compose_port}` : ""}
                        </code>
                      </div>
                    )}
                    {conn.backend_url && (
                      <div className="detail-row">
                        <strong>{t("connections.detail.backend")}</strong>
                        <code className="codeblock">{conn.backend_url}</code>
                      </div>
                    )}
                  </>
                )}

                <div className="detail-row">
                  <strong>{t("connections.detail.updated")}</strong>
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
              <h2>{editingId ? t("connections.modal.editTitle") : t("connections.modal.newTitle")}</h2>
              <button className="btn-icon" onClick={resetForm}>
                <X size={20} />
              </button>
            </div>

            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>{t("connections.field.type")}</label>
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
                        {t(opt.labelKey)}
                      </button>
                    );
                  })}
                </div>
                <small>
                  {(() => {
                    const k = SOURCE_TYPES.find((o) => o.value === sourceType)?.hintKey;
                    return k ? t(k) : null;
                  })()}
                </small>
              </div>

              <div className="form-group">
                <label>{t("connections.field.name")}</label>
                <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                  <input
                    type="text"
                    data-testid="conn-name"
                    value={formData.name}
                    onChange={(e) => updateFormField("name", e.target.value)}
                    placeholder={t("connections.field.namePlaceholder")}
                    required
                    style={{ flex: 1 }}
                  />
                  <button
                    type="button"
                    className={`toggle-btn ${formData.enabled ? "active" : ""}`}
                    onClick={() => updateFormField("enabled", !formData.enabled)}
                    title={formData.enabled ? t("connections.field.enabledTitle") : t("connections.field.disabledTitle")}
                  >
                    <span className="toggle-track">
                      <span className="toggle-thumb" />
                    </span>
                    <span className="toggle-label">
                      {formData.enabled ? t("connections.on") : t("connections.off")}
                    </span>
                  </button>
                </div>
              </div>

              <div className="form-group">
                <label>
                  {t("connections.field.domains")}
                  {sourceType === "static_generate" || sourceType === "container"
                    ? " *"
                    : ""}
                </label>
                <input
                  type="text"
                  data-testid="conn-domains"
                  value={domainsInput}
                  onChange={(e) => setDomainsInput(e.target.value)}
                  placeholder={t("connections.field.domainsPlaceholder")}
                />
                <small>
                  {sourceType === "nginx_config"
                    ? <>{t("connections.help.domainsNginx.before")}<code>server_name</code>{t("connections.help.domainsNginx.after")}</>
                    : t("connections.help.domainsDefault")}
                </small>
              </div>

              {sourceType === "nginx_config" && (
                <div className="form-group">
                  <label>{t("connections.field.nginxFolder")}</label>
                  <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
                    <input
                      type="text"
                      data-testid="conn-nginx-config-path"
                      value={formData.nginx_config_path || ""}
                      onChange={(e) =>
                        updateFormField("nginx_config_path", e.target.value || null)
                      }
                      placeholder="/app/site-templates/.../nginx.conf"
                      style={{ flex: 1, minWidth: "240px" }}
                    />
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={() => nginxConfigInputRef.current?.click()}
                      title={t("connections.title.selectConfigFolder")}
                    >
                      {t("connections.btn.selectConfigFolder")}
                    </button>
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
                            t("connections.toast.uploadedFolder", { count: files.length, filename: result.filename }),
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
                          showToast(t("connections.toast.uploadFailedMsg", { msg }), "error");
                        }
                        e.target.value = "";
                      }}
                    />
                  </div>
                  <small>
                    {t("connections.help.nginxConfig.part1")}<strong>{t("connections.help.nginxConfig.folder")}</strong>{t("connections.help.nginxConfig.part2")}<code>{t("connections.help.nginxConfig.file")}</code>{t("connections.help.nginxConfig.part3")}
                  </small>
                </div>
              )}

              {sourceType === "static_generate" && (
                <div className="form-group">
                  <label>{t("connections.field.staticPath")}</label>
                  <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                    <input
                      type="text"
                      data-testid="conn-static-dir"
                      value={formData.static_dir || ""}
                      onChange={(e) =>
                        updateFormField("static_dir", e.target.value || null)
                      }
                      placeholder={t("connections.field.staticPlaceholder")}
                      style={{ flex: 1, minWidth: "200px" }}
                      required
                    />
                    <button
                      type="button"
                      className="btn btn-outline btn-sm"
                      onClick={() => fileInputRef.current?.click()}
                      title={t("connections.title.uploadIndex")}
                    >
                      {t("connections.btn.uploadIndex")}
                    </button>
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      onClick={() => staticDirInputRef.current?.click()}
                      title={t("connections.title.uploadFolder")}
                    >
                      {t("connections.btn.uploadFolder")}
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
                            t("connections.toast.uploadedFile", { filename: result.filename, path: result.path }),
                            "success"
                          );
                        } catch (err: any) {
                          showToast(
                            err?.message
                              ? t("connections.toast.uploadFailedMsg", { msg: err.message })
                              : t("connections.toast.uploadFailedUnknown"),
                            "error"
                          );
                        }
                        e.target.value = "";
                      }}
                    />
                    <input
                      type="file"
                      ref={setStaticDirRef}
                      style={{ display: "none" }}
                      multiple
                      onChange={async (e) => {
                        const files = e.target.files;
                        if (!files || files.length === 0) return;
                        try {
                          const result = await api.uploadStaticDir(
                            files,
                            editingId ?? undefined,
                          );
                          if (editingId === null) {
                            // Create flow: temp staging — surface the path
                            // so the create payload references it.
                            updateFormField("static_dir", result.path);
                            showToast(
                              t("connections.toast.stagedFiles", { count: files.length, path: result.path }),
                              "success",
                            );
                          } else {
                            // Edit flow: written directly into conn_<id>/site.
                            showToast(
                              t("connections.toast.uploadedSiteFiles", { count: result.files ?? files.length }),
                              "success",
                            );
                          }
                        } catch (err: any) {
                          const msg =
                            typeof err.message === "string"
                              ? err.message
                              : JSON.stringify(err.message || err);
                          showToast(t("connections.toast.uploadFailedMsg", { msg }), "error");
                        }
                        e.target.value = "";
                      }}
                    />
                  </div>
                  <small>
                    {t("connections.help.static.part1")}<code>{t("connections.help.static.path")}</code>{t("connections.help.static.part2")}<code>{t("connections.help.static.indexFile")}</code>{t("connections.help.static.part3")}<strong>{t("connections.help.static.uploadFolderStrong")}</strong>{t("connections.help.static.part4")}<code>{t("connections.help.static.distPath")}</code>{t("connections.help.static.part5")}<code>{t("connections.help.static.blog")}</code>{t("connections.help.static.part6")}<code>{t("connections.help.static.about")}</code>{t("connections.help.static.part7")}
                  </small>
                </div>
              )}

              {sourceType === "container" && (
                <div className="form-group">
                  <label>{t("connections.field.backendHostPort")}</label>
                  <input
                    type="text"
                    data-testid="conn-backend-url"
                    value={formData.backend_url || ""}
                    onChange={(e) =>
                      updateFormField("backend_url", e.target.value)
                    }
                    placeholder={t("connections.field.backendPlaceholder")}
                    required
                  />
                  <small>
                    {t("connections.help.backend.part1")}<code>{t("connections.help.backend.code")}</code>{t("connections.help.backend.part2")}
                  </small>
                </div>
              )}

              {sourceType === "docker_compose" && (
                <>
                  <div className="form-group">
                    <label>{t("connections.field.composeService")}</label>
                    <input
                      type="text"
                      data-testid="conn-compose-service"
                      value={formData.compose_service || ""}
                      onChange={(e) =>
                        updateFormField(
                          "compose_service",
                          e.target.value || null
                        )
                      }
                      placeholder={t("connections.field.composeServicePlaceholder")}
                      required
                    />
                    <small>
                      {t("connections.help.composeService.part1")}<code>{t("connections.help.composeService.code")}</code>{t("connections.help.composeService.part2")}
                    </small>
                  </div>

                  <div className="form-group">
                    <label>{t("connections.field.composePort")}</label>
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      data-testid="conn-compose-port"
                      value={formData.compose_port ?? ""}
                      onChange={(e) => {
                        const v = e.target.value
                          ? parseInt(e.target.value, 10)
                          : null;
                        updateFormField(
                          "compose_port",
                          Number.isFinite(v as number) ? v : null
                        );
                      }}
                      placeholder="80"
                    />
                    <small>
                      {t("connections.help.composePort.part1")}<code>{t("connections.help.composePort.code1")}</code>{t("connections.help.composePort.part2")}<code>{t("connections.help.composePort.code2")}</code>{t("connections.help.composePort.part3")}
                    </small>
                  </div>

                  <div className="form-group">
                    <label>{t("connections.field.composeYaml")}</label>
                    <textarea
                      data-testid="conn-compose-yaml"
                      value={formData.compose_yaml || ""}
                      onChange={(e) =>
                        updateFormField(
                          "compose_yaml",
                          e.target.value || null
                        )
                      }
                      placeholder={DEFAULT_COMPOSE_YAML}
                      rows={12}
                      required
                      style={{
                        fontFamily: "monospace",
                        fontSize: "12px",
                        width: "100%",
                        minHeight: "220px",
                      }}
                    />
                    <small>
                      {t("connections.help.composeYaml.part1")}<code>{t("connections.help.composeYaml.code")}</code>{t("connections.help.composeYaml.part2")}<code>{t("connections.help.composeYaml.cmd")}</code>{t("connections.help.composeYaml.part3")}
                    </small>
                  </div>
                </>
              )}

              <div className="modal-actions">
                <button
                  type="button"
                  className="btn btn-outline"
                  onClick={resetForm}
                >
                  {t("general.cancel")}
                </button>
                <button
                  type="submit"
                  data-testid="conn-submit"
                  className="btn btn-primary"
                  disabled={saving}
                >
                  {saving
                    ? t("general.saving")
                    : editingId
                    ? t("connections.btn.update")
                    : t("connections.btn.create")}
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
