import { useState, useEffect } from "react";
import {
  api,
  ModSecuritySettings,
  AngieSettings,
  ModuleInfo,
} from "../api/client";
import { Save, RefreshCw } from "lucide-react";

type TabType = "modsecurity" | "angie";

const COUNTRY_OPTIONS = [
  "RU", "CN", "US", "BR", "DE", "FR", "GB", "IN", "JP", "KR",
  "PL", "QA", "UA", "NL", "IR", "KP", "SY", "IQ", "AF", "PK",
];

export default function ConfigEditor() {
  const [activeTab, setActiveTab] = useState<TabType>("modsecurity");
  const [modsec, setModsec] = useState<ModSecuritySettings | null>(null);
  const [angie, setAngie] = useState<AngieSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{
    message: string;
    type: "success" | "error" | "info";
  } | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    try {
      const [m, a] = await Promise.all([
        api.getModsecSettings(),
        api.getAngieSettings(),
      ]);
      setModsec(m);
      setAngie(a);
    } catch (err) {
      showToast("Failed to load settings", "error");
    } finally {
      setLoading(false);
    }
  }

  function showToast(message: string, type: "success" | "error" | "info") {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  }

  async function handleSaveModsec() {
    if (!modsec) return;
    setSaving(true);
    try {
      await api.updateModsecSettings(modsec);
      showToast("ModSecurity settings saved", "success");
    } catch (err) {
      showToast("Failed to save ModSecurity settings", "error");
    } finally {
      setSaving(false);
    }
  }

  async function handleSaveAngie() {
    if (!angie) return;
    setSaving(true);
    try {
      await api.updateAngieSettings(angie);
      showToast("Angie settings saved", "success");
    } catch (err) {
      showToast("Failed to save Angie settings", "error");
    } finally {
      setSaving(false);
    }
  }

  async function handleReload(type: "modsec" | "angie") {
    try {
      const result =
        type === "modsec" ? await api.reloadModsec() : await api.reloadAngie();
      if (result.success) {
        showToast("Reloaded successfully", "success");
      } else {
        showToast(`Reload failed: ${result.message}`, "error");
      }
    } catch {
      showToast("Reload request failed", "error");
    }
  }

  function updateModsecField<K extends keyof ModSecuritySettings>(
    key: K,
    value: ModSecuritySettings[K]
  ) {
    setModsec((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  function updateAngieField<K extends keyof AngieSettings>(
    key: K,
    value: AngieSettings[K]
  ) {
    setAngie((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  function toggleModule(modName: string) {
    if (!angie) return;
    const modules = angie.modules.map((m) =>
      m.name === modName ? { ...m, loaded: !m.loaded } : m
    );
    updateAngieField("modules", modules);
  }

  function toggleCountry(code: string) {
    if (!angie) return;
    const countries = angie.denied_countries.includes(code)
      ? angie.denied_countries.filter((c) => c !== code)
      : [...angie.denied_countries, code];
    updateAngieField("denied_countries", countries);
  }

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
        Loading settings...
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Configuration</h1>
          <p>Manage ModSecurity and Angie settings</p>
        </div>
      </div>

      <div className="tabs">
        <button
          className={`tab ${activeTab === "modsecurity" ? "active" : ""}`}
          onClick={() => setActiveTab("modsecurity")}
        >
          ModSecurity
        </button>
        <button
          className={`tab ${activeTab === "angie" ? "active" : ""}`}
          onClick={() => setActiveTab("angie")}
        >
          Angie
        </button>
      </div>

      {activeTab === "modsecurity" && modsec && (
        <ModSecurityTab
          settings={modsec}
          onChange={updateModsecField}
          onSave={handleSaveModsec}
          onReload={() => handleReload("modsec")}
          saving={saving}
        />
      )}

      {activeTab === "angie" && angie && (
        <AngieTab
          settings={angie}
          onChange={updateAngieField}
          onSave={handleSaveAngie}
          onReload={() => handleReload("angie")}
          onToggleModule={toggleModule}
          onToggleCountry={toggleCountry}
          saving={saving}
        />
      )}

      {toast && (
        <div className={`toast toast-${toast.type}`}>{toast.message}</div>
      )}
    </div>
  );
}

/* ─── ModSecurity Tab ─── */

function ModSecurityTab({
  settings,
  onChange,
  onSave,
  onReload,
  saving,
}: {
  settings: ModSecuritySettings;
  onChange: <K extends keyof ModSecuritySettings>(
    key: K,
    value: ModSecuritySettings[K]
  ) => void;
  onSave: () => void;
  onReload: () => void;
  saving: boolean;
}) {
  return (
    <div>
      <div className="card">
        <div className="card-header">
          <h3>Rule Engine</h3>
        </div>
        <div className="form-group">
          <label>SecRuleEngine</label>
          <select
            value={settings.rule_engine}
            onChange={(e) => onChange("rule_engine", e.target.value)}
          >
            <option value="On">On (Blocking)</option>
            <option value="Off">Off (Disabled)</option>
            <option value="DetectionOnly">DetectionOnly (Logging only)</option>
          </select>
        </div>
        <label
          className="checkbox-row"
          onClick={() =>
            onChange("status_engine", !settings.status_engine)
          }
        >
          <input
            type="checkbox"
            checked={settings.status_engine}
            readOnly
          />
          <span>SecStatusEngine — share version info</span>
        </label>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Request Body</h3>
        </div>
        <label
          className="checkbox-row"
          onClick={() =>
            onChange("request_body_access", !settings.request_body_access)
          }
        >
          <input
            type="checkbox"
            checked={settings.request_body_access}
            readOnly
          />
          <span>SecRequestBodyAccess — inspect request bodies</span>
        </label>
        <div className="form-group">
          <label>SecRequestBodyLimit (bytes)</label>
          <input
            type="number"
            value={settings.request_body_limit}
            onChange={(e) =>
              onChange("request_body_limit", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <label>SecRequestBodyNoFilesLimit (bytes)</label>
          <input
            type="number"
            value={settings.request_body_no_files_limit}
            onChange={(e) =>
              onChange("request_body_no_files_limit", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <label>SecRequestBodyLimitAction</label>
          <select
            value={settings.request_body_limit_action}
            onChange={(e) =>
              onChange("request_body_limit_action", e.target.value)
            }
          >
            <option value="Reject">Reject</option>
            <option value="ProcessPartial">ProcessPartial</option>
          </select>
        </div>
        <div className="form-group">
          <label>SecRequestBodyJsonDepthLimit</label>
          <input
            type="number"
            value={settings.request_body_json_depth_limit}
            onChange={(e) =>
              onChange(
                "request_body_json_depth_limit",
                Number(e.target.value)
              )
            }
          />
        </div>
        <div className="form-group">
          <label>SecArgumentsLimit</label>
          <input
            type="number"
            value={settings.arguments_limit}
            onChange={(e) =>
              onChange("arguments_limit", Number(e.target.value))
            }
          />
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Response Body</h3>
        </div>
        <label
          className="checkbox-row"
          onClick={() =>
            onChange(
              "response_body_access",
              !settings.response_body_access
            )
          }
        >
          <input
            type="checkbox"
            checked={settings.response_body_access}
            readOnly
          />
          <span>SecResponseBodyAccess — inspect response bodies</span>
        </label>
        <div className="form-group">
          <label>SecResponseBodyLimit (bytes)</label>
          <input
            type="number"
            value={settings.response_body_limit}
            onChange={(e) =>
              onChange("response_body_limit", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <label>SecResponseBodyLimitAction</label>
          <select
            value={settings.response_body_limit_action}
            onChange={(e) =>
              onChange("response_body_limit_action", e.target.value)
            }
          >
            <option value="ProcessPartial">ProcessPartial</option>
            <option value="Reject">Reject</option>
          </select>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Audit Log</h3>
        </div>
        <div className="form-group">
          <label>SecAuditEngine</label>
          <select
            value={settings.audit_engine}
            onChange={(e) => onChange("audit_engine", e.target.value)}
          >
            <option value="On">On</option>
            <option value="Off">Off</option>
            <option value="RelevantOnly">RelevantOnly</option>
          </select>
        </div>
        <div className="form-group">
          <label>SecAuditLogType</label>
          <select
            value={settings.audit_log_type}
            onChange={(e) => onChange("audit_log_type", e.target.value)}
          >
            <option value="Serial">Serial</option>
            <option value="Concurrent">Concurrent</option>
          </select>
        </div>
        <div className="form-group">
          <label>SecAuditLogFormat</label>
          <select
            value={settings.audit_log_format}
            onChange={(e) => onChange("audit_log_format", e.target.value)}
          >
            <option value="JSON">JSON</option>
            <option value="Native">Native</option>
          </select>
        </div>
        <div className="form-group">
          <label>SecAuditLogParts</label>
          <input
            type="text"
            value={settings.audit_log_parts}
            onChange={(e) => onChange("audit_log_parts", e.target.value)}
          />
        </div>
        <div className="form-group">
          <label>SecAuditLogRelevantStatus (regex)</label>
          <input
            type="text"
            value={settings.audit_log_relevant_status}
            onChange={(e) =>
              onChange("audit_log_relevant_status", e.target.value)
            }
          />
        </div>
        <div className="form-group">
          <label>SecAuditLog path</label>
          <input
            type="text"
            value={settings.audit_log_path}
            onChange={(e) => onChange("audit_log_path", e.target.value)}
          />
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>PCRE & Filesystem</h3>
        </div>
        <div className="form-group">
          <label>SecPcreMatchLimit</label>
          <input
            type="number"
            value={settings.pcre_match_limit}
            onChange={(e) =>
              onChange("pcre_match_limit", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <label>SecPcreMatchLimitRecursion</label>
          <input
            type="number"
            value={settings.pcre_match_limit_recursion}
            onChange={(e) =>
              onChange("pcre_match_limit_recursion", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <label>SecTmpDir</label>
          <input
            type="text"
            value={settings.tmp_dir}
            onChange={(e) => onChange("tmp_dir", e.target.value)}
          />
        </div>
        <div className="form-group">
          <label>SecDataDir</label>
          <input
            type="text"
            value={settings.data_dir}
            onChange={(e) => onChange("data_dir", e.target.value)}
          />
        </div>
      </div>

      <div className="actions-bar" style={{ marginTop: 16 }}>
        <button
          className="btn btn-primary"
          onClick={onSave}
          disabled={saving}
        >
          <Save size={16} />
          {saving ? "Saving..." : "Save ModSecurity Settings"}
        </button>
        <button className="btn btn-success" onClick={onReload}>
          <RefreshCw size={16} />
          Reload Angie
        </button>
      </div>
    </div>
  );
}

/* ─── Angie Tab ─── */

function AngieTab({
  settings,
  onChange,
  onSave,
  onReload,
  onToggleModule,
  onToggleCountry,
  saving,
}: {
  settings: AngieSettings;
  onChange: <K extends keyof AngieSettings>(
    key: K,
    value: AngieSettings[K]
  ) => void;
  onSave: () => void;
  onReload: () => void;
  onToggleModule: (name: string) => void;
  onToggleCountry: (code: string) => void;
  saving: boolean;
}) {
  const topModules = settings.modules.slice(0, 20);
  const restModules = settings.modules.slice(20);
  const [showAllModules, setShowAllModules] = useState(false);

  const visibleModules = showAllModules
    ? settings.modules
    : topModules;

  return (
    <div>
      <div className="card">
        <div className="card-header">
          <h3>Worker</h3>
        </div>
        <div className="form-group">
          <label>worker_processes</label>
          <select
            value={settings.worker_processes}
            onChange={(e) => onChange("worker_processes", e.target.value)}
          >
            <option value="auto">auto</option>
            <option value="1">1</option>
            <option value="2">2</option>
            <option value="4">4</option>
            <option value="8">8</option>
          </select>
        </div>
        <div className="form-group">
          <label>worker_rlimit_nofile</label>
          <input
            type="number"
            value={settings.worker_rlimit_nofile}
            onChange={(e) =>
              onChange("worker_rlimit_nofile", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <label>worker_connections</label>
          <input
            type="number"
            value={settings.worker_connections}
            onChange={(e) =>
              onChange("worker_connections", Number(e.target.value))
            }
          />
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>HTTP</h3>
        </div>
        <div className="form-group">
          <label>keepalive_timeout (seconds)</label>
          <input
            type="number"
            value={settings.keepalive_timeout}
            onChange={(e) =>
              onChange("keepalive_timeout", Number(e.target.value))
            }
          />
        </div>
        <label
          className="checkbox-row"
          onClick={() => onChange("sendfile", !settings.sendfile)}
        >
          <input type="checkbox" checked={settings.sendfile} readOnly />
          <span>sendfile — use kernel sendfile for static files</span>
        </label>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>GeoIP Blocked Countries</h3>
        </div>
        <div className="checkbox-grid">
          {COUNTRY_OPTIONS.map((code) => (
            <label
              key={code}
              className="checkbox-row"
              onClick={() => onToggleCountry(code)}
            >
              <input
                type="checkbox"
                checked={settings.denied_countries.includes(code)}
                readOnly
              />
              <span>{code}</span>
            </label>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Modules</h3>
        </div>
        <div className="checkbox-grid">
          {visibleModules.map((mod) => (
            <label
              key={mod.name}
              className="checkbox-row"
              onClick={() => onToggleModule(mod.name)}
            >
              <input type="checkbox" checked={mod.loaded} readOnly />
              <span>{mod.name.replace("ngx_http_", "").replace("ngx_", "").replace("_module.so", "")}</span>
            </label>
          ))}
        </div>
        {restModules.length > 0 && (
          <button
            className="btn btn-outline btn-sm"
            style={{ marginTop: 12 }}
            onClick={() => setShowAllModules(!showAllModules)}
          >
            {showAllModules
              ? "Show less"
              : `Show all ${settings.modules.length} modules`}
          </button>
        )}
      </div>

      <div className="actions-bar" style={{ marginTop: 16 }}>
        <button
          className="btn btn-primary"
          onClick={onSave}
          disabled={saving}
        >
          <Save size={16} />
          {saving ? "Saving..." : "Save Angie Settings"}
        </button>
        <button className="btn btn-success" onClick={onReload}>
          <RefreshCw size={16} />
          Reload Angie
        </button>
      </div>
    </div>
  );
}
