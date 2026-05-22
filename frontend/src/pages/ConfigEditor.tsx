import { useState, useEffect } from "react";
import {
  api,
  ModSecuritySettings,
  AngieSettings,
} from "../api/client";
import { Save, RefreshCw, Shield, Cog } from "lucide-react";
import { useSettings } from "../context/SettingsContext";

type TabType = "modsecurity" | "angie";

const COUNTRY_OPTIONS = [
  "RU", "CN", "US", "BR", "DE", "FR", "GB", "IN", "JP", "KR",
  "PL", "QA", "UA", "NL", "IR", "KP", "SY", "IQ", "AF", "PK",
];

/* ══════════════════════════════════════════════════════════════════
    Tooltip component — shows a ? icon that reveals a description
    bubble on hover. Supports i18n via translation keys.
    ══════════════════════════════════════════════════════════════════ */
function Tooltip({ tooltipKey }: { tooltipKey: string }) {
  const { t } = useSettings();
  const text = t(tooltipKey);

  // Don't render if there's no translation (e.g., key not defined)
  if (text === tooltipKey) return null;

  return (
    <span className="tooltip-wrapper">
      <span className="tooltip-trigger" tabIndex={0} aria-label={text}>
        ?
      </span>
      <span className="tooltip-bubble">{text}</span>
    </span>
  );
}

/* ══════════════════════════════════════════════════════════════════
    FieldLabel — renders a form label with an optional tooltip (?) icon.
    Passing a tooltipKey will show the help bubble on hover.
    ══════════════════════════════════════════════════════════════════ */
function FieldLabel({
  label,
  tooltipKey,
}: {
  label: string;
  tooltipKey?: string;
}) {
  return (
    <label>
      {label}
      {tooltipKey ? <> <Tooltip tooltipKey={tooltipKey} /></> : null}
    </label>
  );
}

/* ══════════════════════════════════════════════════════════════════
    CheckboxLabel — a checkbox-row label with optional tooltip.
    ══════════════════════════════════════════════════════════════════ */
function CheckboxLabel({
  text,
  tooltipKey,
}: {
  text: string;
  tooltipKey?: string;
}) {
  return (
    <span>
      {text}
      {tooltipKey ? <> <Tooltip tooltipKey={tooltipKey} /></> : null}
    </span>
  );
}

export default function ConfigEditor() {
  const { t } = useSettings();
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
    } catch {
      showToast(t("config.toast.loadFailed"), "error");
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

  async function handleSaveModsec() {
    if (!modsec) return;
    setSaving(true);
    try {
      await api.updateModsecSettings(modsec);
      showToast(t("config.toast.modsecSaved"), "success");
    } catch {
      showToast(t("config.toast.modsecSaveFailed"), "error");
    } finally {
      setSaving(false);
    }
  }

  async function handleSaveAngie() {
    if (!angie) return;
    setSaving(true);
    try {
      await api.updateAngieSettings(angie);
      showToast(t("config.toast.angieSaved"), "success");
    } catch {
      showToast(t("config.toast.angieSaveFailed"), "error");
    } finally {
      setSaving(false);
    }
  }

  async function handleReload(type: "modsec" | "angie") {
    try {
      const result =
        type === "modsec"
          ? await api.reloadModsec()
          : await api.reloadAngie();
      if (result.success) {
        showToast(t("config.toast.reloaded"), "success");
      } else {
        showToast(t("config.toast.reloadFailedMsg", { msg: result.message }), "error");
      }
    } catch {
      showToast(t("config.toast.reloadError"), "error");
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
        {t("config.loading")}
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>{t("config.title")}</h1>
          <p>{t("config.subtitle")}</p>
        </div>
      </div>

      <div className="tabs">
        <button
          className={`tab ${activeTab === "modsecurity" ? "active" : ""}`}
          onClick={() => setActiveTab("modsecurity")}
        >
          <Shield size={14} style={{ marginRight: "6px" }} />
          {t("config.tab.modsec")}
        </button>
        <button
          className={`tab ${activeTab === "angie" ? "active" : ""}`}
          onClick={() => setActiveTab("angie")}
        >
          <Cog size={14} style={{ marginRight: "6px" }} />
          {t("config.tab.angie")}
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
          onSave={handleSaveAngie}
          onReload={() => handleReload("angie")}
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

/* ══════════════════════════════════════════════════════════════════
    ModSecurity Tab
    ══════════════════════════════════════════════════════════════════ */
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
  const { t } = useSettings();
  return (
    <div>
      <div className="card">
        <div className="card-header">
          <h3>{t("config.ruleEngine")}</h3>
        </div>
        <div className="form-group">
          <FieldLabel label={t("config.secRuleEngine")} tooltipKey="tooltip.rule_engine" />
          <select
            value={settings.rule_engine}
            onChange={(e) => onChange("rule_engine", e.target.value)}
          >
            <option value="On">{t("config.on")}</option>
            <option value="Off">{t("config.off")}</option>
            <option value="DetectionOnly">{t("config.detectionOnly")}</option>
          </select>
        </div>
        <label
          className="checkbox-row"
          onClick={() => onChange("status_engine", !settings.status_engine)}
        >
          <input type="checkbox" checked={settings.status_engine} readOnly />
          <CheckboxLabel
            text={t("config.statusEngine")}
            tooltipKey="tooltip.status_engine"
          />
        </label>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{t("config.section.requestBody")}</h3>
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
          <CheckboxLabel
            text={t("config.field.bodyAccess")}
            tooltipKey="tooltip.request_body_access"
          />
        </label>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.bodyLimit")}
            tooltipKey="tooltip.request_body_limit"
          />
          <input
            type="number"
            value={settings.request_body_limit}
            onChange={(e) =>
              onChange("request_body_limit", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.noFilesLimit")}
            tooltipKey="tooltip.request_body_no_files_limit"
          />
          <input
            type="number"
            value={settings.request_body_no_files_limit}
            onChange={(e) =>
              onChange("request_body_no_files_limit", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.bodyLimitAction")}
            tooltipKey="tooltip.request_body_limit_action"
          />
          <select
            value={settings.request_body_limit_action}
            onChange={(e) =>
              onChange("request_body_limit_action", e.target.value)
            }
          >
            <option value="Reject">{t("config.option.reject")}</option>
            <option value="ProcessPartial">{t("config.option.processPartial")}</option>
          </select>
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.jsonDepth")}
            tooltipKey="tooltip.request_body_json_depth_limit"
          />
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
          <FieldLabel
            label={t("config.field.argumentsLimit")}
            tooltipKey="tooltip.arguments_limit"
          />
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
          <h3>{t("config.section.responseBody")}</h3>
        </div>
        <label
          className="checkbox-row"
          onClick={() =>
            onChange("response_body_access", !settings.response_body_access)
          }
        >
          <input
            type="checkbox"
            checked={settings.response_body_access}
            readOnly
          />
          <CheckboxLabel
            text={t("config.field.responseAccess")}
            tooltipKey="tooltip.response_body_access"
          />
        </label>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.responseLimit")}
            tooltipKey="tooltip.response_body_limit"
          />
          <input
            type="number"
            value={settings.response_body_limit}
            onChange={(e) =>
              onChange("response_body_limit", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.responseLimitAction")}
            tooltipKey="tooltip.response_body_limit_action"
          />
          <select
            value={settings.response_body_limit_action}
            onChange={(e) =>
              onChange("response_body_limit_action", e.target.value)
            }
          >
            <option value="ProcessPartial">{t("config.option.processPartial")}</option>
            <option value="Reject">{t("config.option.reject")}</option>
          </select>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{t("config.section.auditLog")}</h3>
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.auditEngine")}
            tooltipKey="tooltip.audit_engine"
          />
          <select
            value={settings.audit_engine}
            onChange={(e) => onChange("audit_engine", e.target.value)}
          >
            <option value="On">{t("config.option.onAudit")}</option>
            <option value="Off">{t("config.option.offAudit")}</option>
            <option value="RelevantOnly">{t("config.option.relevantOnly")}</option>
          </select>
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.auditLogType")}
            tooltipKey="tooltip.audit_log_type"
          />
          <select
            value={settings.audit_log_type}
            onChange={(e) => onChange("audit_log_type", e.target.value)}
          >
            <option value="Serial">{t("config.option.serial")}</option>
            <option value="Concurrent">{t("config.option.concurrent")}</option>
          </select>
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.auditLogFormat")}
            tooltipKey="tooltip.audit_log_format"
          />
          <select
            value={settings.audit_log_format}
            onChange={(e) => onChange("audit_log_format", e.target.value)}
          >
            <option value="JSON">{t("config.option.json")}</option>
            <option value="Native">{t("config.option.native")}</option>
          </select>
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.auditLogParts")}
            tooltipKey="tooltip.audit_log_parts"
          />
          <input
            type="text"
            value={settings.audit_log_parts}
            onChange={(e) => onChange("audit_log_parts", e.target.value)}
          />
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.auditRelevantStatus")}
            tooltipKey="tooltip.audit_log_relevant_status"
          />
          <input
            type="text"
            value={settings.audit_log_relevant_status}
            onChange={(e) =>
              onChange("audit_log_relevant_status", e.target.value)
            }
          />
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.auditLogPath")}
            tooltipKey="tooltip.audit_log_path"
          />
          <input
            type="text"
            value={settings.audit_log_path}
            onChange={(e) => onChange("audit_log_path", e.target.value)}
          />
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{t("config.pcre")}</h3>
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.pcreLimit")}
            tooltipKey="tooltip.pcre_match_limit"
          />
          <input
            type="number"
            value={settings.pcre_match_limit}
            onChange={(e) =>
              onChange("pcre_match_limit", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <FieldLabel
            label={t("config.field.pcreLimitRecursion")}
            tooltipKey="tooltip.pcre_match_limit_recursion"
          />
          <input
            type="number"
            value={settings.pcre_match_limit_recursion}
            onChange={(e) =>
              onChange("pcre_match_limit_recursion", Number(e.target.value))
            }
          />
        </div>
        <div className="form-group">
          <FieldLabel label={t("config.field.tmpDir")} tooltipKey="tooltip.tmp_dir" />
          <input
            type="text"
            value={settings.tmp_dir}
            onChange={(e) => onChange("tmp_dir", e.target.value)}
          />
        </div>
        <div className="form-group">
          <FieldLabel label={t("config.field.dataDir")} tooltipKey="tooltip.data_dir" />
          <input
            type="text"
            value={settings.data_dir}
            onChange={(e) => onChange("data_dir", e.target.value)}
          />
        </div>
      </div>

      <div className="actions-bar" style={{ marginTop: "16px" }}>
        <button
          className="btn btn-primary"
          onClick={onSave}
          disabled={saving}
        >
          <Save size={16} />
          {saving ? t("general.saving") : t("config.btn.saveModSec")}
        </button>
        <button className="btn btn-success" onClick={onReload}>
          <RefreshCw size={16} />
          {t("config.btn.reloadAngie")}
        </button>
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════
    Angie Tab
    ══════════════════════════════════════════════════════════════════ */
function AngieTab({
  settings,
  onSave,
  onReload,
  onToggleCountry,
  saving,
}: {
  settings: AngieSettings;
  onSave: () => void;
  onReload: () => void;
  onToggleCountry: (code: string) => void;
  saving: boolean;
}) {
  const { t } = useSettings();
  return (
    <div>
      <div className="card">
        <div className="card-header">
          <h3>{t("config.section.geoBlocked")}</h3>
          <Tooltip tooltipKey="tooltip.geoip_countries" />
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

      <div className="actions-bar" style={{ marginTop: "16px" }}>
        <button
          className="btn btn-primary"
          onClick={onSave}
          disabled={saving}
        >
          <Save size={16} />
          {saving ? t("general.saving") : t("config.btn.saveAngie")}
        </button>
        <button className="btn btn-success" onClick={onReload}>
          <RefreshCw size={16} />
          {t("config.btn.reloadAngie")}
        </button>
      </div>
    </div>
  );
}
