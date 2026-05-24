/**
 * Configuration page — per-connection WAF settings (spec: per-connection
 * ModSecurity state + GeoIP2 denied countries).
 *
 * Picks a connection from a dropdown synced to `?conn=<id>` so the page is
 * bookmarkable and shareable. The selected connection's WAF knobs live in
 * a single form: a 3-way radio for SecRuleEngine and a country grid for
 * GeoIP2 blocking. Save persists, regenerates the per-connection Angie
 * .conf, and triggers `angie -s reload` on the backend.
 */

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Save, Shield, Globe } from "lucide-react";
import {
  api,
  Connection,
  ModSecState,
  SecurityConfig,
} from "../api/client";
import { useSettings } from "../context/SettingsContext";

// Most-commonly-blocked countries. ISO 3166-1 alpha-2. Keep this list
// short — the backend accepts any valid ISO code, so we can extend later
// without a UI change.
const COUNTRY_OPTIONS = [
  "AF", "BR", "CN", "DE", "FR", "GB", "IL", "IN", "IQ", "IR",
  "JP", "KP", "KR", "MX", "NG", "NL", "PK", "PL", "QA", "RU",
  "SY", "TR", "UA", "US", "VN",
];

const MODSEC_STATES: ModSecState[] = ["blocking", "detection_only", "off"];

type Toast = { kind: "success" | "error" | "info"; msg: string };

export default function ConfigEditor() {
  const { t } = useSettings();
  const [searchParams, setSearchParams] = useSearchParams();
  const [connections, setConnections] = useState<Connection[] | null>(null);
  const [security, setSecurity] = useState<SecurityConfig | null>(null);
  const [initial, setInitial] = useState<SecurityConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<Toast | null>(null);

  const selectedIdRaw = searchParams.get("conn");
  const selectedId =
    selectedIdRaw && Number.isFinite(Number(selectedIdRaw))
      ? Number(selectedIdRaw)
      : null;

  function showToast(kind: Toast["kind"], msg: string) {
    setToast({ kind, msg });
    setTimeout(() => setToast(null), 3000);
  }

  // Load the connection list once on mount.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await api.getConnections();
        if (cancelled) return;
        setConnections(list);
        if (selectedId == null && list.length > 0) {
          setSearchParams({ conn: String(list[0].id) }, { replace: true });
        }
      } catch {
        if (!cancelled) showToast("error", t("config.toast.loadFailed"));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Load the selected connection's security config every time it changes.
  useEffect(() => {
    if (selectedId == null) {
      setSecurity(null);
      setInitial(null);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const cfg = await api.getConnectionSecurity(selectedId);
        if (cancelled) return;
        setSecurity(cfg);
        setInitial(cfg);
      } catch {
        if (!cancelled) showToast("error", t("config.toast.loadFailed"));
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  function selectConnection(id: number) {
    setSearchParams({ conn: String(id) });
  }

  function setModsecState(state: ModSecState) {
    setSecurity((p) => (p ? { ...p, modsec_state: state } : p));
  }

  function toggleCountry(code: string) {
    setSecurity((p) => {
      if (!p) return p;
      const set = new Set(p.geoip_denied_countries);
      if (set.has(code)) set.delete(code);
      else set.add(code);
      return { ...p, geoip_denied_countries: Array.from(set).sort() };
    });
  }

  const isDirty = useMemo(() => {
    if (!security || !initial) return false;
    if (security.modsec_state !== initial.modsec_state) return true;
    const a = [...security.geoip_denied_countries].sort();
    const b = [...initial.geoip_denied_countries].sort();
    return a.length !== b.length || a.some((v, i) => v !== b[i]);
  }, [security, initial]);

  async function handleSave() {
    if (!security || selectedId == null) return;
    setSaving(true);
    try {
      const saved = await api.updateConnectionSecurity(selectedId, security);
      setSecurity(saved);
      setInitial(saved);
      showToast("success", t("config.toast.saved"));
    } catch {
      showToast("error", t("config.toast.saveFailed"));
    } finally {
      setSaving(false);
    }
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

      {connections && connections.length === 0 ? (
        <div className="card">
          <p>{t("config.picker.empty")}</p>
        </div>
      ) : (
        <>
          <div className="card">
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label htmlFor="config-conn-picker">
                {t("config.picker.label")}
              </label>
              <select
                id="config-conn-picker"
                value={selectedId ?? ""}
                onChange={(e) => selectConnection(Number(e.target.value))}
              >
                {(connections ?? []).map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} — {c.domain}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {security && (
            <>
              <div className="card">
                <div className="card-header">
                  <h3>
                    <Shield
                      size={16}
                      style={{ marginRight: 6, verticalAlign: "middle" }}
                    />
                    {t("config.modsec.title")}
                  </h3>
                </div>
                <p style={{ marginTop: 0, opacity: 0.75 }}>
                  {t("config.modsec.description")}
                </p>
                <div className="config-radio-group">
                  {MODSEC_STATES.map((state) => (
                    <label
                      key={state}
                      className={`config-radio-row${
                        security.modsec_state === state ? " selected" : ""
                      }`}
                    >
                      <input
                        type="radio"
                        name="modsec_state"
                        value={state}
                        checked={security.modsec_state === state}
                        onChange={() => setModsecState(state)}
                      />
                      <span>
                        <strong>{t(`config.modsec.state.${state}`)}</strong>
                        <small style={{ display: "block", opacity: 0.7 }}>
                          {t(`config.modsec.state.${state}.desc`)}
                        </small>
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="card">
                <div className="card-header">
                  <h3>
                    <Globe
                      size={16}
                      style={{ marginRight: 6, verticalAlign: "middle" }}
                    />
                    {t("config.geoip.title")}
                  </h3>
                </div>
                <p style={{ marginTop: 0, opacity: 0.75 }}>
                  {t("config.geoip.description")}
                </p>
                <div className="checkbox-grid">
                  {COUNTRY_OPTIONS.map((code) => (
                    <label
                      key={code}
                      className="checkbox-row"
                      onClick={(e) => {
                        e.preventDefault();
                        toggleCountry(code);
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={security.geoip_denied_countries.includes(code)}
                        readOnly
                      />
                      <span>{code}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="actions-bar" style={{ marginTop: 16 }}>
                <button
                  className="btn btn-primary"
                  onClick={handleSave}
                  disabled={saving || !isDirty}
                >
                  <Save size={16} />
                  {saving ? t("config.saving") : t("config.save")}
                </button>
                {isDirty && (
                  <span style={{ opacity: 0.7 }}>{t("config.dirty")}</span>
                )}
              </div>
            </>
          )}
        </>
      )}

      {toast && <div className={`toast toast-${toast.kind}`}>{toast.msg}</div>}
    </div>
  );
}
