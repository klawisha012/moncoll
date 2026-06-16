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

import { createSignal, createEffect, createMemo, onMount, onCleanup, For, Show } from "solid-js";
import { useSearchParams } from "@solidjs/router";
import { Save, Shield, Globe, ShieldAlert, Gauge } from "lucide-solid";
import {
  api,
  Connection,
  ModSecState,
  SecurityConfig,
} from "../api/client";
import { useSettings } from "../context/SettingsContext";
import { useGlobalFilters } from "../context/GlobalFiltersContext";

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
  const settings = useSettings();
  const [searchParams, setSearchParams] = useSearchParams();
  const [connections, setConnections] = createSignal<Connection[] | null>(null);
  const [security, setSecurity] = createSignal<SecurityConfig | null>(null);
  const [initial, setInitial] = createSignal<SecurityConfig | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [saving, setSaving] = createSignal(false);
  const [toast, setToast] = createSignal<Toast | null>(null);

  const filters = useGlobalFilters();
  const selectedId = () => filters.connectionId;

  function showToast(kind: Toast["kind"], msg: string) {
    setToast({ kind, msg });
    setTimeout(() => setToast(null), 3000);
  }

  // Load the connection list once on mount.
  onMount(() => {
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    (async () => {
      try {
        const list = await api.getConnections();
        if (cancelled) return;
        setConnections(list);

        // Resolve the active connection: prefer a valid URL ?conn=, else the
        // persisted selection, else the first enabled connection. A param or
        // persisted id that isn't in the fetched list (e.g. a stale link to
        // another tenant's connection) falls back instead of getting stuck.
        const inList = (id: number | null) =>
          id != null && list.some((c) => c.id === id);
        const connParam = searchParams.conn;
        const paramId =
          connParam && Number.isFinite(Number(connParam)) ? Number(connParam) : null;
        if (inList(paramId)) {
          filters.setConnectionId(paramId);
        } else if (!inList(filters.connectionId) && list.length > 0) {
          const activeConns = list.filter((c) => c.enabled);
          filters.setConnectionId(activeConns.length > 0 ? activeConns[0].id : list[0].id);
        }
      } catch {
        if (!cancelled) showToast("error", settings.t("config.toast.loadFailed"));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
  });

  // Synchronize URL conn search query parameter with the global connectionId state
  createEffect(() => {
    const connParam = searchParams.conn;
    const currentId = selectedId();
    if (currentId != null) {
      if (connParam !== String(currentId)) {
        setSearchParams({ conn: String(currentId) }, { replace: true });
      }
    } else if (connParam != null) {
      // Clear URL conn param if connectionId is null
      setSearchParams({ conn: undefined }, { replace: true });
    }
  });

  // Load the selected connection's security config every time it changes.
  createEffect(() => {
    const activeId = selectedId();
    if (activeId == null) {
      setSecurity(null);
      setInitial(null);
      return;
    }
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    (async () => {
      try {
        const cfg = await api.getConnectionSecurity(activeId);
        if (cancelled) return;
        setSecurity(cfg);
        setInitial(cfg);
      } catch {
        if (!cancelled) showToast("error", settings.t("config.toast.loadFailed"));
      }
    })();
  });

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

  const isDirty = createMemo(() => {
    const sec = security();
    const init = initial();
    if (!sec || !init) return false;
    if (sec.modsec_state !== init.modsec_state) return true;
    if (sec.crowdsec_active !== init.crowdsec_active) return true;
    if (sec.ddos_protection !== init.ddos_protection) return true;
    const a = [...sec.geoip_denied_countries].sort();
    const b = [...init.geoip_denied_countries].sort();
    return a.length !== b.length || a.some((v, i) => v !== b[i]);
  });

  async function handleSave() {
    const activeId = selectedId();
    const sec = security();
    if (!sec || activeId == null) return;
    setSaving(true);
    try {
      const saved = await api.updateConnectionSecurity(activeId, sec);
      setSecurity(saved);
      setInitial(saved);
      showToast("success", settings.t("config.toast.saved"));
    } catch {
      showToast("error", settings.t("config.toast.saveFailed"));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Show
      when={!loading()}
      fallback={
        <div class="loading">
          <div class="spinner" />
          {settings.t("config.loading")}
        </div>
      }
    >
      <Show
        when={connections() && connections()!.length > 0}
        fallback={
          <div>
            <div class="page-header">
              <div>
                <h1>{settings.t("config.title")}</h1>
                <p>{settings.t("config.subtitle")}</p>
              </div>
            </div>
            <div class="card">
              <p>{settings.t("config.picker.empty")}</p>
            </div>
          </div>
        }
      >
        <Show
          when={selectedId() != null}
          fallback={
            <div>
              <div class="page-header">
                <div>
                  <h1>{settings.t("config.title")}</h1>
                  <p>{settings.t("config.subtitle")}</p>
                </div>
              </div>
              <div class="card text-center" style={{ padding: "48px 24px", display: "flex", "flex-direction": "column", "align-items": "center" }}>
                <ShieldAlert size={48} style={{ "margin-bottom": "16px", opacity: 0.6, color: "#f59e0b" }} />
                <h3 style={{ margin: 0 }}>{settings.t("config.picker.selectDomainTitle")}</h3>
                <p style={{ opacity: 0.7, "max-width": "460px", margin: "12px auto 0", "line-height": 1.5 }}>
                  {settings.t("config.picker.selectDomainDesc")}
                </p>
              </div>
            </div>
          }
        >
          <div>
            <div class="page-header">
              <div>
                <h1>{settings.t("config.title")}</h1>
                <p>{settings.t("config.subtitle")}</p>
              </div>
            </div>

            <Show when={security()}>
              <>
                <div class="card">
                  <div class="card-header">
                    <h3>
                      <Shield
                        size={16}
                        style={{ "margin-right": "6px", "vertical-align": "middle" }}
                      />
                      {settings.t("config.modsec.title")}
                    </h3>
                  </div>
                  <p style={{ "margin-top": 0, opacity: 0.75 }}>
                    {settings.t("config.modsec.description")}
                  </p>
                  <div class="config-radio-group">
                    <For each={MODSEC_STATES}>
                      {(state) => (
                        <label
                          class={`config-radio-row${
                            security()!.modsec_state === state ? " selected" : ""
                          }`}
                        >
                          <input
                            type="radio"
                            name="modsec_state"
                            value={state}
                            checked={security()!.modsec_state === state}
                            onChange={() => setModsecState(state)}
                          />
                          <span>
                            <strong>{settings.t(`config.modsec.state.${state}`)}</strong>
                            <small style={{ display: "block", opacity: 0.7 }}>
                              {settings.t(`config.modsec.state.${state}.desc`)}
                            </small>
                          </span>
                        </label>
                      )}
                    </For>
                  </div>
                </div>

                <div class="card">
                  <div class="card-header">
                    <h3>
                      <ShieldAlert
                        size={16}
                        style={{ "margin-right": "6px", "vertical-align": "middle" }}
                      />
                      {settings.t("config.crowdsec.title")}
                    </h3>
                  </div>
                  <p style={{ "margin-top": 0, opacity: 0.75 }}>
                    {settings.t("config.crowdsec.description")}
                  </p>
                  <label class="checkbox-row" style={{ "margin-top": "12px" }}>
                    <input
                      type="checkbox"
                      checked={security()!.crowdsec_active}
                      onChange={(e) => {
                        setSecurity((p) => p ? { ...p, crowdsec_active: e.currentTarget.checked } : p);
                      }}
                    />
                    <span>{settings.t("config.crowdsec.activeLabel")}</span>
                  </label>
                </div>

                <div class="card">
                  <div class="card-header">
                    <h3>
                      <Gauge
                        size={16}
                        style={{ "margin-right": "6px", "vertical-align": "middle" }}
                      />
                      {settings.t("config.ddos.title")}
                    </h3>
                  </div>
                  <p style={{ "margin-top": 0, opacity: 0.75 }}>
                    {settings.t("config.ddos.description")}
                  </p>
                  <label class="checkbox-row" style={{ "margin-top": "12px" }}>
                    <input
                      type="checkbox"
                      checked={security()!.ddos_protection}
                      onChange={(e) => {
                        setSecurity((p) => p ? { ...p, ddos_protection: e.currentTarget.checked } : p);
                      }}
                    />
                    <span>{settings.t("config.ddos.activeLabel")}</span>
                  </label>
                </div>

                <div class="card">
                  <div class="card-header">
                    <h3>
                      <Globe
                        size={16}
                        style={{ "margin-right": "6px", "vertical-align": "middle" }}
                      />
                      {settings.t("config.geoip.title")}
                    </h3>
                  </div>
                  <p style={{ "margin-top": 0, opacity: 0.75 }}>
                    {settings.t("config.geoip.description")}
                  </p>
                  <div style={{ display: "flex", gap: "8px", "margin-bottom": "16px" }}>
                    <button
                      type="button"
                      class="btn btn-outline btn-sm"
                      onClick={() => {
                        setSecurity((p) => p ? { ...p, geoip_denied_countries: [...COUNTRY_OPTIONS].sort() } : p);
                      }}
                    >
                      {settings.t("config.geoip.selectAll")}
                    </button>
                    <button
                      type="button"
                      class="btn btn-outline btn-sm"
                      onClick={() => {
                        setSecurity((p) => p ? { ...p, geoip_denied_countries: [] } : p);
                      }}
                    >
                      {settings.t("config.geoip.deselectAll")}
                    </button>
                  </div>
                  <div class="checkbox-grid">
                    <For each={COUNTRY_OPTIONS}>
                      {(code) => (
                        <label class="checkbox-row">
                          <input
                            type="checkbox"
                            checked={security()!.geoip_denied_countries.includes(code)}
                            onChange={() => toggleCountry(code)}
                          />
                          <span>{code}</span>
                        </label>
                      )}
                    </For>
                  </div>
                </div>

                <div class="actions-bar" style={{ "margin-top": "16px" }}>
                  <button
                    class="btn btn-primary"
                    onClick={handleSave}
                    disabled={saving() || !isDirty()}
                  >
                    <Save size={16} />
                    {saving() ? settings.t("config.saving") : settings.t("config.save")}
                  </button>
                  <Show when={isDirty()}>
                    <span style={{ opacity: 0.7 }}>{settings.t("config.dirty")}</span>
                  </Show>
                </div>
              </>
            </Show>

            <Show when={toast()}>
              <div class={`toast toast-${toast()!.kind}`}>{toast()!.msg}</div>
            </Show>
          </div>
        </Show>
      </Show>
    </Show>
  );
}
