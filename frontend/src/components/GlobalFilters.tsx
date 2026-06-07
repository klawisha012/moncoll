import { createEffect, onCleanup, For, Show, createSignal } from "solid-js";
import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import { useGlobalFilters, type TimeUnit } from "../context/GlobalFiltersContext";
import { useSettings } from "../context/SettingsContext";

const UNITS: { value: TimeUnit; labelKey: string }[] = [
  { value: "minutes", labelKey: "dashboard.ui.minutes" },
  { value: "hours", labelKey: "dashboard.ui.hours" },
  { value: "days", labelKey: "dashboard.ui.days" },
];

const PRESETS = [
  { value: 15, unit: "minutes" as TimeUnit, labelSuffix: "dashboard.ui.min" },
  { value: 1, unit: "hours" as TimeUnit, labelSuffix: "dashboard.ui.hr" },
  { value: 24, unit: "hours" as TimeUnit, labelSuffix: "dashboard.ui.hr" },
  { value: 7, unit: "days" as TimeUnit, labelSuffix: "dashboard.ui.day" },
  { value: 30, unit: "days" as TimeUnit, labelSuffix: "dashboard.ui.day" },
];

const MAX_HOURS = 8760;

export default function GlobalFilters() {
  const settings = useSettings();
  const auth = useAuth();
  const filters = useGlobalFilters();
  const [showCustom, setShowCustom] = createSignal(false);



  const maxValue = () => {
    const unitMultiplier =
      filters.timeUnit === "minutes" ? 1 / 60 : filters.timeUnit === "days" ? 24 : 1;
    return Math.max(1, Math.floor(MAX_HOURS / unitMultiplier));
  };

  const enabledConns = () => filters.connections.filter((c) => c.enabled);

  const isPresetActive = (p: typeof PRESETS[0]) => {
    return filters.timeValue === p.value && filters.timeUnit === p.unit;
  };

  const hasMatchingPreset = () => {
    return PRESETS.some((p) => filters.timeValue === p.value && filters.timeUnit === p.unit);
  };

  // If initial loaded filters don't match any preset, ensure Custom fields show up
  createEffect(() => {
    if (!hasMatchingPreset()) {
      setShowCustom(true);
    }
  });

  return (
    <Show when={auth.user?.platform_role === "client"}>
      <div class="global-filters">
        <div class="global-filters-row">
          <label class="global-filters-label">{settings.t("dashboard.ui.domain")}</label>
          <select
            data-testid="global-domain-picker"
            class="global-filters-select"
            value={filters.connectionId ?? ""}
            onChange={(e) =>
              filters.setConnectionId(e.target.value === "" ? null : Number(e.target.value))
            }
          >
            <option value="">{settings.t("dashboard.ui.allDomains")}</option>
            <For each={enabledConns()}>
              {(c) => (
                <option value={c.id}>
                  {c.name}
                  {c.domain ? ` (${c.domain})` : ""}
                </option>
              )}
            </For>
          </select>
        </div>

        <div class="global-filters-row">
          <label class="global-filters-label">
            {settings.t("dashboard.ui.timeRange")}
          </label>
          
          <div style={{ display: "flex", "flex-wrap": "wrap", gap: "6px", "margin-bottom": "4px" }}>
            <For each={PRESETS}>
              {(p) => {
                const active = () => isPresetActive(p);
                return (
                  <button
                    type="button"
                    class="btn btn-sm"
                    style={{
                      background: active() ? "var(--ink)" : "var(--cream)",
                      color: active() ? "var(--cream)" : "var(--ink)",
                      "border-color": "var(--ink)",
                      "box-shadow": active() ? "none" : "2px 2px 0 var(--ink)",
                      transform: active() ? "translate(1px, 1px)" : "none",
                      "font-family": "var(--font-mono)",
                      "padding": "4px 6px",
                      "font-size": "11px",
                      "letter-spacing": "0",
                      "text-transform": "none",
                      "cursor": "pointer",
                      "transition": "background 0.15s, color 0.15s, transform 0.1s, box-shadow 0.1s"
                    }}
                    onClick={() => {
                      filters.setTimeValue(p.value);
                      filters.setTimeUnit(p.unit);
                      setShowCustom(false);
                    }}
                  >
                    {p.value}{settings.t(p.labelSuffix)}
                  </button>
                );
              }}
            </For>
            
            <button
              type="button"
              class="btn btn-sm"
              style={{
                background: showCustom() && !hasMatchingPreset() ? "var(--cream)" : showCustom() ? "var(--ink)" : "var(--cream)",
                color: showCustom() && !hasMatchingPreset() ? "var(--ink)" : showCustom() ? "var(--cream)" : "var(--ink)",
                "border-color": "var(--ink)",
                "box-shadow": showCustom() ? "none" : "2px 2px 0 var(--ink)",
                transform: showCustom() ? "translate(1px, 1px)" : "none",
                "font-family": "var(--font-mono)",
                "padding": "4px 6px",
                "font-size": "11px",
                "letter-spacing": "0",
                "text-transform": "none",
                "cursor": "pointer",
                "transition": "background 0.15s, color 0.15s, transform 0.1s, box-shadow 0.1s"
              }}
              onClick={() => {
                setShowCustom((prev) => !prev);
              }}
            >
              {settings.t("dashboard.ui.custom")}
            </button>
          </div>

          <Show when={showCustom() || !hasMatchingPreset()}>
            <div
              class="global-filters-time-row"
              style={{
                "margin-top": "6px",
                "padding-top": "8px",
                "border-top": "1px dashed var(--line)",
                display: "flex",
                gap: "6px",
                animation: "fadeIn 0.2s var(--ease-out)"
              }}
            >
              <input
                type="number"
                data-testid="global-time-value"
                class="global-filters-input"
                min={1}
                max={maxValue()}
                value={filters.timeValue}
                style={{ width: "65px", cursor: "text" }}
                onChange={(e) => {
                  const v = parseInt(e.target.value, 10);
                  if (!Number.isNaN(v) && v >= 1 && v <= maxValue()) filters.setTimeValue(v);
                }}
              />
              <select
                data-testid="global-time-unit"
                class="global-filters-select"
                value={filters.timeUnit}
                onChange={(e) => filters.setTimeUnit(e.target.value as TimeUnit)}
              >
                <For each={UNITS}>
                  {(u) => (
                    <option value={u.value}>
                      {settings.t(u.labelKey)}
                    </option>
                  )}
                </For>
              </select>
            </div>
          </Show>
        </div>
      </div>
    </Show>
  );
}

