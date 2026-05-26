import { createEffect, onCleanup, For, Show } from "solid-js";
import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import { useGlobalFilters, type TimeUnit } from "../context/GlobalFiltersContext";
import { useSettings } from "../context/SettingsContext";

const UNITS: { value: TimeUnit; labelKey: string }[] = [
  { value: "minutes", labelKey: "dashboard.ui.minutes" },
  { value: "hours", labelKey: "dashboard.ui.hours" },
  { value: "days", labelKey: "dashboard.ui.days" },
];

const MAX_HOURS = 8760;

export default function GlobalFilters() {
  const settings = useSettings();
  const auth = useAuth();
  const filters = useGlobalFilters();

  createEffect(() => {
    const usr = auth.user;
    if (!usr) return;
    if (usr.platform_role !== "client") return;
    if (filters.connections.length > 0) return;

    let cancelled = false;
    api
      .getConnections()
      .then((cs) => {
        if (!cancelled) filters.setConnections(cs);
      })
      .catch(() => {
        // Silent — sidebar still works without a connection list (defaults to "all").
      });

    onCleanup(() => {
      cancelled = true;
    });
  });

  const maxValue = () => {
    const unitMultiplier =
      filters.timeUnit === "minutes" ? 1 / 60 : filters.timeUnit === "days" ? 24 : 1;
    return Math.max(1, Math.floor(MAX_HOURS / unitMultiplier));
  };

  const enabledConns = () => filters.connections.filter((c) => c.enabled);

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
          <div class="global-filters-time-row">
            <input
              type="number"
              data-testid="global-time-value"
              class="global-filters-input"
              min={1}
              max={maxValue()}
              value={filters.timeValue}
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
        </div>
      </div>
    </Show>
  );
}
