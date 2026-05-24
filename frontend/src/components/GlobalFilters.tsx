import { useEffect } from "react";
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

/**
 * Sidebar block (under the brand) that owns the site-wide domain and
 * time-range filters. Pages read from useGlobalFilters().
 *
 * Hidden when the sidebar is collapsed — there's no compact icon for these
 * controls; expanding the sidebar restores them.
 *
 * Only renders for client users — admins see platform-wide data and don't
 * have tenant-scoped connections to pick from.
 */
export default function GlobalFilters() {
  const { t } = useSettings();
  const { user } = useAuth();
  const {
    connectionId,
    setConnectionId,
    timeValue,
    setTimeValue,
    timeUnit,
    setTimeUnit,
    connections,
    setConnections,
  } = useGlobalFilters();

  // Load connections once after auth lands. Admins skip — no per-tenant list.
  useEffect(() => {
    if (!user) return;
    if (user.platform_role !== "client") return;
    if (connections.length > 0) return;
    let cancelled = false;
    api
      .getConnections()
      .then((cs) => {
        if (!cancelled) setConnections(cs);
      })
      .catch(() => {
        // Silent — sidebar still works without a connection list (defaults to "all").
      });
    return () => {
      cancelled = true;
    };
  }, [user, connections.length, setConnections]);

  // Admins don't need the picker (no tenant-scoped connections).
  if (user?.platform_role !== "client") return null;

  const unitMultiplier =
    timeUnit === "minutes" ? 1 / 60 : timeUnit === "days" ? 24 : 1;
  const maxValue = Math.max(1, Math.floor(MAX_HOURS / unitMultiplier));

  const enabledConns = connections.filter((c) => c.enabled);

  return (
    <div className="global-filters">
      <div className="global-filters-row">
        <label className="global-filters-label">{t("dashboard.ui.domain")}</label>
        <select
          data-testid="global-domain-picker"
          className="global-filters-select"
          value={connectionId ?? ""}
          onChange={(e) =>
            setConnectionId(e.target.value === "" ? null : Number(e.target.value))
          }
        >
          <option value="">{t("dashboard.ui.allDomains")}</option>
          {enabledConns.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
              {c.domain ? ` (${c.domain})` : ""}
            </option>
          ))}
        </select>
      </div>

      <div className="global-filters-row">
        <label className="global-filters-label">
          {t("dashboard.ui.timeRange")}
        </label>
        <div className="global-filters-time-row">
          <input
            type="number"
            data-testid="global-time-value"
            className="global-filters-input"
            min={1}
            max={maxValue}
            value={timeValue}
            onChange={(e) => {
              const v = parseInt(e.target.value, 10);
              if (!Number.isNaN(v) && v >= 1 && v <= maxValue) setTimeValue(v);
            }}
          />
          <select
            data-testid="global-time-unit"
            className="global-filters-select"
            value={timeUnit}
            onChange={(e) => setTimeUnit(e.target.value as TimeUnit)}
          >
            {UNITS.map((u) => (
              <option key={u.value} value={u.value}>
                {t(u.labelKey)}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
}
