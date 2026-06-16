import { createSignal, onMount, For, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { api, type TenantRow } from "../api/client";
import { useSettings } from "../context/SettingsContext";

export default function Clients() {
  const settings = useSettings();
  const navigate = useNavigate();
  const [rows, setRows] = createSignal<TenantRow[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [toast, setToast] = createSignal<{ kind: "ok" | "err"; msg: string } | null>(null);

  const showToast = (kind: "ok" | "err", msg: string) => {
    setToast({ kind, msg });
    setTimeout(() => setToast(null), 4000);
  };

  const load = async () => {
    try {
      const data = await api.admin.listTenants();
      setRows(data);
    } catch (err) {
      showToast("err", err instanceof Error ? err.message : settings.t("general.error"));
    } finally {
      setLoading(false);
    }
  };

  onMount(() => { void load(); });

  const suspend = async (row: TenantRow) => {
    if (!confirm(settings.t("clients.confirm.suspend").replace("{name}", row.name))) return;
    try {
      await api.admin.suspendTenant(row.id);
      showToast("ok", `${row.name} suspended`);
      void load();
    } catch (err) {
      showToast("err", err instanceof Error ? err.message : settings.t("general.error"));
    }
  };

  const unsuspend = async (row: TenantRow) => {
    try {
      await api.admin.unsuspendTenant(row.id);
      showToast("ok", `${row.name} unsuspended`);
      void load();
    } catch (err) {
      showToast("err", err instanceof Error ? err.message : settings.t("general.error"));
    }
  };

  const deleteTenant = async (row: TenantRow) => {
    const msg = settings.t("clients.confirm.delete").replace("{name}", row.name);
    if (!confirm(msg)) return;
    try {
      await api.admin.deleteTenant(row.id, row.name);
      showToast("ok", `${row.name} deleted`);
      void load();
    } catch (err) {
      showToast("err", err instanceof Error ? err.message : settings.t("general.error"));
    }
  };

  const fmt = (v: string | null) =>
    v ? new Date(v).toLocaleDateString() : "—";

  return (
    <div class="page-content">
      <style>{styles}</style>

      <Show when={toast()}>
        <div class={`cl-toast cl-toast--${toast()!.kind}`}>{toast()!.msg}</div>
      </Show>

      <div class="page-header">
        <div>
          <h1 class="page-title">{settings.t("clients.title")}</h1>
          <p class="page-subtitle">{settings.t("clients.subtitle")}</p>
        </div>
      </div>

      <Show
        when={!loading()}
        fallback={<div class="cl-loading">{settings.t("clients.loading")}</div>}
      >
        <Show
          when={rows().length > 0}
          fallback={<div class="cl-empty">{settings.t("clients.empty")}</div>}
        >
          <div class="cl-table-wrap">
            <table class="cl-table">
              <thead>
                <tr>
                  <th>{settings.t("clients.col.tenant")}</th>
                  <th>{settings.t("clients.col.owner")}</th>
                  <th>{settings.t("clients.col.users")}</th>
                  <th>{settings.t("clients.col.connections")}</th>
                  <th>{settings.t("clients.col.created")}</th>
                  <th>{settings.t("clients.col.lastActivity")}</th>
                  <th>{settings.t("clients.col.status")}</th>
                  <th>{settings.t("clients.col.actions")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={rows()}>
                  {(row) => {
                    const suspended = () => !!row.suspended_at;
                    return (
                      <tr class={suspended() ? "cl-row--suspended" : ""}>
                        <td>
                          <button
                            type="button"
                            class="cl-name-btn"
                            onClick={() => navigate(`/clients/${row.id}`)}
                          >
                            {row.display_name || row.name}
                            <span class="cl-slug">{row.name}</span>
                          </button>
                        </td>
                        <td class="cl-mono">{row.owner_email ?? "—"}</td>
                        <td class="cl-num">{row.user_count}</td>
                        <td class="cl-num">{row.connection_count}</td>
                        <td>{fmt(row.created_at)}</td>
                        <td>{fmt(row.last_activity)}</td>
                        <td>
                          <span class={`cl-badge cl-badge--${suspended() ? "suspended" : "active"}`}>
                            {suspended()
                              ? settings.t("clients.status.suspended")
                              : settings.t("clients.status.active")}
                          </span>
                        </td>
                        <td>
                          <div class="cl-actions">
                            <Show
                              when={suspended()}
                              fallback={
                                <button type="button" class="cl-btn cl-btn--warn" onClick={() => suspend(row)}>
                                  {settings.t("clients.action.suspend")}
                                </button>
                              }
                            >
                              <button type="button" class="cl-btn cl-btn--ok" onClick={() => unsuspend(row)}>
                                {settings.t("clients.action.unsuspend")}
                              </button>
                            </Show>
                            <button type="button" class="cl-btn cl-btn--danger" onClick={() => deleteTenant(row)}>
                              {settings.t("clients.action.delete")}
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  }}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </Show>
    </div>
  );
}

const styles = `
.cl-loading, .cl-empty {
  font-family: 'JetBrains Mono', monospace; font-size: 13px;
  color: var(--ink-soft, #666); padding: 32px 0;
}
.cl-toast {
  position: fixed; top: 20px; right: 20px; z-index: 1000;
  padding: 12px 20px; border: 3px solid var(--rule, var(--ink));
  font-family: 'JetBrains Mono', monospace; font-size: 13px;
}
.cl-toast--ok { background: rgba(44,122,61,0.1); color: var(--ok, #2c7a3d); }
.cl-toast--err { background: rgba(214,54,42,0.1); color: var(--red); }
.cl-table-wrap { overflow-x: auto; }
.cl-table {
  width: 100%; border-collapse: collapse;
  font-family: 'Inter Tight', sans-serif; font-size: 14px;
}
.cl-table th {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--cream); border-bottom: 3px solid var(--ink);
  padding: 10px 12px; text-align: left; white-space: nowrap;
}
.cl-table td {
  padding: 12px 12px; border-bottom: 1px solid rgba(0,0,0,0.1); vertical-align: middle;
}
[data-theme="dark"] .cl-table td { border-bottom: 1px solid rgba(255,255,255,0.08); }
.cl-row--suspended td { opacity: 0.55; }
.cl-mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
.cl-num { font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 700; text-align: right; }
.cl-name-btn {
  background: none; border: none; cursor: pointer; padding: 0;
  text-align: left; color: var(--ink);
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 13px; letter-spacing: 0.06em; text-transform: uppercase;
  display: flex; flex-direction: column; gap: 2px;
}
.cl-name-btn:hover { color: var(--red); }
.cl-slug { font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 400; opacity: 0.6; letter-spacing: 0; text-transform: none; }
.cl-badge {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 10px; letter-spacing: 0.18em; text-transform: uppercase;
  padding: 3px 8px;
}
.cl-badge--active { background: rgba(44,122,61,0.12); color: var(--ok, #2c7a3d); }
.cl-badge--suspended { background: rgba(214,54,42,0.12); color: var(--red); }
.cl-actions { display: flex; gap: 6px; }
.cl-btn {
  border: 2px solid currentColor; background: transparent;
  cursor: pointer; padding: 4px 10px;
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 10px; letter-spacing: 0.18em; text-transform: uppercase;
  transition: background 80ms, color 80ms;
}
.cl-btn--ok { color: var(--ok, #2c7a3d); }
.cl-btn--ok:hover { background: var(--ok, #2c7a3d); color: var(--cream); }
.cl-btn--warn { color: var(--amber, #b27a00); }
.cl-btn--warn:hover { background: var(--amber, #b27a00); color: var(--cream); }
.cl-btn--danger { color: var(--red); }
.cl-btn--danger:hover { background: var(--red); color: var(--cream); }
`;
