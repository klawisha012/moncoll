import { createSignal, createEffect, For, Show } from "solid-js";
import { A, useParams } from "@solidjs/router";
import { api, type TenantDetail } from "../api/client";
import { useSettings } from "../context/SettingsContext";

export default function ClientDetail() {
  const settings = useSettings();
  const params = useParams<{ id: string }>();
  const [detail, setDetail] = createSignal<TenantDetail | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    const id = params.id;
    if (!id) return;
    setLoading(true);
    setError(null);
    api.admin.getTenant(Number(id))
      .then(setDetail)
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  });

  const fmt = (v: string | null | undefined) =>
    v ? new Date(v).toLocaleString() : "—";

  return (
    <Show
      when={!loading()}
      fallback={<div class="cd-state">{settings.t("clients.detail.loading")}</div>}
    >
      <Show
        when={!error() && detail()}
        fallback={<div class="cd-state cd-state--err">{error() ?? "Not found"}</div>}
      >
        {(() => {
          const d = detail()!;
          return (
            <div class="page-content">
              <style>{styles}</style>

              <div class="page-header">
                <div>
                  <div class="cd-back-row">
                    <A href="/clients" class="cd-back">{settings.t("clients.back")}</A>
                  </div>
                  <h1 class="page-title">{d.tenant.display_name || d.tenant.name}</h1>
                  <p class="page-subtitle cd-mono">{d.tenant.name}</p>
                </div>
                <div class="cd-meta-chips">
                  <Show when={d.tenant.suspended_at}>
                    <span class="cd-chip cd-chip--suspended">{settings.t("clients.status.suspended")}</span>
                  </Show>
                  <span class="cd-chip">{settings.t("clients.col.created")}: {fmt(d.tenant.created_at)}</span>
                </div>
              </div>

              <div class="cd-sections">
                {/* Users */}
                <section class="cd-section">
                  <h2 class="cd-section-title">{settings.t("clients.detail.users")}</h2>
                  <Show
                    when={d.users.length > 0}
                    fallback={<p class="cd-empty">—</p>}
                  >
                    <table class="cd-table">
                      <thead>
                        <tr>
                          <th>{settings.t("clients.detail.meta.email")}</th>
                          <th>{settings.t("clients.detail.meta.role")}</th>
                          <th>{settings.t("clients.detail.meta.joined")}</th>
                          <th>TOTP</th>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={d.users}>
                          {(u) => (
                            <tr>
                              <td class="cd-mono">{u.email}</td>
                              <td><span class="cd-role">{u.tenant_role}</span></td>
                              <td class="cd-mono">{fmt(u.last_login_at)}</td>
                              <td>{u.totp_enabled ? "✓" : "—"}</td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </Show>
                </section>

                {/* Connections */}
                <section class="cd-section">
                  <h2 class="cd-section-title">{settings.t("clients.detail.connections")}</h2>
                  <Show
                    when={d.connections.length > 0}
                    fallback={<p class="cd-empty">—</p>}
                  >
                    <table class="cd-table">
                      <thead>
                        <tr>
                          <th>{settings.t("clients.detail.conn.domain")}</th>
                          <th>{settings.t("clients.detail.conn.status")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={d.connections}>
                          {(c) => (
                            <tr>
                              <td class="cd-mono">{c.domain}</td>
                              <td><span class={`cd-status cd-status--${c.status}`}>{c.status}</span></td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </Show>
                </section>
              </div>
            </div>
          );
        })()}
      </Show>
    </Show>
  );
}

const styles = `
.cd-state {
  font-family: 'JetBrains Mono', monospace; font-size: 13px;
  color: var(--ink-soft, #666); padding: 32px;
}
.cd-state--err { color: var(--red); }
.cd-back-row { margin-bottom: 8px; }
.cd-back {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--ink); text-decoration: none;
}
.cd-back:hover { color: var(--red); }
.cd-mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
.cd-meta-chips { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
.cd-chip {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 10px; letter-spacing: 0.18em; text-transform: uppercase;
  padding: 4px 10px; border: 2px solid var(--ink);
  color: var(--ink);
}
.cd-chip--suspended { background: rgba(214,54,42,0.12); color: var(--red); border-color: var(--red); }
.cd-sections { display: flex; flex-direction: column; gap: 40px; margin-top: 32px; }
.cd-section {}
.cd-section-title {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 13px; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--ink); border-bottom: 3px solid var(--ink);
  padding-bottom: 8px; margin: 0 0 16px;
}
.cd-empty {
  font-family: 'JetBrains Mono', monospace; font-size: 13px;
  color: var(--ink-soft, #666);
}
.cd-table {
  width: 100%; border-collapse: collapse;
  font-family: 'Inter Tight', sans-serif; font-size: 14px;
}
.cd-table th {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 10px; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--ink); border-bottom: 2px solid var(--ink);
  padding: 8px 12px; text-align: left;
}
.cd-table td {
  padding: 10px 12px; border-bottom: 1px solid rgba(0,0,0,0.08); vertical-align: middle;
}
[data-theme="dark"] .cd-table td { border-bottom: 1px solid rgba(255,255,255,0.08); }
.cd-role {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 10px; letter-spacing: 0.16em; text-transform: uppercase;
  padding: 3px 8px; border: 1px solid var(--ink); color: var(--ink);
}
.cd-status {
  font-family: 'JetBrains Mono', monospace; font-size: 11px;
  padding: 2px 6px;
}
.cd-status--active { color: var(--ok, #2c7a3d); }
.cd-status--error { color: var(--red); }
`;
