import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type TenantDetail } from "../api/client";
import { useSettings } from "../context/SettingsContext";

export default function ClientDetail() {
  const { t } = useSettings();
  const { id } = useParams<{ id: string }>();
  const [detail, setDetail] = useState<TenantDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    api.admin.getTenant(Number(id))
      .then(setDetail)
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, [id]);

  const fmt = (v: string | null | undefined) =>
    v ? new Date(v).toLocaleString() : "—";

  if (loading) return <div className="cd-state">{t("clients.detail.loading")}</div>;
  if (error || !detail) return <div className="cd-state cd-state--err">{error ?? "Not found"}</div>;

  const { tenant, users, connections } = detail;

  return (
    <div className="page-content">
      <style>{styles}</style>

      <div className="page-header">
        <div>
          <div className="cd-back-row">
            <Link to="/clients" className="cd-back">{t("clients.back")}</Link>
          </div>
          <h1 className="page-title">{tenant.display_name || tenant.name}</h1>
          <p className="page-subtitle cd-mono">{tenant.name}</p>
        </div>
        <div className="cd-meta-chips">
          {tenant.suspended_at && (
            <span className="cd-chip cd-chip--suspended">{t("clients.status.suspended")}</span>
          )}
          <span className="cd-chip">{t("clients.col.created")}: {fmt(tenant.created_at)}</span>
        </div>
      </div>

      <div className="cd-sections">
        {/* Users */}
        <section className="cd-section">
          <h2 className="cd-section-title">{t("clients.detail.users")}</h2>
          {users.length === 0 ? (
            <p className="cd-empty">—</p>
          ) : (
            <table className="cd-table">
              <thead>
                <tr>
                  <th>{t("clients.detail.meta.email")}</th>
                  <th>{t("clients.detail.meta.role")}</th>
                  <th>{t("clients.detail.meta.joined")}</th>
                  <th>TOTP</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="cd-mono">{u.email}</td>
                    <td><span className="cd-role">{u.tenant_role}</span></td>
                    <td className="cd-mono">{fmt(u.last_login_at)}</td>
                    <td>{u.totp_enabled ? "✓" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        {/* Connections */}
        <section className="cd-section">
          <h2 className="cd-section-title">{t("clients.detail.connections")}</h2>
          {connections.length === 0 ? (
            <p className="cd-empty">—</p>
          ) : (
            <table className="cd-table">
              <thead>
                <tr>
                  <th>{t("clients.detail.conn.domain")}</th>
                  <th>{t("clients.detail.conn.status")}</th>
                </tr>
              </thead>
              <tbody>
                {connections.map((c) => (
                  <tr key={c.id}>
                    <td className="cd-mono">{c.domain}</td>
                    <td><span className={`cd-status cd-status--${c.status}`}>{c.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </div>
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
