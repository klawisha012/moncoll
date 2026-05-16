import { useCallback, useEffect, useState, type CSSProperties, type FormEvent, type ReactNode } from "react";
import { Plus, Trash2, KeyRound, Shield, Eye } from "lucide-react";
import { api, type UserPublic, type UserRole } from "../api/client";
import { useAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";

export default function Users() {
  const { user: me } = useAuth();
  const { t } = useSettings();
  const [users, setUsers] = useState<UserPublic[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [resetTarget, setResetTarget] = useState<UserPublic | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setUsers(await api.auth.listUsers());
    } catch (e) {
      setError(e instanceof Error ? e.message : "error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const handleRoleChange = async (u: UserPublic, role: UserRole) => {
    try {
      await api.auth.updateUser(u.id, { role });
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "error");
    }
  };

  const handleDelete = async (u: UserPublic) => {
    if (!confirm(t("auth.users.confirmDelete").replace("{name}", u.username))) return;
    try {
      await api.auth.deleteUser(u.id);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "error");
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">{t("auth.users.title")}</h1>
          <p className="page-subtitle">{t("auth.users.subtitle")}</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          <Plus size={16} /> {t("auth.users.add")}
        </button>
      </div>

      {error && (
        <div
          style={{
            padding: "10px 12px",
            background: "rgba(239,68,68,0.08)",
            border: "1px solid rgba(239,68,68,0.25)",
            borderRadius: 8,
            color: "#ef4444",
            fontSize: 13,
            marginBottom: 16,
          }}
        >
          {error}
        </div>
      )}

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "var(--bg-base)" }}>
              <Th>{t("auth.username")}</Th>
              <Th>{t("auth.users.role")}</Th>
              <Th>{t("auth.users.status")}</Th>
              <Th>{t("auth.users.created")}</Th>
              <Th style={{ textAlign: "right" }}>{t("auth.users.actions")}</Th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <Td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)" }}>
                  {t("general.loading")}
                </Td>
              </tr>
            )}
            {!loading && users.length === 0 && (
              <tr>
                <Td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)" }}>
                  —
                </Td>
              </tr>
            )}
            {users.map((u) => {
              const isMe = me?.id === u.id;
              return (
                <tr key={u.id} style={{ borderTop: "1px solid var(--border-subtle)" }}>
                  <Td>
                    <strong>{u.username}</strong>
                    {isMe && (
                      <span
                        style={{
                          marginLeft: 8,
                          fontSize: 11,
                          color: "var(--text-muted)",
                        }}
                      >
                        ({t("auth.users.you")})
                      </span>
                    )}
                  </Td>
                  <Td>
                    <select
                      value={u.role}
                      disabled={isMe}
                      onChange={(e) => handleRoleChange(u, e.target.value as UserRole)}
                      style={selectStyle}
                    >
                      <option value="admin">admin</option>
                      <option value="viewer">viewer</option>
                    </select>
                  </Td>
                  <Td>
                    {u.must_change_password ? (
                      <span style={{ color: "#f59e0b", fontSize: 12 }}>
                        {t("auth.users.mustChange")}
                      </span>
                    ) : (
                      <span style={{ color: "#10b981", fontSize: 12 }}>
                        {t("auth.users.active")}
                      </span>
                    )}
                  </Td>
                  <Td style={{ color: "var(--text-muted)", fontSize: 12 }}>
                    {new Date(u.created_at).toLocaleString()}
                  </Td>
                  <Td style={{ textAlign: "right" }}>
                    <button
                      className="btn btn-ghost"
                      title={t("auth.users.resetPassword")}
                      onClick={() => setResetTarget(u)}
                      style={{ padding: 6, marginRight: 6 }}
                    >
                      <KeyRound size={15} />
                    </button>
                    <button
                      className="btn btn-ghost"
                      title={t("general.delete")}
                      disabled={isMe}
                      onClick={() => handleDelete(u)}
                      style={{ padding: 6 }}
                    >
                      <Trash2 size={15} />
                    </button>
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreated={async () => {
            setShowCreate(false);
            await reload();
          }}
        />
      )}

      {resetTarget && (
        <ResetPasswordModal
          target={resetTarget}
          onClose={() => setResetTarget(null)}
          onDone={async () => {
            setResetTarget(null);
            await reload();
          }}
        />
      )}
    </div>
  );
}

function CreateUserModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const { t } = useSettings();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("viewer");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (password.length < 8) {
      setError(t("auth.changePassword.tooShort"));
      return;
    }
    setBusy(true);
    try {
      await api.auth.createUser({ username, password, role });
      onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title={t("auth.users.add")} onClose={onClose}>
      <form onSubmit={submit}>
        <Label>{t("auth.username")}</Label>
        <input
          autoFocus
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
          style={inputStyle}
        />
        <Label>{t("auth.password")}</Label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          minLength={8}
          style={inputStyle}
        />
        <Label>{t("auth.users.role")}</Label>
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          <RoleButton
            active={role === "admin"}
            onClick={() => setRole("admin")}
            icon={<Shield size={14} />}
            label="admin"
          />
          <RoleButton
            active={role === "viewer"}
            onClick={() => setRole("viewer")}
            icon={<Eye size={14} />}
            label="viewer"
          />
        </div>
        {error && <FormError msg={error} />}
        <ModalButtons busy={busy} onClose={onClose} />
      </form>
    </ModalShell>
  );
}

function ResetPasswordModal({
  target,
  onClose,
  onDone,
}: {
  target: UserPublic;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useSettings();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (password.length < 8) {
      setError(t("auth.changePassword.tooShort"));
      return;
    }
    setBusy(true);
    try {
      await api.auth.updateUser(target.id, { password });
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title={`${t("auth.users.resetPassword")}: ${target.username}`} onClose={onClose}>
      <form onSubmit={submit}>
        <Label>{t("auth.changePassword.new")}</Label>
        <input
          autoFocus
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          minLength={8}
          style={inputStyle}
        />
        <p
          style={{
            fontSize: 12,
            color: "var(--text-muted)",
            marginTop: -4,
            marginBottom: 14,
          }}
        >
          {t("auth.users.resetNote")}
        </p>
        {error && <FormError msg={error} />}
        <ModalButtons busy={busy} onClose={onClose} />
      </form>
    </ModalShell>
  );
}

function ModalShell({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.5)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "100%",
          maxWidth: 400,
          background: "var(--bg-elevated)",
          border: "1px solid var(--border-subtle)",
          borderRadius: 12,
          padding: 24,
        }}
      >
        <h2
          style={{
            fontSize: 17,
            margin: "0 0 18px 0",
            color: "var(--text-primary)",
          }}
        >
          {title}
        </h2>
        {children}
      </div>
    </div>
  );
}

function ModalButtons({ busy, onClose }: { busy: boolean; onClose: () => void }) {
  const { t } = useSettings();
  return (
    <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
      <button
        type="button"
        onClick={onClose}
        style={{
          padding: "9px 14px",
          borderRadius: 8,
          border: "1px solid var(--border-subtle)",
          background: "transparent",
          color: "var(--text-primary)",
          fontSize: 13,
          cursor: "pointer",
        }}
      >
        {t("general.cancel")}
      </button>
      <button
        type="submit"
        disabled={busy}
        style={{
          padding: "9px 14px",
          borderRadius: 8,
          border: "1px solid var(--accent-primary)",
          background: "var(--accent-primary)",
          color: "#fff",
          fontSize: 13,
          fontWeight: 600,
          cursor: busy ? "not-allowed" : "pointer",
          opacity: busy ? 0.6 : 1,
        }}
      >
        {busy ? t("general.saving") : t("general.save")}
      </button>
    </div>
  );
}

function Th({ children, style }: { children: ReactNode; style?: CSSProperties }) {
  return (
    <th
      style={{
        textAlign: "left",
        padding: "11px 14px",
        fontSize: 11,
        color: "var(--text-muted)",
        textTransform: "uppercase",
        letterSpacing: 0.4,
        fontWeight: 600,
        ...style,
      }}
    >
      {children}
    </th>
  );
}

function Td({
  children,
  style,
  colSpan,
}: {
  children: ReactNode;
  style?: CSSProperties;
  colSpan?: number;
}) {
  return (
    <td colSpan={colSpan} style={{ padding: "12px 14px", fontSize: 13, ...style }}>
      {children}
    </td>
  );
}

function Label({ children }: { children: ReactNode }) {
  return (
    <label
      style={{
        display: "block",
        fontSize: 11,
        color: "var(--text-muted)",
        marginBottom: 6,
        textTransform: "uppercase",
        letterSpacing: 0.4,
      }}
    >
      {children}
    </label>
  );
}

function FormError({ msg }: { msg: string }) {
  return (
    <div
      style={{
        padding: "9px 12px",
        background: "rgba(239,68,68,0.08)",
        border: "1px solid rgba(239,68,68,0.25)",
        borderRadius: 8,
        color: "#ef4444",
        fontSize: 12,
        marginBottom: 12,
      }}
    >
      {msg}
    </div>
  );
}

function RoleButton({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: ReactNode;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        flex: 1,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 6,
        padding: "9px 12px",
        borderRadius: 8,
        border: `1px solid ${active ? "var(--accent-primary)" : "var(--border-subtle)"}`,
        background: active ? "rgba(59,130,246,0.08)" : "transparent",
        color: "var(--text-primary)",
        fontSize: 13,
        cursor: "pointer",
      }}
    >
      {icon}
      {label}
    </button>
  );
}

const inputStyle: CSSProperties = {
  width: "100%",
  padding: "10px 12px",
  borderRadius: 8,
  border: "1px solid var(--border-subtle)",
  background: "var(--bg-base)",
  color: "var(--text-primary)",
  fontSize: 14,
  outline: "none",
  marginBottom: 14,
};

const selectStyle: CSSProperties = {
  padding: "5px 8px",
  borderRadius: 6,
  border: "1px solid var(--border-subtle)",
  background: "var(--bg-base)",
  color: "var(--text-primary)",
  fontSize: 12,
};
