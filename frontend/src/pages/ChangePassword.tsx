import { useState, type FormEvent, type CSSProperties } from "react";
import { useNavigate } from "react-router-dom";
import { Eye, EyeOff, Lock } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";

export default function ChangePassword() {
  const navigate = useNavigate();
  const { user, changePassword } = useAuth();
  const { t } = useSettings();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNext, setShowNext] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const forced = !!user?.must_change_password;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (next.length < 8) {
      setError(t("auth.changePassword.tooShort"));
      return;
    }
    if (next !== confirm) {
      setError(t("auth.changePassword.mismatch"));
      return;
    }
    setSubmitting(true);
    try {
      // On first login the current password is always the default "admin"
      await changePassword(forced ? "admin" : current, next);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : t("general.error"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        width: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "var(--bg-base)",
        padding: 20,
      }}
    >
      <form
        onSubmit={submit}
        style={{
          width: "100%",
          maxWidth: 420,
          background: "var(--bg-elevated)",
          border: "1px solid var(--border-subtle)",
          borderRadius: 14,
          padding: 28,
        }}
      >
        <h1 style={{ fontSize: 22, margin: 0, color: "var(--text-primary)" }}>
          {t("auth.changePassword.title")}
        </h1>
        <p
          style={{
            fontSize: 13,
            color: "var(--text-muted)",
            marginTop: 6,
            marginBottom: 22,
          }}
        >
          {forced ? t("auth.changePassword.forced") : t("auth.changePassword.subtitle")}
        </p>

        {!forced && (
          <Field label={t("auth.changePassword.current")} value={current} onChange={setCurrent} show={showCurrent} onToggleShow={() => setShowCurrent((v) => !v)} />
        )}
        <Field label={t("auth.changePassword.new")} value={next} onChange={setNext} show={showNext} onToggleShow={() => setShowNext((v) => !v)} />
        <Field label={t("auth.changePassword.confirm")} value={confirm} onChange={setConfirm} show={showConfirm} onToggleShow={() => setShowConfirm((v) => !v)} />

        {error && (
          <div
            style={{
              padding: "10px 12px",
              background: "rgba(239,68,68,0.08)",
              border: "1px solid rgba(239,68,68,0.25)",
              borderRadius: 8,
              color: "#ef4444",
              fontSize: 13,
              marginBottom: 14,
            }}
          >
            {error}
          </div>
        )}

        <div style={{ display: "flex", gap: 10 }}>
          <button
            type="submit"
            disabled={submitting || (!forced && !current) || !next || !confirm}
            style={{
              flex: 1,
              padding: "11px 14px",
              borderRadius: 8,
              border: "1px solid var(--accent-primary)",
              background: "var(--accent-primary)",
              color: "#fff",
              fontSize: 14,
              fontWeight: 600,
              cursor: submitting ? "not-allowed" : "pointer",
              opacity: submitting ? 0.6 : 1,
            }}
          >
            {submitting ? t("general.saving") : t("general.save")}
          </button>
        </div>
      </form>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  show,
  onToggleShow,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  show: boolean;
  onToggleShow: () => void;
}) {
  const { t } = useSettings();
  return (
    <div style={{ marginBottom: 14 }}>
      <label
        style={{
          display: "block",
          fontSize: 12,
          color: "var(--text-muted)",
          marginBottom: 6,
          textTransform: "uppercase",
          letterSpacing: 0.4,
        }}
      >
        {label}
      </label>
      <div style={{ position: "relative" }}>
        <Lock
          size={15}
          style={{
            position: "absolute",
            left: 12,
            top: "50%",
            transform: "translateY(-50%)",
            color: "var(--text-muted)",
          }}
        />
        <input
          type={show ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          required
          style={{ ...inputStyle, paddingRight: 40 }}
        />
        <button
          type="button"
          onClick={onToggleShow}
          tabIndex={-1}
          aria-label={show ? t("auth.hidePassword") : t("auth.showPassword")}
          style={{
            position: "absolute",
            right: 8,
            top: "50%",
            transform: "translateY(-50%)",
            background: "none",
            border: "none",
            color: "var(--text-muted)",
            cursor: "pointer",
            padding: 4,
            display: "flex",
            alignItems: "center",
          }}
        >
          {show ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </div>
    </div>
  );
}

const inputStyle: CSSProperties = {
  width: "100%",
  padding: "10px 12px 10px 36px",
  borderRadius: 8,
  border: "1px solid var(--border-subtle)",
  background: "var(--bg-base)",
  color: "var(--text-primary)",
  fontSize: 14,
  outline: "none",
};
