import { useState, type FormEvent, type CSSProperties } from "react";
import { useNavigate } from "react-router-dom";
import { Eye, EyeOff, Lock, User as UserIcon } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const { t, theme } = useSettings();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const user = await login(username, password);
      navigate(user.must_change_password ? "/change-password" : "/dashboard", {
        replace: true,
      });
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
        padding: "20px",
      }}
    >
      <form
        onSubmit={submit}
        style={{
          width: "100%",
          maxWidth: 380,
          background: "var(--bg-elevated)",
          border: "1px solid var(--border-subtle)",
          borderRadius: 14,
          padding: 28,
          boxShadow:
            theme === "dark"
              ? "0 10px 40px rgba(0,0,0,0.4)"
              : "0 10px 40px rgba(0,0,0,0.1)",
        }}
      >
        <div style={{ marginBottom: 22 }}>
          <h1 style={{ fontSize: 22, margin: 0, color: "var(--text-primary)" }}>
            {t("auth.login.title")}
          </h1>
          <p style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 6 }}>
            {t("auth.login.subtitle")}
          </p>
        </div>

        <div
          style={{
            padding: "10px 14px",
            background: "rgba(99,102,241,0.08)",
            border: "1px solid rgba(99,102,241,0.2)",
            borderRadius: 8,
            marginBottom: 20,
            fontSize: 13,
            color: "var(--text-secondary)",
            lineHeight: 1.5,
          }}
        >
          <strong style={{ color: "var(--accent-1)" }}>
            {t("auth.login.defaultCredentials")}
          </strong>
          <br />
          admin&nbsp;&nbsp;/&nbsp;&nbsp;admin
        </div>

        <label style={fieldLabel}>{t("auth.username")}</label>
        <div style={fieldWrap}>
          <UserIcon size={15} style={fieldIcon} />
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
            required
            autoComplete="username"
            style={fieldInput}
          />
        </div>

        <label style={fieldLabel}>{t("auth.password")}</label>
        <div style={fieldWrap}>
          <Lock size={15} style={fieldIcon} />
          <input
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
            style={{ ...fieldInput, paddingRight: 40 }}
          />
          <button
            type="button"
            onClick={() => setShowPassword((v) => !v)}
            tabIndex={-1}
            aria-label={showPassword ? "Hide password" : "Show password"}
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
            {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
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
              marginBottom: 14,
            }}
          >
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={submitting || !username || !password}
          style={{
            width: "100%",
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
          {submitting ? t("general.loading") : t("auth.login.submit")}
        </button>
      </form>
    </div>
  );
}

const fieldLabel: CSSProperties = {
  display: "block",
  fontSize: 12,
  color: "var(--text-muted)",
  marginBottom: 6,
  textTransform: "uppercase",
  letterSpacing: 0.4,
};

const fieldWrap: CSSProperties = {
  position: "relative",
  marginBottom: 16,
};

const fieldIcon: CSSProperties = {
  position: "absolute",
  left: 12,
  top: "50%",
  transform: "translateY(-50%)",
  color: "var(--text-muted)",
};

const fieldInput: CSSProperties = {
  width: "100%",
  padding: "10px 12px 10px 36px",
  borderRadius: 8,
  border: "1px solid var(--border-subtle)",
  background: "var(--bg-base)",
  color: "var(--text-primary)",
  fontSize: 14,
  outline: "none",
};
