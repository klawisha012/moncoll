import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const { t } = useSettings();
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
    <div className="cv-root">
      <style>{styles}</style>

      <section className="cv-manifest">
        <div className="cv-eyebrow">
          <span className="cv-n">01</span>
          <span className="cv-eyebrow-text">— Authentication</span>
        </div>
        <h1 className="cv-h1">
          <span className="cv-stack">Вход</span>
          <span className="cv-stack">
            <span className="cv-ws">в систему</span>
          </span>
          <span className="cv-stack">
            <span className="cv-tilt">контроля.</span>
          </span>
        </h1>
        <p className="cv-deck">
          «Безопасность — это не продукт, а процесс.
          Каждый запрос — повод для выбора.»
        </p>
        <div className="cv-disc" aria-hidden />
      </section>

      <section className="cv-form-side">
        <form onSubmit={submit} className="cv-form">
          <div className="cv-form-head">
            <span className="cv-kicker">№ 02 / форма авторизации</span>
            <span className="cv-creds-hint">
              <span className="cv-creds-lab">Дефолт</span>
              admin&nbsp;·&nbsp;admin
            </span>
          </div>

          <div className="cv-field">
            <label htmlFor="cv-username">{t("auth.username")}</label>
            <div className="cv-inp">
              <span className="cv-tag">@</span>
              <input
                id="cv-username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoFocus
                required
                autoComplete="username"
              />
            </div>
          </div>

          <div className="cv-field">
            <label htmlFor="cv-password">{t("auth.password")}</label>
            <div className="cv-inp">
              <span className="cv-tag">#</span>
              <input
                id="cv-password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
              />
              <button
                type="button"
                className="cv-reveal"
                onClick={() => setShowPassword((v) => !v)}
                tabIndex={-1}
                aria-label={showPassword ? "Скрыть пароль" : "Показать пароль"}
              >
                {showPassword ? "скрыть" : "показ"}
              </button>
            </div>
          </div>

          {error && <div className="cv-error">{error}</div>}

          <button
            type="submit"
            className="cv-submit"
            disabled={submitting || !username || !password}
          >
            <span>{submitting ? t("general.loading") : t("auth.login.submit")}</span>
            <span className="cv-ar">→</span>
          </button>
        </form>
      </section>
    </div>
  );
}

const styles = `
.cv-root {
  --rule: var(--ink);
  height: 100vh;
  width: 100%;
  background: var(--cream);
  color: var(--ink);
  font-family: 'Inter Tight', system-ui, -apple-system, sans-serif;
  font-size: 15px;
  line-height: 1.45;
  display: grid;
  grid-template-columns: 1.25fr 1fr;
  overflow: auto;
  background-image: radial-gradient(rgba(0,0,0,0.05) 1px, transparent 1px);
  background-size: 4px 4px;
}
[data-theme="dark"] .cv-root {
  background-image: radial-gradient(rgba(241, 234, 216, 0.04) 1px, transparent 1px);
}

.cv-manifest {
  padding: 72px 64px;
  border-right: 3px solid var(--rule);
  position: relative;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  justify-content: center;
}
.cv-disc {
  position: absolute;
  right: -110px; bottom: -110px;
  width: 340px; height: 340px;
  background: var(--red);
  border: 3px solid var(--rule);
  border-radius: 50%;
  pointer-events: none;
}

.cv-eyebrow {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 22px;
  position: relative;
  z-index: 1;
}
.cv-n {
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: 22px; line-height: 1;
  background: var(--red); color: var(--cream); padding: 4px 10px 6px;
  transform: rotate(-2deg);
  display: inline-block;
}
.cv-eyebrow-text {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 13px; letter-spacing: 0.28em; text-transform: uppercase;
  color: var(--ink);
}

.cv-h1 {
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: clamp(64px, 8vw, 124px);
  line-height: 0.86;
  letter-spacing: -0.05em;
  text-transform: uppercase;
  margin: 0 0 32px;
  position: relative;
  z-index: 1;
  color: var(--ink);
}
.cv-stack { display: block; }
.cv-ws { color: var(--red); }
.cv-tilt { display: inline-block; transform: rotate(-3deg); }

.cv-deck {
  font-family: 'Inter Tight', sans-serif; font-weight: 500;
  font-size: 17px; line-height: 1.5;
  max-width: 36ch;
  border-left: 4px solid var(--red);
  padding-left: 16px;
  margin: 0;
  position: relative; z-index: 1;
  color: var(--ink);
}

.cv-form-side {
  background: var(--cream);
  padding: 72px 64px;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.cv-form { display: flex; flex-direction: column; gap: 22px; max-width: 460px; }

.cv-form-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 16px;
  border-bottom: 3px solid var(--rule);
  padding-bottom: 14px;
  margin-bottom: 6px;
}
.cv-kicker {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 12px; letter-spacing: 0.28em; text-transform: uppercase;
  color: var(--red);
}
.cv-creds-hint {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--ink);
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.cv-creds-lab {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 10px; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--ink);
  opacity: 0.55;
}

.cv-field { display: flex; flex-direction: column; }
.cv-field label {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.24em; text-transform: uppercase;
  margin-bottom: 8px;
  color: var(--ink);
}
.cv-inp {
  border: 3px solid var(--rule);
  background: var(--cream);
  display: flex;
  align-items: stretch;
}
.cv-inp:focus-within {
  outline: 3px solid var(--red);
  outline-offset: 3px;
}
.cv-tag {
  background: var(--ink); color: var(--cream);
  padding: 0 14px;
  display: flex; align-items: center;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 700;
  font-size: 16px;
}
.cv-inp input {
  flex: 1;
  border: 0;
  background: transparent;
  outline: 0;
  padding: 14px 16px;
  font-family: 'Inter Tight', sans-serif;
  font-weight: 500;
  font-size: 16px;
  color: var(--ink);
  min-width: 0;
}
.cv-reveal {
  border: 0;
  border-left: 3px solid var(--rule);
  background: transparent;
  padding: 0 14px;
  display: flex; align-items: center;
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.18em; text-transform: uppercase;
  cursor: pointer;
  color: var(--ink);
}
.cv-reveal:hover { color: var(--red); }

.cv-error {
  border: 3px solid var(--red);
  background: rgba(214, 54, 42, 0.08);
  padding: 12px 16px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  color: var(--red);
}

.cv-submit {
  background: var(--red);
  color: var(--cream);
  border: 3px solid var(--rule);
  padding: 18px 24px;
  cursor: pointer;
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: 22px;
  letter-spacing: 0.02em;
  text-transform: uppercase;
  display: flex;
  justify-content: space-between;
  align-items: center;
  box-shadow: 6px 6px 0 var(--rule);
  transition: transform 90ms, box-shadow 90ms;
  margin-top: 8px;
}
.cv-submit:hover:not(:disabled) {
  transform: translate(-3px, -3px);
  box-shadow: 9px 9px 0 var(--rule);
}
.cv-submit:disabled {
  opacity: 0.45;
  cursor: not-allowed;
  box-shadow: 3px 3px 0 var(--rule);
  transform: none;
}
.cv-ar {
  font-family: 'JetBrains Mono', monospace;
  font-size: 22px;
}

@media (max-width: 960px) {
  .cv-root { grid-template-columns: 1fr; height: auto; min-height: 100vh; }
  .cv-manifest { border-right: 0; border-bottom: 3px solid var(--rule); padding: 48px 32px; }
  .cv-form-side { padding: 48px 32px; }
  .cv-h1 { font-size: clamp(48px, 14vw, 84px); }
}
`;
