import { useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useSettings } from "../context/SettingsContext";
import { api } from "../api/client";

export default function ResetPassword() {
  const { t } = useSettings();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.auth.resetPassword(token, password);
      setSuccess(true);
      setTimeout(() => navigate("/login", { replace: true }), 2000);
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
          <span className="cv-n">05</span>
          <span className="cv-eyebrow-text">{t("auth.reset.eyebrow")}</span>
        </div>
        <h1 className="cv-h1">
          <span className="cv-stack">{t("auth.reset.heroLine1")}</span>
          <span className="cv-stack"><span className="cv-ws">{t("auth.reset.heroLine2")}</span></span>
          <span className="cv-stack"><span className="cv-tilt">{t("auth.reset.heroLine3")}</span></span>
        </h1>
        <p className="cv-deck">{t("auth.reset.quote")}</p>
        <div className="cv-disc" aria-hidden />
      </section>

      <section className="cv-form-side">
        <form onSubmit={submit} className="cv-form">
          <div className="cv-form-head">
            <span className="cv-kicker">{t("auth.reset.kicker")}</span>
          </div>

          {success ? (
            <div className="cv-success">{t("auth.reset.success")}</div>
          ) : (
            <>
              <div className="cv-field">
                <label htmlFor="cv-password">{t("auth.reset.newPassword")}</label>
                <div className="cv-inp">
                  <span className="cv-tag">#</span>
                  <input
                    id="cv-password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoFocus required minLength={8}
                    autoComplete="new-password"
                  />
                  <button type="button" className="cv-reveal"
                    onClick={() => setShowPassword((v) => !v)} tabIndex={-1}
                    aria-label={showPassword ? t("auth.hidePassword") : t("auth.showPassword")}>
                    {showPassword ? t("auth.hidePasswordShort") : t("auth.showPasswordShort")}
                  </button>
                </div>
              </div>

              {error && <div className="cv-error">{error}</div>}

              <button type="submit" className="cv-submit" disabled={submitting || !password || !token}>
                <span>{submitting ? t("general.loading") : t("auth.reset.submit")}</span>
                <span className="cv-ar">→</span>
              </button>
            </>
          )}
        </form>
      </section>
    </div>
  );
}

const styles = `
.cv-root {
  --rule: var(--ink);
  height: 100vh; width: 100%;
  background: var(--cream); color: var(--ink);
  font-family: 'Inter Tight', system-ui, -apple-system, sans-serif;
  font-size: 15px; line-height: 1.45;
  display: grid; grid-template-columns: 1.25fr 1fr; overflow: auto;
  background-image: radial-gradient(rgba(0,0,0,0.05) 1px, transparent 1px);
  background-size: 4px 4px;
}
[data-theme="dark"] .cv-root { background-image: radial-gradient(rgba(241, 234, 216, 0.04) 1px, transparent 1px); }
.cv-manifest {
  padding: 72px 64px; border-right: 3px solid var(--rule);
  position: relative; overflow: hidden;
  display: flex; flex-direction: column; justify-content: center;
}
.cv-disc {
  position: absolute; right: -110px; bottom: -110px;
  width: 340px; height: 340px;
  background: var(--red); border: 3px solid var(--rule); border-radius: 50%; pointer-events: none;
}
.cv-eyebrow { display: flex; align-items: center; gap: 16px; margin-bottom: 22px; position: relative; z-index: 1; }
.cv-n {
  font-family: 'Unbounded', sans-serif; font-weight: 900; font-size: 22px; line-height: 1;
  background: var(--red); color: var(--cream); padding: 4px 10px 6px;
  transform: rotate(-2deg); display: inline-block;
}
.cv-eyebrow-text {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 13px; letter-spacing: 0.28em; text-transform: uppercase; color: var(--ink);
}
.cv-h1 {
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: clamp(64px, 8vw, 124px); line-height: 0.86;
  letter-spacing: -0.05em; text-transform: uppercase;
  margin: 0 0 32px; position: relative; z-index: 1; color: var(--ink);
}
.cv-stack { display: block; }
.cv-ws { color: var(--red); }
.cv-tilt { display: inline-block; transform: rotate(-3deg); }
.cv-deck {
  font-family: 'Inter Tight', sans-serif; font-weight: 500;
  font-size: 17px; line-height: 1.5; max-width: 36ch;
  border-left: 4px solid var(--red); padding-left: 16px;
  margin: 0; position: relative; z-index: 1; color: var(--ink);
}
.cv-form-side { background: var(--cream); padding: 72px 64px; display: flex; flex-direction: column; justify-content: center; }
.cv-form { display: flex; flex-direction: column; gap: 22px; max-width: 460px; }
.cv-form-head {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 16px; border-bottom: 3px solid var(--rule); padding-bottom: 14px; margin-bottom: 6px;
}
.cv-kicker {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 12px; letter-spacing: 0.28em; text-transform: uppercase; color: var(--red);
}
.cv-field { display: flex; flex-direction: column; }
.cv-field label {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.24em; text-transform: uppercase; margin-bottom: 8px; color: var(--ink);
}
.cv-inp { border: 3px solid var(--rule); background: var(--cream); display: flex; align-items: stretch; }
.cv-inp:focus-within { outline: 3px solid var(--red); outline-offset: 3px; }
.cv-tag {
  background: var(--ink); color: var(--cream); padding: 0 14px;
  display: flex; align-items: center;
  font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 16px;
}
.cv-inp input {
  flex: 1; border: 0; background: transparent; outline: 0; padding: 14px 16px;
  font-family: 'Inter Tight', sans-serif; font-weight: 500; font-size: 16px; color: var(--ink); min-width: 0;
}
.cv-reveal {
  border: 0; border-left: 3px solid var(--rule); background: transparent; padding: 0 14px;
  display: flex; align-items: center;
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.18em; text-transform: uppercase; cursor: pointer; color: var(--ink);
}
.cv-reveal:hover { color: var(--red); }
.cv-success {
  border: 3px solid var(--ok, #2c7a3d); background: rgba(44, 122, 61, 0.08); padding: 12px 16px;
  font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--ok, #2c7a3d);
}
.cv-error {
  border: 3px solid var(--red); background: rgba(214, 54, 42, 0.08); padding: 12px 16px;
  font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--red);
}
.cv-submit {
  background: var(--red); color: var(--cream); border: 3px solid var(--rule);
  padding: 18px 24px; cursor: pointer;
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: 22px; letter-spacing: 0.02em; text-transform: uppercase;
  display: flex; justify-content: space-between; align-items: center;
  box-shadow: 6px 6px 0 var(--rule); transition: transform 90ms, box-shadow 90ms; margin-top: 8px;
}
.cv-submit:hover:not(:disabled) { transform: translate(-3px, -3px); box-shadow: 9px 9px 0 var(--rule); }
.cv-submit:disabled { opacity: 0.45; cursor: not-allowed; box-shadow: 3px 3px 0 var(--rule); transform: none; }
.cv-ar { font-family: 'JetBrains Mono', monospace; font-size: 22px; }
@media (max-width: 960px) {
  .cv-root { grid-template-columns: 1fr; height: auto; min-height: 100vh; }
  .cv-manifest { border-right: 0; border-bottom: 3px solid var(--rule); padding: 48px 32px; }
  .cv-form-side { padding: 48px 32px; }
  .cv-h1 { font-size: clamp(48px, 14vw, 84px); }
}
`;
