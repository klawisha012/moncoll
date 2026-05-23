import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";
import { api, type ProvidersResponse } from "../api/client";
import TurnstileWidget from "../components/TurnstileWidget";

const TENANT_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,38}[a-zA-Z0-9]$|^[a-zA-Z0-9]{3}$/;

export default function Signup() {
  const [searchParams] = useSearchParams();
  const { signup, oauthStart } = useAuth();
  const { t } = useSettings();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [captchaToken, setCaptchaToken] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [devVerifyUrl, setDevVerifyUrl] = useState<string | null>(null);
  const [providers, setProviders] = useState<ProvidersResponse | null>(null);

  useEffect(() => {
    api.auth.getProviders().then(setProviders).catch(() => null);
  }, []);

  // Surface OAuth callback errors (we redirect here with ?oauth_error=<code>).
  useEffect(() => {
    const code = searchParams.get("oauth_error");
    if (code) setError(t(`auth.oauth.err.${code}`) || code);
  }, [searchParams, t]);

  const handleToken = useCallback((token: string) => setCaptchaToken(token), []);

  const oauthSignup = (provider: "google" | "github") => {
    if (!providers?.[provider]) {
      setError(t("auth.oauth.notConfigured").replace("{provider}", provider));
      return;
    }
    // tenant_name is optional with OAuth — backend auto-derives a slug from
    // the provider profile. If the user typed one, we honour it; otherwise
    // pass undefined and let the backend pick.
    const wsName = TENANT_NAME_RE.test(tenantName) ? tenantName : undefined;
    oauthStart(provider, "signup", wsName);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!TENANT_NAME_RE.test(tenantName)) {
      setError(t("auth.signup.tenantNameHint"));
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      const resp = await signup(email, password, tenantName, captchaToken, displayName || undefined);
      if (resp.dev_verify_url) setDevVerifyUrl(resp.dev_verify_url);
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("general.error"));
    } finally {
      setSubmitting(false);
    }
  };

  const captchaReady = !providers || !!captchaToken;
  const canSubmit = email && password && tenantName && captchaReady;

  if (done) {
    return (
      <div className="cv-root">
        <style>{styles}</style>
        <section className="cv-manifest">
          <div className="cv-eyebrow">
            <span className="cv-n">✓</span>
            <span className="cv-eyebrow-text">{t("auth.signup.eyebrow")}</span>
          </div>
          <h1 className="cv-h1 cv-h1-sm">
            <span className="cv-stack">{t("auth.signup.checkEmail")}</span>
          </h1>
          <p className="cv-deck">{t("auth.signup.checkEmailDesc").replace("{email}", email)}</p>
          <div className="cv-disc" aria-hidden />
        </section>
        <section className="cv-form-side">
          <div className="cv-form">
            <div className="cv-form-head">
              <span className="cv-kicker">{t("auth.signup.kicker")}</span>
            </div>
            <p style={{ fontFamily: "'Inter Tight', sans-serif", fontSize: 15, color: "var(--ink)", lineHeight: 1.6 }}>
              {t("auth.signup.checkEmailDesc").replace("{email}", email)}
            </p>
            {devVerifyUrl && (
              <div className="cv-dev-banner">
                <span className="cv-dev-tag">{t("auth.dev.smtpOff")}</span>
                <a href={devVerifyUrl} className="cv-dev-link">{devVerifyUrl}</a>
              </div>
            )}
            <Link to="/login" className="cv-submit" style={{ textDecoration: "none", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>{t("auth.signup.haveAccount")}</span>
              <span className="cv-ar">→</span>
            </Link>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="cv-root">
      <style>{styles}</style>

      <section className="cv-manifest">
        <div className="cv-eyebrow">
          <span className="cv-n">03</span>
          <span className="cv-eyebrow-text">{t("auth.signup.eyebrow")}</span>
        </div>
        <h1 className="cv-h1">
          <span className="cv-stack">{t("auth.signup.heroLine1")}</span>
          <span className="cv-stack">
            <span className="cv-ws">{t("auth.signup.heroLine2")}</span>
          </span>
          <span className="cv-stack">
            <span className="cv-tilt">{t("auth.signup.heroLine3")}</span>
          </span>
        </h1>
        <p className="cv-deck">{t("auth.signup.quote")}</p>
        <div className="cv-disc" aria-hidden />
      </section>

      <section className="cv-form-side">
        <form onSubmit={submit} className="cv-form">
          <div className="cv-form-head">
            <span className="cv-kicker">{t("auth.signup.kicker")}</span>
            <Link to="/login" className="cv-switch-link">{t("auth.signup.haveAccount")}</Link>
          </div>

          {/* OAuth buttons — always visible. Disabled with hint when not configured. */}
          <div className="cv-oauth-row">
            <button
              type="button"
              className={`cv-oauth-btn ${providers?.google ? "" : "cv-oauth-btn-off"}`}
              onClick={() => oauthSignup("google")}
              title={providers?.google ? "Google" : t("auth.oauth.notConfigured").replace("{provider}", "Google")}
            >
              <span className="cv-oauth-icon">G</span>
              Google
              {providers && !providers.google && <span className="cv-oauth-off-tag">{t("auth.oauth.offTag")}</span>}
            </button>
            <button
              type="button"
              className={`cv-oauth-btn ${providers?.github ? "" : "cv-oauth-btn-off"}`}
              onClick={() => oauthSignup("github")}
              title={providers?.github ? "GitHub" : t("auth.oauth.notConfigured").replace("{provider}", "GitHub")}
            >
              <span className="cv-oauth-icon">⌥</span>
              GitHub
              {providers && !providers.github && <span className="cv-oauth-off-tag">{t("auth.oauth.offTag")}</span>}
            </button>
          </div>
          <div className="cv-divider"><span>{t("auth.login.orEmail")}</span></div>

          <div className="cv-field">
            <label htmlFor="cv-email">{t("auth.email")}</label>
            <div className="cv-inp">
              <span className="cv-tag">@</span>
              <input id="cv-email" type="email" value={email}
                onChange={(e) => setEmail(e.target.value)} autoFocus required autoComplete="email" />
            </div>
          </div>

          <div className="cv-field">
            <label htmlFor="cv-password">{t("auth.password")}</label>
            <div className="cv-inp">
              <span className="cv-tag">#</span>
              <input id="cv-password" type={showPassword ? "text" : "password"} value={password}
                onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password" />
              <button type="button" className="cv-reveal"
                onClick={() => setShowPassword((v) => !v)} tabIndex={-1}
                aria-label={showPassword ? t("auth.hidePassword") : t("auth.showPassword")}>
                {showPassword ? t("auth.hidePasswordShort") : t("auth.showPasswordShort")}
              </button>
            </div>
          </div>

          <div className="cv-field">
            <label htmlFor="cv-tenant">{t("auth.signup.tenantName")}</label>
            <div className="cv-inp">
              <span className="cv-tag">⬡</span>
              <input id="cv-tenant" type="text" value={tenantName}
                onChange={(e) => setTenantName(e.target.value)} required
                placeholder={t("auth.signup.tenantNameHint")} />
            </div>
          </div>

          <div className="cv-field">
            <label htmlFor="cv-display">{t("auth.signup.displayName")}</label>
            <div className="cv-inp">
              <span className="cv-tag">✎</span>
              <input id="cv-display" type="text" value={displayName}
                onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" />
            </div>
          </div>

          {providers?.captcha_site_key && (
            <div className="cv-captcha">
              <TurnstileWidget siteKey={providers.captcha_site_key} onToken={handleToken} />
              {providers.captcha_dev_mode && (
                <span className="cv-captcha-dev-tag">{t("auth.captcha.devMode")}</span>
              )}
            </div>
          )}

          {error && <div className="cv-error">{error}</div>}

          <button type="submit" className="cv-submit" disabled={submitting || !canSubmit}>
            <span>{submitting ? t("general.loading") : t("auth.signup.submit")}</span>
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
  height: 100vh; width: 100%;
  background: var(--cream); color: var(--ink);
  font-family: 'Inter Tight', system-ui, -apple-system, sans-serif;
  font-size: 15px; line-height: 1.45;
  display: grid; grid-template-columns: 1.25fr 1fr;
  overflow: auto;
  background-image: radial-gradient(rgba(0,0,0,0.05) 1px, transparent 1px);
  background-size: 4px 4px;
}
[data-theme="dark"] .cv-root {
  background-image: radial-gradient(rgba(241, 234, 216, 0.04) 1px, transparent 1px);
}
.cv-manifest {
  padding: 72px 64px; border-right: 3px solid var(--rule);
  position: relative; overflow: hidden;
  display: flex; flex-direction: column; justify-content: center;
}
.cv-disc {
  position: absolute; right: -110px; bottom: -110px;
  width: 340px; height: 340px;
  background: var(--red); border: 3px solid var(--rule); border-radius: 50%;
  pointer-events: none;
}
.cv-eyebrow { display: flex; align-items: center; gap: 16px; margin-bottom: 22px; position: relative; z-index: 1; }
.cv-n {
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: 22px; line-height: 1;
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
.cv-h1-sm { font-size: clamp(40px, 6vw, 80px); }
.cv-stack { display: block; }
.cv-ws { color: var(--red); }
.cv-tilt { display: inline-block; transform: rotate(-3deg); }
.cv-deck {
  font-family: 'Inter Tight', sans-serif; font-weight: 500;
  font-size: 17px; line-height: 1.5; max-width: 36ch;
  border-left: 4px solid var(--red); padding-left: 16px;
  margin: 0; position: relative; z-index: 1; color: var(--ink);
}
.cv-form-side {
  background: var(--cream); padding: 72px 64px;
  display: flex; flex-direction: column; justify-content: center;
}
.cv-form { display: flex; flex-direction: column; gap: 22px; max-width: 460px; }
.cv-form-head {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 16px; border-bottom: 3px solid var(--rule); padding-bottom: 14px; margin-bottom: 6px;
}
.cv-kicker {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 12px; letter-spacing: 0.28em; text-transform: uppercase; color: var(--red);
}
.cv-switch-link {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--ink); text-decoration: none;
}
.cv-switch-link:hover { color: var(--red); }
.cv-oauth-row { display: flex; gap: 12px; }
.cv-oauth-btn {
  flex: 1; border: 3px solid var(--rule); background: var(--cream); color: var(--ink);
  padding: 12px 16px; cursor: pointer;
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 13px; letter-spacing: 0.14em; text-transform: uppercase;
  display: flex; align-items: center; gap: 10px; transition: background 90ms;
}
.cv-oauth-btn:hover { background: var(--ink); color: var(--cream); }
.cv-oauth-icon { font-family: 'JetBrains Mono', monospace; font-size: 14px; font-weight: 700; }
.cv-divider { display: flex; align-items: center; gap: 12px; }
.cv-divider::before, .cv-divider::after { content: ''; flex: 1; height: 2px; background: var(--rule); }
.cv-divider span {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 10px; letter-spacing: 0.24em; text-transform: uppercase;
  color: var(--ink); opacity: 0.5;
}
.cv-field { display: flex; flex-direction: column; }
.cv-field label {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.24em; text-transform: uppercase;
  margin-bottom: 8px; color: var(--ink);
}
.cv-inp { border: 3px solid var(--rule); background: var(--cream); display: flex; align-items: stretch; }
.cv-inp:focus-within { outline: 3px solid var(--red); outline-offset: 3px; }
.cv-tag {
  background: var(--ink); color: var(--cream); padding: 0 14px;
  display: flex; align-items: center;
  font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 16px;
}
.cv-inp input {
  flex: 1; border: 0; background: transparent; outline: 0;
  padding: 14px 16px;
  font-family: 'Inter Tight', sans-serif; font-weight: 500; font-size: 16px;
  color: var(--ink); min-width: 0;
}
.cv-reveal {
  border: 0; border-left: 3px solid var(--rule); background: transparent; padding: 0 14px;
  display: flex; align-items: center;
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.18em; text-transform: uppercase;
  cursor: pointer; color: var(--ink);
}
.cv-reveal:hover { color: var(--red); }
.cv-captcha { display: flex; align-items: center; gap: 12px; justify-content: flex-start; }
.cv-captcha-dev-tag {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 10px; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--red);
  border: 2px solid var(--red);
  padding: 2px 6px;
}
.cv-oauth-btn-off {
  opacity: 0.55;
  cursor: not-allowed;
}
.cv-oauth-btn-off:hover { background: var(--cream); color: var(--ink); }
.cv-oauth-off-tag {
  margin-left: auto;
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 9px; letter-spacing: 0.2em; text-transform: uppercase;
  color: var(--red);
}
.cv-dev-banner {
  border: 3px dashed var(--red);
  padding: 14px 16px;
  display: flex; flex-direction: column; gap: 6px;
  background: rgba(214, 54, 42, 0.04);
}
.cv-dev-tag {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--red);
}
.cv-dev-link {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--ink);
  word-break: break-all;
  text-decoration: underline;
}
.cv-dev-link:hover { color: var(--red); }
.cv-error {
  border: 3px solid var(--red); background: rgba(214, 54, 42, 0.08);
  padding: 12px 16px;
  font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--red);
}
.cv-submit {
  background: var(--red); color: var(--cream); border: 3px solid var(--rule);
  padding: 18px 24px; cursor: pointer;
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: 22px; letter-spacing: 0.02em; text-transform: uppercase;
  display: flex; justify-content: space-between; align-items: center;
  box-shadow: 6px 6px 0 var(--rule); transition: transform 90ms, box-shadow 90ms;
  margin-top: 8px;
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
