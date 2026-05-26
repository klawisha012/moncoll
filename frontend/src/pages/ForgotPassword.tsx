import { createSignal, onMount } from "solid-js";
import { Show } from "solid-js";
import { A } from "@solidjs/router";
import { useSettings } from "../context/SettingsContext";
import { api, type ProvidersResponse } from "../api/client";
import TurnstileWidget from "../components/TurnstileWidget";

export default function ForgotPassword() {
  const settings = useSettings();
  const [email, setEmail] = createSignal("");
  const [captchaToken, setCaptchaToken] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [sent, setSent] = createSignal(false);
  const [devResetUrl, setDevResetUrl] = createSignal<string | null>(null);
  const [providers, setProviders] = createSignal<ProvidersResponse | null>(null);

  onMount(() => {
    api.auth.getProviders().then((data) => setProviders(() => data)).catch(() => null);
  });

  const handleToken = (token: string) => setCaptchaToken(token);

  const submit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const resp = await api.auth.forgotPassword(email(), captchaToken());
      if (resp.dev_reset_url) setDevResetUrl(resp.dev_reset_url);
      setSent(true);
    } catch (err) {
      setError(() => err instanceof Error ? err.message : settings.t("general.error"));
    } finally {
      setSubmitting(false);
    }
  };

  const captchaReady = () => !providers() || !providers()?.captcha_site_key || !!captchaToken();
  const canSubmit = () => email() && captchaReady();

  return (
    <div class="cv-root">
      <style>{styles}</style>

      <section class="cv-manifest">
        <div class="cv-eyebrow">
          <span class="cv-n">04</span>
          <span class="cv-eyebrow-text">{settings.t("auth.forgot.eyebrow")}</span>
        </div>
        <h1 class="cv-h1">
          <span class="cv-stack">{settings.t("auth.forgot.heroLine1")}</span>
          <span class="cv-stack"><span class="cv-ws">{settings.t("auth.forgot.heroLine2")}</span></span>
          <span class="cv-stack"><span class="cv-tilt">{settings.t("auth.forgot.heroLine3")}</span></span>
        </h1>
        <p class="cv-deck">{settings.t("auth.forgot.quote")}</p>
        <div class="cv-disc" aria-hidden />
      </section>

      <section class="cv-form-side">
        <Show
          when={sent()}
          fallback={
            <form onSubmit={submit} class="cv-form">
              <div class="cv-form-head">
                <span class="cv-kicker">{settings.t("auth.forgot.kicker")}</span>
                <A href="/login" class="cv-switch-link">{settings.t("auth.forgot.backToLogin")}</A>
              </div>

              <div class="cv-field">
                <label for="cv-email">{settings.t("auth.email")}</label>
                <div class="cv-inp">
                  <span class="cv-tag">@</span>
                  <input id="cv-email" type="email" value={email()}
                    onInput={(e) => setEmail(e.currentTarget.value)}
                    autofocus required autocomplete="email" />
                </div>
              </div>

              <Show when={providers()?.captcha_site_key}>
                {(siteKey) => (
                  <div class="cv-captcha">
                    <TurnstileWidget siteKey={siteKey()} onToken={handleToken} />
                    <Show when={providers()?.captcha_dev_mode}>
                      <span class="cv-captcha-dev-tag">{settings.t("auth.captcha.devMode")}</span>
                    </Show>
                  </div>
                )}
              </Show>

              <Show when={error()}>
                <div class="cv-error">{error()}</div>
              </Show>

              <button type="submit" class="cv-submit" disabled={submitting() || !canSubmit()}>
                <span>{submitting() ? settings.t("general.loading") : settings.t("auth.forgot.submit")}</span>
                <span class="cv-ar">→</span>
              </button>
            </form>
          }
        >
          <div class="cv-form">
            <div class="cv-form-head">
              <span class="cv-kicker">{settings.t("auth.forgot.kicker")}</span>
            </div>
            <p class="cv-body">{settings.t("auth.forgot.sentDesc")}</p>
            <Show when={devResetUrl()}>
              <div class="cv-dev-banner">
                <span class="cv-dev-tag">{settings.t("auth.dev.smtpOff")}</span>
                <a href={devResetUrl() ?? undefined} class="cv-dev-link">{devResetUrl()}</a>
              </div>
            </Show>
            <A href="/login" class="cv-submit" style={{ "text-decoration": "none", "display": "flex", "justify-content": "space-between", "align-items": "center" }}>
              <span>{settings.t("auth.forgot.backToLogin")}</span>
              <span class="cv-ar">→</span>
            </A>
          </div>
        </Show>
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
.cv-switch-link {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--ink); text-decoration: none;
}
.cv-switch-link:hover { color: var(--red); }
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
.cv-captcha { display: flex; align-items: center; gap: 12px; justify-content: flex-start; }
.cv-captcha-dev-tag {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 10px; letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--red); border: 2px solid var(--red); padding: 2px 6px;
}
.cv-dev-banner {
  border: 3px dashed var(--red); padding: 14px 16px;
  display: flex; flex-direction: column; gap: 6px;
  background: rgba(214, 54, 42, 0.04);
}
.cv-dev-tag {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.22em; text-transform: uppercase; color: var(--red);
}
.cv-dev-link {
  font-family: 'JetBrains Mono', monospace; font-size: 12px;
  color: var(--ink); word-break: break-all; text-decoration: underline;
}
.cv-dev-link:hover { color: var(--red); }
.cv-body { font-family: 'Inter Tight', sans-serif; font-size: 15px; color: var(--ink); line-height: 1.6; margin: 0; }
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
