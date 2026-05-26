import { createSignal, createEffect } from "solid-js";
import { Show } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import { useSettings } from "../context/SettingsContext";
import { api } from "../api/client";

export default function VerifyEmail() {
  const settings = useSettings();
  const [params] = useSearchParams();
  const token = () => params.token ?? "";

  const [status, setStatus] = createSignal<"loading" | "success" | "error">("loading");
  const [message, setMessage] = createSignal("");

  createEffect(() => {
    const tok = token();
    if (!tok) {
      setStatus("error");
      setMessage("Missing token");
      return;
    }
    api.auth.verifyEmail(tok)
      .then(() => setStatus("success"))
      .catch((err: Error) => {
        setStatus("error");
        setMessage(err.message);
      });
  });

  const isSuccess = () => status() === "success";
  const title = () => status() === "loading"
    ? settings.t("auth.verifyEmail.verifying")
    : isSuccess()
      ? settings.t("auth.verifyEmail.success")
      : settings.t("auth.verifyEmail.error");

  return (
    <div class="cv-root">
      <style>{styles}</style>
      <section class="cv-manifest">
        <div class="cv-eyebrow">
          <span class="cv-n">
            <Show when={status() === "loading"} fallback={isSuccess() ? "✓" : "✕"}>
              …
            </Show>
          </span>
          <span class="cv-eyebrow-text">— Email</span>
        </div>
        <h1 class="cv-h1 cv-h1-sm">
          <span class="cv-stack">{title()}</span>
        </h1>
        <Show when={isSuccess()}>
          <p class="cv-deck">{settings.t("auth.verifyEmail.successDesc")}</p>
        </Show>
        <Show when={status() === "error"}>
          <p class="cv-deck" style={{ "border-left-color": "var(--red)" }}>{message()}</p>
        </Show>
        <div class="cv-disc" aria-hidden />
      </section>

      <section class="cv-form-side">
        <div class="cv-form">
          <div class="cv-form-head">
            <span class="cv-kicker">№ 07 / email verification</span>
          </div>
          <Show when={status() === "loading"}>
            <p class="cv-body">{settings.t("auth.verifyEmail.verifying")}</p>
          </Show>
          <Show when={isSuccess()}>
            <p class="cv-body">{settings.t("auth.verifyEmail.successDesc")}</p>
            <A href="/login" class="cv-submit" style={{ "text-decoration": "none", "display": "flex", "justify-content": "space-between", "align-items": "center" }}>
              <span>{settings.t("auth.verifyEmail.toLogin")}</span>
              <span class="cv-ar">→</span>
            </A>
          </Show>
          <Show when={status() === "error"}>
            <p class="cv-body cv-body-err">{message() || settings.t("auth.verifyEmail.error")}</p>
            <A href="/login" class="cv-submit cv-submit-alt" style={{ "text-decoration": "none", "display": "flex", "justify-content": "space-between", "align-items": "center" }}>
              <span>{settings.t("auth.verifyEmail.toLogin")}</span>
              <span class="cv-ar">→</span>
            </A>
          </Show>
        </div>
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
.cv-h1-sm { font-size: clamp(36px, 5vw, 72px); }
.cv-stack { display: block; }
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
.cv-body { font-family: 'Inter Tight', sans-serif; font-size: 15px; color: var(--ink); line-height: 1.6; margin: 0; }
.cv-body-err { color: var(--red); }
.cv-submit {
  background: var(--red); color: var(--cream); border: 3px solid var(--rule);
  padding: 18px 24px; cursor: pointer;
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: 22px; letter-spacing: 0.02em; text-transform: uppercase;
  display: flex; justify-content: space-between; align-items: center;
  box-shadow: 6px 6px 0 var(--rule); transition: transform 90ms, box-shadow 90ms; margin-top: 8px;
}
.cv-submit:hover { transform: translate(-3px, -3px); box-shadow: 9px 9px 0 var(--rule); }
.cv-submit-alt { background: var(--ink); }
.cv-ar { font-family: 'JetBrains Mono', monospace; font-size: 22px; }
@media (max-width: 960px) {
  .cv-root { grid-template-columns: 1fr; height: auto; min-height: 100vh; }
  .cv-manifest { border-right: 0; border-bottom: 3px solid var(--rule); padding: 48px 32px; }
  .cv-form-side { padding: 48px 32px; }
  .cv-h1 { font-size: clamp(32px, 12vw, 64px); }
}
`;
