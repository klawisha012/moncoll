import { createSignal, createEffect, Show } from "solid-js";
import { useSearchParams, useNavigate, A } from "@solidjs/router";
import { api, type InvitationPreview } from "../api/client";
import { useSettings } from "../context/SettingsContext";
import { useAuth } from "../context/AuthContext";

type Status = "loading" | "ready" | "accepting" | "accepted" | "error";

export default function InviteAccept() {
  const settings = useSettings();
  const auth = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const t = settings.t;
  const token = () => params.token ?? "";

  const [status, setStatus] = createSignal<Status>("loading");
  const [preview, setPreview] = createSignal<InvitationPreview | null>(null);
  const [errKey, setErrKey] = createSignal("invite.accept.err");

  // Resolve the token to its team/role/email before asking the user to do
  // anything — the page can then show exactly what they're joining.
  createEffect(() => {
    const tok = token();
    if (!tok) { setErrKey("invite.accept.err"); setStatus("error"); return; }
    setStatus("loading");
    api.teams
      .previewInvite(tok)
      .then((p) => {
        if (!p.valid) { setErrKey("invite.accept.err"); setStatus("error"); return; }
        setPreview(p);
        setStatus("ready");
      })
      .catch(() => { setErrKey("invite.accept.err"); setStatus("error"); });
  });

  const role = () => preview()?.role ?? "member";
  const roleLabel = () => t(`team.role.${role()}`);
  const teamName = () => preview()?.team_name ?? "";
  const invitedEmail = () => preview()?.email ?? "";
  const emailMatches = () =>
    !!auth.user && auth.user.email.toLowerCase() === invitedEmail().toLowerCase();

  const accept = () => {
    setStatus("accepting");
    api.teams
      .acceptInvite(token())
      .then(() => setStatus("accepted"))
      .catch((e) => {
        const msg = e instanceof Error ? e.message.toLowerCase() : "";
        setErrKey(msg.includes("different email") ? "invite.accept.errEmail" : "invite.accept.err");
        setStatus("error");
      });
  };

  const switchAccount = async () => {
    try { await auth.logout(); } catch { /* ignore */ }
    navigate(`/login?next=${encodeURIComponent(`/invite/accept?token=${token()}`)}`);
  };

  return (
    <div class="iv-root">
      <style>{styles}</style>

      {/* ── Left manifest ─────────────────────────────────────── */}
      <section class="iv-manifest">
        <div class="iv-eyebrow">
          <span class="iv-n">✦</span>
          <span class="iv-eyebrow-text">{t("invite.eyebrow")}</span>
        </div>
        <Show
          when={status() !== "error"}
          fallback={<h1 class="iv-h1 iv-h1-sm"><span class="iv-stack">{t("invite.invalid.title")}</span></h1>}
        >
          <h1 class="iv-h1">
            <span class="iv-stack">{t("invite.title")}</span>
            <Show when={teamName()}>
              <span class="iv-stack"><span class="iv-ws">{teamName()}</span></span>
            </Show>
          </h1>
          <Show when={status() === "ready" || status() === "accepting"}>
            <p class="iv-deck">
              {t("invite.deck", { role: roleLabel(), team: teamName() })}
            </p>
          </Show>
        </Show>
        <div class="iv-disc" aria-hidden />
      </section>

      {/* ── Right action panel ────────────────────────────────── */}
      <section class="iv-side">
        <div class="iv-card">
          <div class="iv-card-head">
            <span class="iv-kicker">{t("invite.accept.title")}</span>
            <Show when={preview()?.valid}>
              <span class="iv-role">{roleLabel()}</span>
            </Show>
          </div>

          {/* loading */}
          <Show when={status() === "loading"}>
            <p class="iv-text">{t("invite.checking")}</p>
          </Show>

          {/* error / invalid */}
          <Show when={status() === "error"}>
            <div class="iv-error">{t(errKey())}</div>
            <A href="/login" class="iv-btn iv-btn-ghost">{t("invite.login")}</A>
          </Show>

          {/* accepted */}
          <Show when={status() === "accepted"}>
            <p class="iv-text">{t("invite.accepted.desc", { team: teamName() })}</p>
            <div class="iv-actions">
              <button type="button" class="iv-btn iv-btn-primary" onClick={() => navigate("/")}>
                {t("invite.goDashboard")}
              </button>
              <button type="button" class="iv-btn iv-btn-ghost" onClick={() => navigate("/team")}>
                {t("invite.openTeam")}
              </button>
            </div>
          </Show>

          {/* ready — branch on auth state */}
          <Show when={status() === "ready" || status() === "accepting"}>
            {/* not logged in */}
            <Show when={!auth.user}>
              <p class="iv-text">{t("invite.needAuth.desc", { email: invitedEmail() })}</p>
              <div class="iv-note">{t("invite.passwordNote")}</div>
              <div class="iv-actions">
                <A href={`/signup?email=${encodeURIComponent(invitedEmail())}`} class="iv-btn iv-btn-primary">
                  {t("invite.signup")}
                </A>
                <A href={`/login?next=${encodeURIComponent(`/invite/accept?token=${token()}`)}`} class="iv-btn iv-btn-ghost">
                  {t("invite.login")}
                </A>
              </div>
            </Show>

            {/* logged in, wrong account */}
            <Show when={auth.user && !emailMatches()}>
              <div class="iv-error">
                {t("invite.mismatch.desc", { email: invitedEmail(), current: auth.user!.email })}
              </div>
              <button type="button" class="iv-btn iv-btn-primary" onClick={switchAccount}>
                {t("invite.switchAccount")}
              </button>
            </Show>

            {/* logged in, right account → accept */}
            <Show when={auth.user && emailMatches()}>
              <p class="iv-text">{t("invite.confirm", { email: invitedEmail() })}</p>
              <button
                type="button"
                class="iv-btn iv-btn-primary iv-btn-big"
                onClick={accept}
                disabled={status() === "accepting"}
              >
                <span>{status() === "accepting" ? t("general.loading") : t("invite.cta.accept")}</span>
                <span class="iv-ar">→</span>
              </button>
            </Show>
          </Show>
        </div>
      </section>
    </div>
  );
}

const styles = `
.iv-root {
  --rule: var(--ink);
  min-height: 100vh; width: 100%;
  background: var(--cream); color: var(--ink);
  font-family: 'Inter Tight', system-ui, -apple-system, sans-serif;
  font-size: 15px; line-height: 1.45;
  display: grid; grid-template-columns: 1.25fr 1fr;
  overflow: auto;
  background-image: radial-gradient(rgba(0,0,0,0.05) 1px, transparent 1px);
  background-size: 4px 4px;
}
[data-theme="dark"] .iv-root {
  background-image: radial-gradient(rgba(241, 234, 216, 0.04) 1px, transparent 1px);
}
.iv-manifest {
  padding: 72px 64px; border-right: 3px solid var(--rule);
  position: relative; overflow: hidden;
  display: flex; flex-direction: column; justify-content: center;
}
.iv-disc {
  position: absolute; right: -110px; bottom: -110px;
  width: 340px; height: 340px;
  background: var(--red); border: 3px solid var(--rule); border-radius: 50%;
  pointer-events: none;
}
.iv-eyebrow { display: flex; align-items: center; gap: 16px; margin-bottom: 22px; position: relative; z-index: 1; }
.iv-n {
  font-family: 'Unbounded', sans-serif; font-weight: 900; font-size: 22px; line-height: 1;
  background: var(--red); color: var(--cream); padding: 4px 10px 6px;
  transform: rotate(-2deg); display: inline-block;
}
.iv-eyebrow-text {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 13px; letter-spacing: 0.28em; text-transform: uppercase; color: var(--ink);
}
.iv-h1 {
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: clamp(48px, 6.5vw, 104px); line-height: 0.88;
  letter-spacing: -0.05em; text-transform: uppercase;
  margin: 0 0 28px; position: relative; z-index: 1; color: var(--ink);
  overflow-wrap: anywhere;
}
.iv-h1-sm { font-size: clamp(36px, 5vw, 68px); }
.iv-stack { display: block; }
.iv-ws { color: var(--red); }
.iv-deck {
  font-family: 'Inter Tight', sans-serif; font-weight: 500;
  font-size: 17px; line-height: 1.5; max-width: 38ch;
  border-left: 4px solid var(--red); padding-left: 16px;
  margin: 0; position: relative; z-index: 1; color: var(--ink);
}
.iv-side {
  background: var(--cream); padding: 72px 64px;
  display: flex; flex-direction: column; justify-content: center;
}
.iv-card { display: flex; flex-direction: column; gap: 20px; max-width: 460px; width: 100%; }
.iv-card-head {
  display: flex; align-items: baseline; justify-content: space-between; gap: 16px;
  border-bottom: 3px solid var(--rule); padding-bottom: 14px;
}
.iv-kicker {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 12px; letter-spacing: 0.28em; text-transform: uppercase; color: var(--red);
}
.iv-role {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.16em; text-transform: uppercase;
  color: var(--cream); background: var(--ink); border: 2px solid var(--rule);
  padding: 3px 10px;
}
.iv-text {
  font-family: 'Inter Tight', sans-serif; font-size: 15.5px; line-height: 1.6;
  color: var(--ink); margin: 0;
}
.iv-note {
  font-family: 'Inter Tight', sans-serif; font-size: 13.5px; line-height: 1.55;
  color: var(--ink); background: rgba(214, 54, 42, 0.06);
  border-left: 4px solid var(--red); padding: 12px 14px;
}
.iv-error {
  border: 3px solid var(--red); background: rgba(214, 54, 42, 0.08);
  padding: 14px 16px; font-family: 'Inter Tight', sans-serif; font-size: 14.5px;
  line-height: 1.55; color: var(--ink);
}
.iv-actions { display: flex; gap: 12px; flex-wrap: wrap; }
.iv-btn {
  border: 3px solid var(--rule); cursor: pointer;
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 13px; letter-spacing: 0.14em; text-transform: uppercase;
  padding: 14px 22px; display: inline-flex; align-items: center; gap: 10px;
  justify-content: center; text-decoration: none; transition: transform 90ms, box-shadow 90ms;
}
.iv-btn-primary { background: var(--red); color: var(--cream); box-shadow: 5px 5px 0 var(--rule); }
.iv-btn-primary:hover:not(:disabled) { transform: translate(-2px, -2px); box-shadow: 7px 7px 0 var(--rule); }
.iv-btn-primary:disabled { opacity: 0.5; cursor: not-allowed; box-shadow: 3px 3px 0 var(--rule); transform: none; }
.iv-btn-ghost { background: var(--cream); color: var(--ink); }
.iv-btn-ghost:hover { background: var(--ink); color: var(--cream); }
.iv-btn-big {
  font-family: 'Unbounded', sans-serif; font-weight: 900; font-size: 19px;
  letter-spacing: 0.02em; padding: 18px 24px; justify-content: space-between; width: 100%;
}
.iv-ar { font-family: 'JetBrains Mono', monospace; font-size: 20px; }
@media (max-width: 960px) {
  .iv-root { grid-template-columns: 1fr; height: auto; min-height: 100vh; }
  .iv-manifest { border-right: 0; border-bottom: 3px solid var(--rule); padding: 48px 32px; }
  .iv-side { padding: 48px 32px; }
}
`;
