import { createSignal, createEffect, Show } from "solid-js";
import { useSearchParams, useNavigate } from "@solidjs/router";
import { api } from "../api/client";
import { useSettings } from "../context/SettingsContext";
import { useAuth } from "../context/AuthContext";

export default function InviteAccept() {
  const settings = useSettings();
  const auth = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token = () => params.token ?? "";
  const [state, setState] = createSignal<"loading" | "ok" | "err" | "login">("loading");

  createEffect(() => {
    const tok = token();
    if (!tok) { setState("err"); return; }
    if (!auth.user) { setState("login"); return; }
    api.teams.acceptInvite(tok).then(() => setState("ok")).catch(() => setState("err"));
  });

  return (
    <div class="page-content">
      <h1 class="page-title">{settings.t("invite.accept.title")}</h1>
      <Show when={state() === "loading"}><p>{settings.t("invite.accept.loading")}</p></Show>
      <Show when={state() === "ok"}>
        <p>{settings.t("invite.accept.ok")}</p>
        <button type="button" onClick={() => navigate("/team")}>{settings.t("team.title")}</button>
      </Show>
      <Show when={state() === "err"}><p>{settings.t("invite.accept.err")}</p></Show>
      <Show when={state() === "login"}>
        <p>{settings.t("invite.accept.login")}</p>
        <button type="button" onClick={() => navigate(`/signup?invite=${encodeURIComponent(token())}`)}>{settings.t("team.action.accept")}</button>
      </Show>
    </div>
  );
}
