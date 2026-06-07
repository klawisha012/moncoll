import { createSignal, onMount, For, Show } from "solid-js";
import { api, type TeamMember, type Invitation } from "../api/client";
import { useSettings } from "../context/SettingsContext";

export default function Team() {
  const settings = useSettings();
  const [members, setMembers] = createSignal<TeamMember[]>([]);
  const [myRole, setMyRole] = createSignal("member");
  const [outgoing, setOutgoing] = createSignal<Invitation[]>([]);
  const [incoming, setIncoming] = createSignal<Invitation[]>([]);
  const [email, setEmail] = createSignal("");
  const [role, setRole] = createSignal("member");
  const [toast, setToast] = createSignal<{ kind: "ok" | "err"; msg: string } | null>(null);
  const t = settings.t;
  const showToast = (kind: "ok" | "err", msg: string) => { setToast({ kind, msg }); setTimeout(() => setToast(null), 4000); };
  const canManage = () => myRole() === "owner" || myRole() === "admin";

  const load = async () => {
    try {
      const m = await api.teams.members();
      setMembers(m.members ?? []); setMyRole(m.my_role);
      const inv = await api.teams.invitations();
      setOutgoing(inv.outgoing); setIncoming(inv.incoming);
    } catch (e) { showToast("err", e instanceof Error ? e.message : "error"); }
  };
  onMount(() => void load());

  const invite = async (e: Event) => {
    e.preventDefault();
    try { await api.teams.invite(email().trim(), role()); setEmail(""); showToast("ok", t("team.invite")); void load(); }
    catch (e) { showToast("err", e instanceof Error ? e.message : "error"); }
  };
  const act = async (fn: () => Promise<unknown>) => {
    try { await fn(); void load(); } catch (e) { showToast("err", e instanceof Error ? e.message : "error"); }
  };

  return (
    <div class="page-content">
      <Show when={toast()}><div class={`toast toast--${toast()!.kind}`}>{toast()!.msg}</div></Show>
      <h1 class="page-title">{t("team.title")}</h1>

      <h2>{t("team.members")}</h2>
      <table>
        <thead><tr><th>{t("team.invite.email")}</th><th></th><th>{t("team.invite.role")}</th><th></th></tr></thead>
        <tbody>
          <For each={members()}>
            {(m) => (
              <tr>
                <td>{m.email}</td>
                <td>{m.display_name}</td>
                <td>
                  <Show when={myRole() === "owner" && m.role !== "owner"} fallback={t(`team.role.${m.role}`)}>
                    <select value={m.role} onChange={(e) => act(() => api.teams.changeRole(m.user_id, e.currentTarget.value))}>
                      <option value="admin">{t("team.role.admin")}</option>
                      <option value="member">{t("team.role.member")}</option>
                    </select>
                  </Show>
                </td>
                <td>
                  <Show when={canManage() && m.role !== "owner"}>
                    <button type="button" onClick={() => act(() => api.teams.removeMember(m.user_id))}>{t("team.action.remove")}</button>
                  </Show>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
      <button type="button" onClick={() => act(() => api.teams.leave())}>{t("team.action.leave")}</button>

      <Show when={canManage()}>
        <h2>{t("team.invitations")}</h2>
        <form onSubmit={invite}>
          <input type="email" required placeholder={t("team.invite.email")} value={email()} onInput={(e) => setEmail(e.currentTarget.value)} />
          <select value={role()} onChange={(e) => setRole(e.currentTarget.value)}>
            <option value="member">{t("team.role.member")}</option>
            <option value="admin">{t("team.role.admin")}</option>
          </select>
          <button type="submit">{t("team.invite")}</button>
        </form>
        <table>
          <tbody>
            <For each={outgoing()}>
              {(inv) => (
                <tr>
                  <td>{inv.email}</td>
                  <td>{t(`team.role.${inv.role}`)}</td>
                  <td>{inv.status}</td>
                  <td>
                    <Show when={inv.status === "pending"}>
                      <button type="button" onClick={() => act(() => api.teams.resendInvite(inv.id))}>{t("team.action.resend")}</button>
                      <button type="button" onClick={() => act(() => api.teams.revokeInvite(inv.id))}>{t("team.action.revoke")}</button>
                    </Show>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </Show>

      <Show when={incoming().length > 0}>
        <h2>{t("team.myInvitations")}</h2>
        <For each={incoming()}>
          {(inv) => (
            <div>
              <span>{inv.team_name} ({t(`team.role.${inv.role}`)})</span>
              <button type="button" onClick={() => act(() => api.teams.declineInvite(inv.id))}>{t("team.action.decline")}</button>
            </div>
          )}
        </For>
      </Show>
    </div>
  );
}
