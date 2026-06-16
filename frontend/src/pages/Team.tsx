import { createSignal, onMount, For, Show } from "solid-js";
import { api, type TeamMember, type Invitation, type UserLookup } from "../api/client";
import { useSettings } from "../context/SettingsContext";
import { useAuth } from "../context/AuthContext";
import TeamSwitcher from "../components/TeamSwitcher";

type ToastKind = "success" | "error" | "info";
type LinkPanel = { url: string; email: string; sent: boolean };
type Confirm = { message: string; danger?: boolean; onConfirm: () => void };

const roleBadgeClass = (role: string) =>
  role === "owner" ? "badge badge-info" : role === "admin" ? "badge badge-primary" : "badge badge-secondary";

const statusBadgeClass = (status: string) =>
  status === "pending" ? "badge badge-warning" : status === "accepted" ? "badge badge-success" : "badge badge-secondary";

export default function Team() {
  const settings = useSettings();
  const auth = useAuth();
  const t = settings.t;

  const [members, setMembers] = createSignal<TeamMember[]>([]);
  const [myRole, setMyRole] = createSignal("member");
  const [teamName, setTeamName] = createSignal("");
  const [editingName, setEditingName] = createSignal(false);
  const [nameDraft, setNameDraft] = createSignal("");
  const [savingName, setSavingName] = createSignal(false);
  const [outgoing, setOutgoing] = createSignal<Invitation[]>([]);
  const [email, setEmail] = createSignal("");
  const [role, setRole] = createSignal("member");
  const [busy, setBusy] = createSignal(false);
  const [lookup, setLookup] = createSignal<UserLookup | null>(null);
  let lookupTimer: ReturnType<typeof setTimeout> | undefined;
  const [toast, setToast] = createSignal<{ kind: ToastKind; msg: string } | null>(null);
  const [linkPanel, setLinkPanel] = createSignal<LinkPanel | null>(null);
  const [confirm, setConfirm] = createSignal<Confirm | null>(null);

  const showToast = (kind: ToastKind, msg: string) => {
    setToast({ kind, msg });
    setTimeout(() => setToast(null), 4000);
  };
  const errMsg = (e: unknown) => (e instanceof Error ? e.message : "error");
  const canManage = () => myRole() === "owner" || myRole() === "admin";
  const isMe = (addr: string) => auth.user?.email?.toLowerCase() === addr.toLowerCase();

  const load = async () => {
    try {
      const m = await api.teams.members();
      setMembers(m.members ?? []);
      setMyRole(m.my_role);
      setTeamName(m.team_name ?? "");
      const inv = await api.teams.invitations();
      setOutgoing(inv.outgoing);
    } catch (e) {
      showToast("error", errMsg(e));
    }
  };
  onMount(() => void load());

  // Run a mutating action then reload, surfacing any error as a toast.
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      void load();
    } catch (e) {
      showToast("error", errMsg(e));
    }
  };

  // Owner-only team rename. Reloads on success so the title and the team
  // switcher pick up the new name everywhere.
  const saveName = async () => {
    const name = nameDraft().trim();
    if (!name || name === teamName() || savingName()) return;
    setSavingName(true);
    try {
      await api.teams.rename(name);
      showToast("success", t("team.name.renamed"));
      setTimeout(() => window.location.reload(), 700);
    } catch (e) {
      showToast("error", errMsg(e));
      setSavingName(false);
    }
  };

  const ask = (c: Confirm) => setConfirm(c);
  const runConfirm = () => {
    const c = confirm();
    setConfirm(null);
    c?.onConfirm();
  };

  // After create/resend the backend returns the raw accept link + whether the
  // email actually went out. Show it so an admin can share it manually even
  // when SMTP delivery is broken.
  const presentInvite = (inv: Invitation) => {
    if (inv.accept_url) {
      setLinkPanel({ url: inv.accept_url, email: inv.email, sent: !!inv.email_sent });
    }
  };

  // Debounced exact-email lookup: tell the admin whether this address already
  // has a WAF account before they send the invite.
  const onEmailInput = (val: string) => {
    setEmail(val);
    setLookup(null);
    if (lookupTimer) clearTimeout(lookupTimer);
    const addr = val.trim();
    if (!addr.includes("@") || addr.length < 3) return;
    lookupTimer = setTimeout(() => {
      api.teams
        .lookupUser(addr)
        .then((r) => {
          // Ignore stale responses if the field changed while in flight.
          if (email().trim().toLowerCase() === addr.toLowerCase()) setLookup(r);
        })
        .catch(() => {});
    }, 400);
  };

  const invite = async (e: Event) => {
    e.preventDefault();
    const addr = email().trim();
    if (!addr || busy()) return;
    setBusy(true);
    try {
      const inv = await api.teams.invite(addr, role());
      setEmail("");
      setLookup(null);
      presentInvite(inv);
      showToast("success", t("team.invited.ok", { email: inv.email }));
      void load();
    } catch (e) {
      showToast("error", errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const resend = async (inv: Invitation) => {
    try {
      const fresh = await api.teams.resendInvite(inv.id);
      presentInvite(fresh);
      showToast(fresh.email_sent ? "success" : "info", t("team.invited.ok", { email: fresh.email }));
      void load();
    } catch (e) {
      showToast("error", errMsg(e));
    }
  };

  const copyLink = async (url: string) => {
    try {
      await navigator.clipboard.writeText(url);
      showToast("info", t("team.link.copied"));
    } catch {
      // clipboard may be denied in insecure contexts — leave the field selectable
    }
  };

  const statusLabel = (s: string) => {
    const key = `team.status.${s}`;
    const label = t(key);
    return label === key ? s : label;
  };
  const fmtDate = (iso: string) => {
    const d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleDateString();
  };

  return (
    <div class="page-content">
      <Show when={toast()}>
        <div class={`toast toast-${toast()!.kind}`}>{toast()!.msg}</div>
      </Show>

      <h1 class="page-title">{t("team.title")}</h1>

      {/* ── Team name editor (owner only) ─────────────────────── */}
      <Show when={myRole() === "owner"}>
        <div style="display: flex; align-items: center; gap: 14px; flex-wrap: wrap; padding: 14px 18px; margin-bottom: 24px; background: var(--cream-2); border: 3px solid var(--line); box-shadow: var(--shadow-offset-sm);">
          <span style="font-family: var(--font-cond); font-size: 12px; font-weight: 700; letter-spacing: 0.18em; text-transform: uppercase; color: var(--ink); flex-shrink: 0;">
            {t("team.name.label")}
          </span>
          <Show
            when={editingName()}
            fallback={
              <>
                <span style="font-family: var(--font-cond); font-size: 15px; font-weight: 600; color: var(--ink); margin-right: auto;">{teamName() || "—"}</span>
                <button type="button" class="btn btn-sm btn-outline" onClick={() => { setNameDraft(teamName()); setEditingName(true); }}>
                  {t("team.name.edit")}
                </button>
              </>
            }
          >
            <input
              class="input"
              style="flex: 1 1 220px; min-width: 180px;"
              maxlength="64"
              value={nameDraft()}
              onInput={(e) => setNameDraft(e.currentTarget.value)}
              onKeyDown={(e) => { if (e.key === "Enter") saveName(); if (e.key === "Escape") setEditingName(false); }}
            />
            <button
              type="button"
              class="btn btn-sm btn-primary"
              disabled={savingName() || !nameDraft().trim() || nameDraft().trim() === teamName()}
              onClick={saveName}
            >
              {t("general.save")}
            </button>
            <button type="button" class="btn btn-sm btn-ghost" onClick={() => setEditingName(false)}>
              {t("general.cancel")}
            </button>
          </Show>
        </div>
      </Show>

      {/* ── Active-team switcher (only when in 2+ teams) ──────── */}
      <TeamSwitcher />

      {/* ── Members ───────────────────────────────────────────── */}
      <div class="card" style="margin-bottom: 24px;">
        <div class="card-header">
          <h2>{t("team.members")}</h2>
          <span class="badge badge-secondary">{members().length}</span>
        </div>
        <p style="color: var(--text-secondary); font-size: 13px; margin: -6px 0 16px;">{t("team.members.subtitle")}</p>

        <Show
          when={members().length > 0}
          fallback={<p style="color: var(--text-muted);">{t("team.empty.members")}</p>}
        >
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>{t("team.invite.email")}</th>
                  <th>{t("team.col.name")}</th>
                  <th>{t("team.invite.role")}</th>
                  <th style="text-align: right;">{t("team.col.actions")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={members()}>
                  {(m) => (
                    <tr>
                      <td>
                        {m.email}
                        <Show when={isMe(m.email)}>
                          <span class="badge badge-phase" style="margin-left: 8px;">{t("team.you")}</span>
                        </Show>
                      </td>
                      <td style="color: var(--text-secondary);">{m.display_name || "—"}</td>
                      <td>
                        <Show
                          when={myRole() === "owner" && m.role !== "owner"}
                          fallback={<span class={roleBadgeClass(m.role)}>{t(`team.role.${m.role}`)}</span>}
                        >
                          <select
                            class="input"
                            style="width: auto; padding: 6px 10px;"
                            value={m.role}
                            onChange={(e) => act(() => api.teams.changeRole(m.user_id, e.currentTarget.value))}
                          >
                            <option value="admin">{t("team.role.admin")}</option>
                            <option value="member">{t("team.role.member")}</option>
                          </select>
                        </Show>
                      </td>
                      <td style="text-align: right;">
                        <Show when={canManage() && m.role !== "owner" && !isMe(m.email)}>
                          <button
                            type="button"
                            class="btn btn-sm btn-outline"
                            onClick={() =>
                              ask({
                                message: t("team.confirm.remove", { email: m.email }),
                                danger: true,
                                onConfirm: () => act(() => api.teams.removeMember(m.user_id)),
                              })
                            }
                          >
                            {t("team.action.remove")}
                          </button>
                        </Show>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>

        <Show when={myRole() !== "owner"}>
          <div style="margin-top: 18px;">
            <button
              type="button"
              class="btn btn-sm btn-ghost"
              onClick={() =>
                ask({
                  message: t("team.confirm.leave"),
                  danger: true,
                  onConfirm: () => act(() => api.teams.leave()),
                })
              }
            >
              {t("team.action.leave")}
            </button>
          </div>
        </Show>
      </div>

      {/* ── Invitations (admins/owners) ───────────────────────── */}
      <Show when={canManage()}>
        <div class="card" style="margin-bottom: 24px;">
          <div class="card-header">
            <h2>{t("team.invitations")}</h2>
          </div>
          <p style="color: var(--text-secondary); font-size: 13px; margin: -6px 0 16px;">{t("team.invite.subtitle")}</p>

          <form onSubmit={invite} style="display: flex; gap: 12px; flex-wrap: wrap; align-items: stretch;">
            <input
              class="input"
              style="flex: 1 1 240px;"
              type="email"
              required
              placeholder={t("team.invite.placeholder")}
              value={email()}
              onInput={(e) => onEmailInput(e.currentTarget.value)}
            />
            <select class="input" style="width: auto;" value={role()} onChange={(e) => setRole(e.currentTarget.value)}>
              <option value="member">{t("team.role.member")}</option>
              <option value="admin">{t("team.role.admin")}</option>
            </select>
            <button type="submit" class="btn btn-primary" disabled={busy() || lookup()?.already_member === true}>
              {t("team.invite")}
            </button>
          </form>

          <Show when={lookup()}>
            <p
              style={`margin: 10px 0 0; font-size: 13px; color: ${lookup()!.already_member ? "var(--text-muted)" : lookup()!.found ? "var(--ok, #1a7f37)" : "var(--text-secondary)"};`}
            >
              {lookup()!.already_member
                ? t("team.lookup.member", { name: lookup()!.display_name || lookup()!.email || "" })
                : lookup()!.found
                ? t("team.lookup.registered", { name: lookup()!.display_name || lookup()!.email || "" })
                : t("team.lookup.unregistered")}
            </p>
          </Show>

          {/* Invite link + delivery status */}
          <Show when={linkPanel()}>
            <div
              style={`margin-top: 18px; border: 3px solid var(--line); background: var(--cream); padding: 16px 18px; box-shadow: var(--shadow-offset-sm);`}
            >
              <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px;">
                <strong style="font-family: var(--font-cond); text-transform: uppercase; letter-spacing: 0.16em; font-size: 12px;">
                  {t("team.link.title")}
                </strong>
                <button type="button" class="btn-icon" aria-label="dismiss" onClick={() => setLinkPanel(null)}>×</button>
              </div>
              <p
                class={`badge ${linkPanel()!.sent ? "badge-success" : "badge-warning"}`}
                style="display: inline-flex; white-space: normal; line-height: 1.4; margin-bottom: 12px;"
              >
                {linkPanel()!.sent
                  ? t("team.email.sent", { email: linkPanel()!.email })
                  : t("team.email.failed")}
              </p>
              <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <input
                  class="input"
                  style="flex: 1 1 280px; font-family: var(--font-mono); font-size: 13px;"
                  readonly
                  value={linkPanel()!.url}
                  onClick={(e) => e.currentTarget.select()}
                />
                <button type="button" class="btn btn-sm btn-outline" onClick={() => copyLink(linkPanel()!.url)}>
                  {t("team.link.copy")}
                </button>
              </div>
              <p style="color: var(--text-muted); font-size: 12px; margin: 10px 0 0;">{t("team.link.hint")}</p>
            </div>
          </Show>

          {/* Outgoing invitations */}
          <div style="margin-top: 22px;">
            <Show
              when={outgoing().length > 0}
              fallback={<p style="color: var(--text-muted);">{t("team.empty.invitations")}</p>}
            >
              <div class="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>{t("team.invite.email")}</th>
                      <th>{t("team.invite.role")}</th>
                      <th>{t("team.col.status")}</th>
                      <th>{t("team.col.expires")}</th>
                      <th style="text-align: right;">{t("team.col.actions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={outgoing()}>
                      {(inv) => (
                        <tr>
                          <td>{inv.email}</td>
                          <td><span class={roleBadgeClass(inv.role)}>{t(`team.role.${inv.role}`)}</span></td>
                          <td><span class={statusBadgeClass(inv.status)}>{statusLabel(inv.status)}</span></td>
                          <td style="color: var(--text-secondary); font-size: 12.5px;">{fmtDate(inv.expires_at)}</td>
                          <td style="text-align: right; white-space: nowrap;">
                            <Show when={inv.status === "pending"}>
                              <button type="button" class="btn btn-sm btn-outline" style="margin-right: 8px;" onClick={() => resend(inv)}>
                                {t("team.action.resend")}
                              </button>
                              <button
                                type="button"
                                class="btn btn-sm btn-ghost"
                                onClick={() =>
                                  ask({
                                    message: t("team.confirm.revoke", { email: inv.email }),
                                    danger: true,
                                    onConfirm: () => act(() => api.teams.revokeInvite(inv.id)),
                                  })
                                }
                              >
                                {t("team.action.revoke")}
                              </button>
                            </Show>
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </div>
        </div>
      </Show>

      {/* ── Confirmation modal ────────────────────────────────── */}
      <Show when={confirm()}>
        <div class="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) setConfirm(null); }}>
          <div class="modal" style="max-width: 460px;">
            <div class="modal-header">
              <h2>{t("team.confirm.title")}</h2>
            </div>
            <p style="line-height: 1.5;">{confirm()!.message}</p>
            <div class="modal-actions">
              <button type="button" class="btn btn-outline" onClick={() => setConfirm(null)}>{t("general.cancel")}</button>
              <button type="button" class={`btn ${confirm()!.danger ? "btn-danger" : "btn-primary"}`} onClick={runConfirm}>
                {t("team.confirm.ok")}
              </button>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}
