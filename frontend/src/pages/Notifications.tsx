import { createSignal, createEffect, onMount, For, Show } from "solid-js";
import { api, type AppNotification } from "../api/client";
import { useSettings } from "../context/SettingsContext";

type FilterTab = "all" | "unread" | "starred";
type ToastKind = "success" | "error" | "info";

function fmtDate(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const now = Date.now();
  const diff = now - d.getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return d.toLocaleDateString();
}

export default function Notifications() {
  const settings = useSettings();
  const t = settings.t;

  const [items, setItems] = createSignal<AppNotification[]>([]);
  const [filter, setFilter] = createSignal<FilterTab>("all");
  const [loading, setLoading] = createSignal(false);
  const [toast, setToast] = createSignal<{ kind: ToastKind; msg: string } | null>(null);

  const showToast = (kind: ToastKind, msg: string) => {
    setToast({ kind, msg });
    setTimeout(() => setToast(null), 4000);
  };
  const errMsg = (e: unknown) => (e instanceof Error ? e.message : "error");

  const load = async () => {
    setLoading(true);
    try {
      const ns = await api.notifications.list(filter());
      setItems(ns);
    } catch (e) {
      showToast("error", errMsg(e));
    } finally {
      setLoading(false);
    }
  };

  onMount(() => void load());
  createEffect(() => {
    filter(); // track
    void load();
  });

  // Localized render helper: derive title + body from notification type + data_json.
  const render = (n: AppNotification): { title: string; body: string } => {
    let data: Record<string, string> = {};
    try {
      data = JSON.parse(n.data_json) as Record<string, string>;
    } catch {
      // malformed JSON — fall through to default
    }
    switch (n.type) {
      case "team.invitation":
        return {
          title: t("notif.invitation.title"),
          body: t("notif.invitation.body", {
            team: data.team_name ?? "",
            role: t(`team.role.${data.role ?? "member"}`),
          }),
        };
      case "team.role_changed":
        return {
          title: t("notif.role.title"),
          body: t("notif.role.body", { role: t(`team.role.${data.role ?? "member"}`) }),
        };
      case "team.member_removed":
        return {
          title: t("notif.removed.title"),
          body: t("notif.removed.body"),
        };
      default:
        // Covers team.member_joined and future types — use backend-provided strings.
        return { title: n.title, body: n.body };
    }
  };

  const markAllRead = async () => {
    try {
      await api.notifications.markAllRead();
      await load();
    } catch (e) {
      showToast("error", errMsg(e));
    }
  };

  const markRead = async (n: AppNotification) => {
    if (n.read) return;
    try {
      await api.notifications.markRead([n.id]);
      setItems((prev) => prev.map((x) => (x.id === n.id ? { ...x, read: true } : x)));
    } catch {
      // best-effort
    }
  };

  const toggleStar = async (n: AppNotification) => {
    try {
      const updated = await api.notifications.toggleStar(n.id, !n.starred);
      setItems((prev) => prev.map((x) => (x.id === n.id ? updated : x)));
    } catch (e) {
      showToast("error", errMsg(e));
    }
  };

  const remove = async (n: AppNotification) => {
    try {
      await api.notifications.remove([n.id]);
      setItems((prev) => prev.filter((x) => x.id !== n.id));
    } catch (e) {
      showToast("error", errMsg(e));
    }
  };

  const acceptInvite = async (n: AppNotification) => {
    let data: Record<string, string> = {};
    try { data = JSON.parse(n.data_json) as Record<string, string>; } catch { /* */ }
    try {
      await api.teams.acceptInviteById(Number(data.invitation_id));
      await api.notifications.remove([n.id]);
      await load();
      showToast("success", t("invite.accept.ok"));
    } catch (e) {
      showToast("error", errMsg(e));
    }
  };

  const declineInvite = async (n: AppNotification) => {
    let data: Record<string, string> = {};
    try { data = JSON.parse(n.data_json) as Record<string, string>; } catch { /* */ }
    try {
      await api.teams.declineInvite(Number(data.invitation_id));
      await api.notifications.remove([n.id]);
      await load();
    } catch (e) {
      showToast("error", errMsg(e));
    }
  };

  const tabs: FilterTab[] = ["all", "unread", "starred"];

  return (
    <div class="page-content">
      <Show when={toast()}>
        <div class={`toast toast-${toast()!.kind}`}>{toast()!.msg}</div>
      </Show>

      <h1 class="page-title">{t("notif.title")}</h1>

      {/* ── Tabs + actions ────────────────────────────────── */}
      <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 20px;">
        <For each={tabs}>
          {(tab) => (
            <button
              type="button"
              class={`btn btn-sm ${filter() === tab ? "btn-primary" : "btn-outline"}`}
              onClick={() => setFilter(tab)}
            >
              {t(`notif.tab.${tab}`)}
            </button>
          )}
        </For>
        <div style="flex: 1;" />
        <button
          type="button"
          class="btn btn-sm btn-ghost"
          onClick={markAllRead}
          disabled={loading()}
        >
          {t("notif.markAllRead")}
        </button>
      </div>

      {/* ── Notification list ─────────────────────────────── */}
      <Show when={!loading()} fallback={<p style="color: var(--text-muted);">{t("general.loading")}</p>}>
        <Show
          when={items().length > 0}
          fallback={<p style="color: var(--text-muted);">{t("notif.empty")}</p>}
        >
          <div class="card" style="padding: 0;">
            <For each={items()}>
              {(n) => {
                const { title, body } = render(n);
                return (
                  <div
                    style={`
                      display: flex;
                      align-items: flex-start;
                      gap: 14px;
                      padding: 14px 18px;
                      border-bottom: 1.5px solid var(--line);
                      background: ${n.read ? "transparent" : "var(--cream, rgba(255,255,220,0.06))"};
                    `}
                    onClick={() => void markRead(n)}
                  >
                    {/* Unread dot */}
                    <div style="padding-top: 5px; width: 8px; flex-shrink: 0;">
                      <Show when={!n.read}>
                        <span style="display: block; width: 8px; height: 8px; border-radius: 50%; background: var(--accent, #4f8fff);" />
                      </Show>
                    </div>

                    {/* Content */}
                    <div style="flex: 1; min-width: 0;">
                      <div style="display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap;">
                        <strong
                          style={`font-size: 14px; ${!n.read ? "font-weight: 700;" : "font-weight: 500;"}`}
                        >
                          {title}
                        </strong>
                        <span style="font-size: 12px; color: var(--text-muted);">{fmtDate(n.created_at)}</span>
                        <Show when={n.starred}>
                          <span style="font-size: 12px; color: var(--warning, #d97706);">★</span>
                        </Show>
                      </div>
                      <p style="margin: 4px 0 0; font-size: 13px; color: var(--text-secondary); line-height: 1.45;">
                        {body}
                      </p>

                      {/* Invitation actions */}
                      <Show when={n.type === "team.invitation"}>
                        <div style="display: flex; gap: 8px; margin-top: 10px;">
                          <button
                            type="button"
                            class="btn btn-sm btn-primary"
                            onClick={(e) => { e.stopPropagation(); void acceptInvite(n); }}
                          >
                            {t("notif.action.accept")}
                          </button>
                          <button
                            type="button"
                            class="btn btn-sm btn-ghost"
                            onClick={(e) => { e.stopPropagation(); void declineInvite(n); }}
                          >
                            {t("notif.action.decline")}
                          </button>
                        </div>
                      </Show>
                    </div>

                    {/* Row actions */}
                    <div style="display: flex; align-items: center; gap: 6px; flex-shrink: 0;">
                      <button
                        type="button"
                        class="btn-icon"
                        title={n.starred ? "Unstar" : "Star"}
                        aria-label={n.starred ? "Unstar" : "Star"}
                        onClick={(e) => { e.stopPropagation(); void toggleStar(n); }}
                        style={n.starred ? "color: var(--warning, #d97706);" : ""}
                      >
                        {n.starred ? "★" : "☆"}
                      </button>
                      <button
                        type="button"
                        class="btn-icon"
                        title={t("notif.action.delete")}
                        aria-label={t("notif.action.delete")}
                        onClick={(e) => { e.stopPropagation(); void remove(n); }}
                      >
                        ×
                      </button>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </Show>
    </div>
  );
}
