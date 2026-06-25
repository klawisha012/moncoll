import { createSignal, For, Show, onMount, onCleanup } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { api, type Account } from "../api/client";
import { useAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";

export default function AccountSwitcher() {
  const auth = useAuth();
  const settings = useSettings();
  const navigate = useNavigate();
  const t = settings.t;
  const [open, setOpen] = createSignal(false);
  const [accounts, setAccounts] = createSignal<Account[]>([]);
  let rootEl: HTMLDivElement | undefined;

  const refresh = async () => {
    try { setAccounts(await api.auth.listAccounts()); } catch { /* ignore */ }
  };
  onMount(() => void refresh());

  const onDocClick = (e: MouseEvent) => {
    if (open() && rootEl && !rootEl.contains(e.target as Node)) setOpen(false);
  };
  document.addEventListener("click", onDocClick);
  onCleanup(() => document.removeEventListener("click", onDocClick));

  const roleLabel = (r: string) => t(`team.role.${r}`);
  const displayName = () => auth.user?.display_name || auth.user?.email || "";
  const initial = () => (auth.user?.display_name || auth.user?.email || "?").slice(0, 1).toUpperCase();

  const toggle = () => {
    const next = !open();
    setOpen(next);
    if (next) void refresh();
  };

  const onSwitch = async (a: Account) => {
    if (a.active) { setOpen(false); return; }
    try {
      await auth.switchAccount(a.user_id);
      setOpen(false);
      window.location.assign(a.platform_role === "admin" ? "/monitoring" : "/home");
    } catch { /* ignore */ }
  };
  const onLogout = async () => { await auth.logout(); navigate("/login", { replace: true }); };
  const onLogoutAll = async () => { await auth.logout(true); navigate("/login", { replace: true }); };

  return (
    <div class="acct-switcher" ref={rootEl}>
      <Show when={open()}>
        <div class="acct-menu" role="menu">
          <For each={accounts()}>
            {(a) => (
              <button type="button" class={`acct-item ${a.active ? "is-active" : ""}`} onClick={() => onSwitch(a)}>
                <span class="acct-item-email">{a.email}</span>
                <span class={`badge ${a.platform_role === "admin" ? "badge-info" : "badge-secondary"}`}>{roleLabel(a.platform_role)}</span>
                <Show when={a.active}><span class="acct-check">✓</span></Show>
              </button>
            )}
          </For>
          <a class="acct-add" href="/login?add=1">{t("account.add")}</a>
          <button type="button" class="acct-logout-one" onClick={onLogout}>{t("auth.logout")}</button>
          <button type="button" class="acct-logout-all" onClick={onLogoutAll}>{t("account.logoutAll")}</button>
        </div>
      </Show>

      <div class="acct-card">
        <button
          type="button"
          class="acct-card-main"
          onClick={toggle}
          aria-haspopup="menu"
          aria-expanded={open()}
        >
          <span class="acct-avatar">{initial()}</span>
          <span class="acct-id">
            <span class="acct-name">{displayName()}</span>
            <span class="acct-role">{auth.user?.platform_role}</span>
          </span>
          <span class="acct-caret">▾</span>
        </button>
      </div>
    </div>
  );
}
