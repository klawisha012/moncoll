import { createSignal, For, Show, onMount } from "solid-js";
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

  const refresh = async () => {
    try { setAccounts(await api.auth.listAccounts()); } catch { /* ignore */ }
  };
  onMount(() => void refresh());

  const active = () => accounts().find((a) => a.active) ?? null;
  const roleLabel = (r: string) => t(`team.role.${r}`);

  const onSwitch = async (a: Account) => {
    if (a.active) { setOpen(false); return; }
    try {
      await auth.switchAccount(a.user_id);
      setOpen(false);
      window.location.assign(a.platform_role === "admin" ? "/monitoring" : "/home");
    } catch { /* ignore */ }
  };
  const onLogoutAll = async () => { await auth.logout(true); navigate("/login", { replace: true }); };

  return (
    <div class="acct-switcher">
      <button type="button" class="acct-chip" onClick={() => { setOpen((v) => !v); void refresh(); }}>
        <span class="acct-email">{auth.user?.email ?? active()?.email ?? ""}</span>
        <span class="acct-caret">▾</span>
      </button>
      <Show when={open()}>
        <div class="acct-menu">
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
          <button type="button" class="acct-logout-all" onClick={onLogoutAll}>{t("account.logoutAll")}</button>
        </div>
      </Show>
    </div>
  );
}
