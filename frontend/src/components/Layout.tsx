import { createSignal, createEffect, createMemo, onCleanup, Show, For, type JSX } from "solid-js";
import { A } from "@solidjs/router";
import {
  LayoutDashboard,
  Link2,
  Activity,
  Settings,
  Shield,
  Ban,
  Cog,
  Users as UsersIcon,
  TestTube,
  Home as HomeIcon,
  PanelLeftClose,
  PanelLeftOpen,
  Users2,
  Bell,
} from "lucide-solid";
import { useSettings } from "../context/SettingsContext";
import { useAuth } from "../context/AuthContext";
import { subscribe } from "../realtime/client";
import { unreadCount, refreshUnread } from "../realtime/notifications";
import SettingsPopover from "./SettingsPopover";
import GlobalFilters from "./GlobalFilters";
import AccountSwitcher from "./AccountSwitcher";
import Logo from "./Logo";

const SIDEBAR_STORAGE_KEY = "waf-sidebar-collapsed";

function loadCollapsed(): boolean {
  try {
    return localStorage.getItem(SIDEBAR_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

type NavItem = { path: string; labelKey: string; icon: JSX.Element };
type NavSection = { titleKey: string; items: NavItem[] };

const ADMIN_NAV: NavSection[] = [
  {
    titleKey: "nav.operations",
    items: [
      { path: "/monitoring", labelKey: "nav.monitoring", icon: <Activity /> },
      { path: "/clients", labelKey: "nav.clients", icon: <UsersIcon /> },
    ],
  },
];

const CLIENT_NAV: NavSection[] = [
  {
    titleKey: "nav.overview",
    items: [
      { path: "/home", labelKey: "nav.home", icon: <HomeIcon /> },
      { path: "/dashboard", labelKey: "nav.dashboard", icon: <LayoutDashboard /> },
    ],
  },
  {
    titleKey: "nav.management",
    items: [
      { path: "/connections", labelKey: "nav.connections", icon: <Link2 /> },
      { path: "/config", labelKey: "nav.configuration", icon: <Settings /> },
      { path: "/team", labelKey: "team.title", icon: <Users2 /> },
    ],
  },
  {
    titleKey: "nav.security",
    items: [
      { path: "/crowdsec", labelKey: "nav.crowdsec", icon: <Ban /> },
      { path: "/tests", labelKey: "nav.tests", icon: <TestTube /> },
    ],
  },
  {
    titleKey: "nav.account",
    items: [
      { path: "/notifications", labelKey: "notif.nav", icon: <Bell /> },
    ],
  },
];

const NAV_MAP: Record<"admin" | "client", NavSection[]> = {
  admin: ADMIN_NAV,
  client: CLIENT_NAV,
};

export default function Layout(props: { children?: JSX.Element }) {
  const settings = useSettings();
  const auth = useAuth();
  const [popoverOpen, setPopoverOpen] = createSignal(false);
  const [collapsed, setCollapsed] = createSignal<boolean>(loadCollapsed());

  createEffect(() => {
    try {
      localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed() ? "1" : "0");
    } catch {
      // ignore
    }
  });

  // Track the active account (it can switch in-tab): refresh the unread count and
  // re-subscribe to the new account's personal channel on every change.
  const notifUserId = createMemo(() => auth.user?.id);
  createEffect(() => {
    const uid = notifUserId();
    if (!uid) return;
    void refreshUnread();
    const unsub = subscribe(`personal:#${uid}`, () => { void refreshUnread(); });
    onCleanup(unsub);
  });

  const sections = () => {
    const role = auth.user?.platform_role ?? "client";
    return NAV_MAP[role] ?? CLIENT_NAV;
  };

  return (
    <div class={`layout ${collapsed() ? "sidebar-collapsed" : ""}`}>
      <Show when={!collapsed()}>
        <div class="sidebar-overlay" onClick={() => setCollapsed(true)} />
      </Show>
      <Show when={collapsed()}>
        <button
          type="button"
          class="sidebar-reopen"
          onClick={() => setCollapsed(false)}
          aria-label={settings.t("sidebar.expand")}
          title={settings.t("sidebar.expand")}
        >
          <PanelLeftOpen size={18} />
        </button>
      </Show>
      <aside class="sidebar">
        <div class="sidebar-brand">
          <div class="brand-icon">
            <Logo size={40} title={settings.t("brand.logoAlt")} />
          </div>
          <div class="brand-text">
            <span class="brand-name">{settings.t("brand.name")}</span>
            <span class="brand-sub">{settings.t("brand.sub")}</span>
          </div>
          <button
            type="button"
            class="sidebar-collapse-btn"
            onClick={() => setCollapsed(true)}
            aria-label={settings.t("sidebar.collapse")}
            title={settings.t("sidebar.collapse")}
          >
            <PanelLeftClose size={16} />
          </button>
        </div>

        <Show when={!collapsed()}>
          <GlobalFilters />
        </Show>

        <nav class="sidebar-nav">
          <For each={sections()}>
            {(section) => (
              <div class="nav-section">
                <div class="nav-section-title">{settings.t(section.titleKey)}</div>
                <For each={section.items}>
                  {(item) => (
                    <A
                      href={item.path}
                      end={item.path === "/home"}
                      class="nav-link"
                      activeClass="active"
                    >
                      {item.icon}
                      {settings.t(item.labelKey)}
                      <Show when={item.path === "/notifications" && unreadCount() > 0}>
                        <span class="badge badge-primary" style="margin-left: auto; min-width: 20px; text-align: center;">
                          {unreadCount()}
                        </span>
                      </Show>
                    </A>
                  )}
                </For>
              </div>
            )}
          </For>
        </nav>

        <div class="sidebar-footer">
          <Show when={auth.user}>
            <AccountSwitcher />
          </Show>
          <div
            style={{
              padding: "14px 18px",
              "border-top": "3px solid var(--ink)",
              display: "flex",
              "align-items": "center",
              gap: "10px",
              "font-family": "var(--font-cond)",
              "font-size": "11px",
              "font-weight": 700,
              "letter-spacing": "0.18em",
              "text-transform": "uppercase",
              color: "var(--ink)",
            }}
          >
            <Shield size={15} />
            <span>{settings.t("status.engine")}</span>
            <span class="status-dot active" style={{ "margin-left": "auto" }} />
            <button
              class="settings-gear-btn"
              onClick={() => setPopoverOpen(!popoverOpen())}
              title={settings.t("settings.title")}
            >
              <Cog size={15} />
            </button>
          </div>
          <SettingsPopover open={popoverOpen()} onClose={() => setPopoverOpen(false)} />
        </div>
      </aside>

      <main class="main-content">
        <div class="page-wrapper">
          {props.children}
        </div>
      </main>
    </div>
  );
}
