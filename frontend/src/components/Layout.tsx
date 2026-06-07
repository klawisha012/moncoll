import { createSignal, createEffect, Show, For, type JSX } from "solid-js";
import { A, useNavigate } from "@solidjs/router";
import {
  LayoutDashboard,
  Link2,
  Activity,
  Settings,
  Shield,
  Ban,
  Cog,
  LogOut,
  Users as UsersIcon,
  TestTube,
  Home as HomeIcon,
  PanelLeftClose,
  PanelLeftOpen,
  Users2,
} from "lucide-solid";
import { useSettings } from "../context/SettingsContext";
import { useAuth } from "../context/AuthContext";
import SettingsPopover from "./SettingsPopover";
import GlobalFilters from "./GlobalFilters";
import TeamSwitcher from "./TeamSwitcher";
import logoDark from "../assets/images/dark theme logo.png";
import logoLight from "../assets/images/ligth theme logo.png";

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
];

const NAV_MAP: Record<"admin" | "client", NavSection[]> = {
  admin: ADMIN_NAV,
  client: CLIENT_NAV,
};

export default function Layout(props: { children?: JSX.Element }) {
  const settings = useSettings();
  const auth = useAuth();
  const navigate = useNavigate();
  const [popoverOpen, setPopoverOpen] = createSignal(false);
  const [collapsed, setCollapsed] = createSignal<boolean>(loadCollapsed());

  createEffect(() => {
    try {
      localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed() ? "1" : "0");
    } catch {
      // ignore
    }
  });

  const handleLogout = async () => {
    await auth.logout();
    navigate("/login", { replace: true });
  };

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
            <img src={settings.theme === "light" ? logoLight : logoDark} alt={settings.t("brand.logoAlt")} />
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
          <TeamSwitcher />
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
                    </A>
                  )}
                </For>
              </div>
            )}
          </For>
        </nav>

        <div class="sidebar-footer">
          <Show when={auth.user}>
            {(usr) => (
              <div
                style={{
                  padding: "14px 18px",
                  display: "flex",
                  "align-items": "center",
                  gap: "12px",
                  "font-size": "12px",
                  "border-top": "3px solid var(--ink)",
                }}
              >
                <div
                  style={{
                    width: "36px",
                    height: "36px",
                    "border-radius": "0px",
                    background: "var(--red)",
                    color: "var(--cream)",
                    display: "flex",
                    "align-items": "center",
                    "justify-content": "center",
                    "font-family": "var(--font-display)",
                    "font-weight": 900,
                    "font-size": "16px",
                    border: "2px solid var(--ink)",
                    "flex-shrink": 0,
                    "letter-spacing": "-0.02em",
                  }}
                >
                  {(usr().display_name || usr().email).slice(0, 1).toUpperCase()}
                </div>
                <div
                  style={{
                    display: "flex",
                    "flex-direction": "column",
                    flex: 1,
                    overflow: "hidden",
                    "line-height": 1.2,
                  }}
                >
                  <span
                    style={{
                      color: "var(--ink)",
                      "font-family": "var(--font-cond)",
                      "font-weight": 700,
                      "font-size": "13px",
                      "letter-spacing": "0.08em",
                      "text-transform": "uppercase",
                      overflow: "hidden",
                      "text-overflow": "ellipsis",
                      "white-space": "nowrap",
                    }}
                  >
                    {usr().display_name || usr().email}
                  </span>
                  <span
                    style={{
                      color: "var(--ink-soft)",
                      "font-family": "var(--font-mono)",
                      "font-size": "10.5px",
                      "letter-spacing": "0.04em",
                    }}
                  >
                    {usr().platform_role}
                  </span>
                </div>
                <button
                  onClick={handleLogout}
                  title={settings.t("auth.logout")}
                  style={{
                    background: "var(--cream)",
                    border: "2px solid var(--ink)",
                    "border-radius": "0px",
                    padding: "6px 8px",
                    color: "var(--ink)",
                    cursor: "pointer",
                    display: "flex",
                    "align-items": "center",
                    "justify-content": "center",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = "var(--red)";
                    e.currentTarget.style.color = "var(--cream)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = "var(--cream)";
                    e.currentTarget.style.color = "var(--ink)";
                  }}
                >
                  <LogOut size={14} />
                </button>
              </div>
            )}
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
