import { type ReactNode, useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
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
} from "lucide-react";
import { useSettings } from "../context/SettingsContext";
import { useAuth } from "../context/AuthContext";
import SettingsPopover from "./SettingsPopover";
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

type NavItem = { path: string; labelKey: string; icon: ReactNode };
type NavSection = { titleKey: string; items: NavItem[] };

// Declared outside component to avoid re-creating every render
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

export default function Layout() {
  const { t, theme } = useSettings();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [popoverOpen, setPopoverOpen] = useState(false);
  const [collapsed, setCollapsed] = useState<boolean>(loadCollapsed);

  useEffect(() => {
    try {
      localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed ? "1" : "0");
    } catch {
      // ignore
    }
  }, [collapsed]);

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  const role = user?.platform_role ?? "client";
  const sections = NAV_MAP[role] ?? CLIENT_NAV;

  return (
    <div className={`layout ${collapsed ? "sidebar-collapsed" : ""}`}>
      {collapsed && (
        <button
          type="button"
          className="sidebar-reopen"
          onClick={() => setCollapsed(false)}
          aria-label={t("sidebar.expand")}
          title={t("sidebar.expand")}
        >
          <PanelLeftOpen size={18} />
        </button>
      )}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">
            <img src={theme === "light" ? logoLight : logoDark} alt={t("brand.logoAlt")} />
          </div>
          <div className="brand-text">
            <span className="brand-name">{t("brand.name")}</span>
            <span className="brand-sub">{t("brand.sub")}</span>
          </div>
          <button
            type="button"
            className="sidebar-collapse-btn"
            onClick={() => setCollapsed(true)}
            aria-label={t("sidebar.collapse")}
            title={t("sidebar.collapse")}
          >
            <PanelLeftClose size={16} />
          </button>
        </div>

        <nav className="sidebar-nav">
          {sections.map((section) => (
            <div key={section.titleKey} className="nav-section">
              <div className="nav-section-title">{t(section.titleKey)}</div>
              {section.items.map((item) => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === "/home"}
                  className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
                >
                  {item.icon}
                  {t(item.labelKey)}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          {user && (
            <div
              style={{
                padding: "14px 18px",
                display: "flex",
                alignItems: "center",
                gap: 12,
                fontSize: 12,
                borderTop: "3px solid var(--ink)",
              }}
            >
              <div
                style={{
                  width: 36,
                  height: 36,
                  borderRadius: 0,
                  background: "var(--red)",
                  color: "var(--cream)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontFamily: "var(--font-display)",
                  fontWeight: 900,
                  fontSize: 16,
                  border: "2px solid var(--ink)",
                  flexShrink: 0,
                  letterSpacing: "-0.02em",
                }}
              >
                {(user.display_name || user.email).slice(0, 1).toUpperCase()}
              </div>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  flex: 1,
                  overflow: "hidden",
                  lineHeight: 1.2,
                }}
              >
                <span
                  style={{
                    color: "var(--ink)",
                    fontFamily: "var(--font-cond)",
                    fontWeight: 700,
                    fontSize: 13,
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {user.display_name || user.email}
                </span>
                <span
                  style={{
                    color: "var(--ink-soft)",
                    fontFamily: "var(--font-mono)",
                    fontSize: 10.5,
                    letterSpacing: "0.04em",
                  }}
                >
                  {user.platform_role}
                </span>
              </div>
              <button
                onClick={handleLogout}
                title={t("auth.logout")}
                style={{
                  background: "var(--cream)",
                  border: "2px solid var(--ink)",
                  borderRadius: 0,
                  padding: "6px 8px",
                  color: "var(--ink)",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
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
          <div
            style={{
              padding: "14px 18px",
              borderTop: "3px solid var(--ink)",
              display: "flex",
              alignItems: "center",
              gap: "10px",
              fontFamily: "var(--font-cond)",
              fontSize: "11px",
              fontWeight: 700,
              letterSpacing: "0.18em",
              textTransform: "uppercase",
              color: "var(--ink)",
            }}
          >
            <Shield size={15} />
            <span>{t("status.engine")}</span>
            <span className="status-dot active" style={{ marginLeft: "auto" }} />
            <button
              className="settings-gear-btn"
              onClick={() => setPopoverOpen(!popoverOpen)}
              title={t("settings.title")}
            >
              <Cog size={15} />
            </button>
          </div>
          <SettingsPopover open={popoverOpen} onClose={() => setPopoverOpen(false)} />
        </div>
      </aside>

      <main className="main-content">
        <div className="page-wrapper">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
