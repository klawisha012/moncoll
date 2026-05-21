import { useState } from "react";
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
} from "lucide-react";
import { useSettings } from "../context/SettingsContext";
import { useAuth } from "../context/AuthContext";
import SettingsPopover from "./SettingsPopover";
import logoDark from "../assets/images/dark theme logo.png";
import logoLight from "../assets/images/ligth theme logo.png";

export default function Layout() {
  const { t, theme } = useSettings();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [popoverOpen, setPopoverOpen] = useState(false);

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">
            <img src={theme === "light" ? logoLight : logoDark} alt="WAF logo" />
          </div>
          <div className="brand-text">
            <span className="brand-name">{t("brand.name")}</span>
            <span className="brand-sub">{t("brand.sub")}</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section">
            <div className="nav-section-title">{t("nav.overview")}</div>
            <NavLink
              to="/dashboard"
              className={({ isActive }) =>
                `nav-link ${isActive ? "active" : ""}`
              }
            >
              <LayoutDashboard />
              {t("nav.dashboard")}
            </NavLink>
            <NavLink
              to="/monitoring"
              className={({ isActive }) =>
                `nav-link ${isActive ? "active" : ""}`
              }
            >
              <Activity />
              {t("nav.monitoring")}
            </NavLink>
          </div>

          {user?.role === "admin" && (
            <>
              <div className="nav-section">
                <div className="nav-section-title">{t("nav.management")}</div>
                <NavLink
                  to="/connections"
                  className={({ isActive }) =>
                    `nav-link ${isActive ? "active" : ""}`
                  }
                >
                  <Link2 />
                  {t("nav.connections")}
                </NavLink>
                <NavLink
                  to="/config"
                  className={({ isActive }) =>
                    `nav-link ${isActive ? "active" : ""}`
                  }
                >
                  <Settings />
                  {t("nav.configuration")}
                </NavLink>
                <NavLink
                  to="/users"
                  className={({ isActive }) =>
                    `nav-link ${isActive ? "active" : ""}`
                  }
                >
                  <UsersIcon />
                  {t("nav.users")}
                </NavLink>
              </div>

              <div className="nav-section">
                <div className="nav-section-title">{t("nav.security")}</div>
                <NavLink
                  to="/crowdsec"
                  className={({ isActive }) =>
                    `nav-link ${isActive ? "active" : ""}`
                  }
                >
                  <Ban />
                  {t("nav.crowdsec")}
                </NavLink>
                <NavLink
                  to="/tests"
                  className={({ isActive }) =>
                    `nav-link ${isActive ? "active" : ""}`
                  }
                >
                  <TestTube />
                  {t("nav.tests")}
                </NavLink>
              </div>
            </>
          )}
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
                {user.username.slice(0, 1).toUpperCase()}
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
                  {user.username}
                </span>
                <span
                  style={{
                    color: "var(--ink-soft)",
                    fontFamily: "var(--font-mono)",
                    fontSize: 10.5,
                    letterSpacing: "0.04em",
                  }}
                >
                  {user.role}
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
