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
              </div>
            </>
          )}
        </nav>

        <div className="sidebar-footer">
          {user && (
            <div
              style={{
                padding: "10px 16px",
                display: "flex",
                alignItems: "center",
                gap: 10,
                fontSize: 12,
                borderTop: "1px solid var(--border-subtle)",
              }}
            >
              <div
                style={{
                  width: 28,
                  height: 28,
                  borderRadius: "50%",
                  background: "var(--accent-primary)",
                  color: "#fff",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontWeight: 600,
                  fontSize: 12,
                  flexShrink: 0,
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
                }}
              >
                <span
                  style={{
                    color: "var(--text-primary)",
                    fontWeight: 500,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {user.username}
                </span>
                <span style={{ color: "var(--text-muted)", fontSize: 11 }}>
                  {user.role}
                </span>
              </div>
              <button
                onClick={handleLogout}
                title={t("auth.logout")}
                style={{
                  background: "transparent",
                  border: "1px solid var(--border-subtle)",
                  borderRadius: 6,
                  padding: 6,
                  color: "var(--text-muted)",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <LogOut size={14} />
              </button>
            </div>
          )}
          <div
            style={{
              padding: "16px",
              borderTop: "1px solid var(--border-subtle)",
              display: "flex",
              alignItems: "center",
              gap: "10px",
              fontSize: "12px",
              color: "var(--text-muted)",
            }}
          >
            <Shield size={14} />
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
