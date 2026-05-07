import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import {
  LayoutDashboard,
  Link2,
  Activity,
  Settings,
  Shield,
  Ban,
  Cog,
} from "lucide-react";
import { useSettings } from "../context/SettingsContext";
import SettingsPopover from "./SettingsPopover";
import logoDark from "../assets/images/dark theme logo.png";
import logoLight from "../assets/images/ligth theme logo.png";

export default function Layout() {
  const { t, theme } = useSettings();
  const [popoverOpen, setPopoverOpen] = useState(false);

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
        </nav>

        <div className="sidebar-footer">
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
