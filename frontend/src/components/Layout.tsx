import { NavLink, Outlet } from "react-router-dom";
import {
  LayoutDashboard,
  Link2,
  Activity,
  Settings,
  Shield,
} from "lucide-react";

export default function Layout() {
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">⚔️</div>
          <div className="brand-text">
            <span className="brand-name">WAF Panel</span>
            <span className="brand-sub">Control Center</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section">
            <div className="nav-section-title">Overview</div>
            <NavLink
              to="/dashboard"
              className={({ isActive }) =>
                `nav-link ${isActive ? "active" : ""}`
              }
            >
              <LayoutDashboard />
              Dashboard
            </NavLink>
            <NavLink
              to="/monitoring"
              className={({ isActive }) =>
                `nav-link ${isActive ? "active" : ""}`
              }
            >
              <Activity />
              Monitoring
            </NavLink>
          </div>

          <div className="nav-section">
            <div className="nav-section-title">Management</div>
            <NavLink
              to="/connections"
              className={({ isActive }) =>
                `nav-link ${isActive ? "active" : ""}`
              }
            >
              <Link2 />
              Connections
            </NavLink>
            <NavLink
              to="/config"
              className={({ isActive }) =>
                `nav-link ${isActive ? "active" : ""}`
              }
            >
              <Settings />
              Configuration
            </NavLink>
          </div>
        </nav>

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
          <span>WAF Engine Active</span>
          <span className="status-dot active" style={{ marginLeft: "auto" }} />
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
