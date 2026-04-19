import { NavLink, Outlet } from "react-router-dom";
import { BarChart3, Settings, Link2 } from "lucide-react";

export default function Layout() {
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="icon">🛡️</span>
          <h1>WAF Control</h1>
        </div>
         <nav className="sidebar-nav">
           <NavLink
             to="/dashboard"
             className={({ isActive }) =>
               `nav-link ${isActive ? "active" : ""}`
             }
           >
             <BarChart3 />
             Dashboard
           </NavLink>
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
         </nav>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
