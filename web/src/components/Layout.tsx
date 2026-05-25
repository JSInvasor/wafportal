import { NavLink, Outlet } from "react-router-dom";

const links = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/events", label: "Events" },
  { to: "/rules", label: "Rules" },
  { to: "/sites", label: "Sites" },
];

export function Layout() {
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">WAF</span>portal
        </div>
        <nav>
          {links.map((l) => (
            <NavLink key={l.to} to={l.to} end={l.end} className={({ isActive }) => (isActive ? "active" : "")}>
              {l.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">OWASP Coraza &middot; Core Rule Set</div>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
