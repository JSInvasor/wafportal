import { NavLink, Navigate, Outlet } from "react-router-dom";
import { api } from "../api";
import { useAsync } from "../hooks";

const links = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/events", label: "Events" },
  { to: "/rules", label: "Rules" },
  { to: "/sites", label: "Sites" },
  { to: "/account", label: "Account" },
];

export function Layout() {
  // Gate the app on a valid session. A 401 from /me triggers a redirect to
  // /login inside the API client, so this mainly handles the loading state.
  const { data, loading } = useAsync(() => api.me(), []);

  if (loading) return null;
  if (!data) return <Navigate to="/login" replace />;

  async function logout() {
    try {
      await api.logout();
    } finally {
      location.assign("/login");
    }
  }

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
        <div className="sidebar-footer">
          <div className="user">
            <span className="muted small">Signed in as</span>
            <strong>{data.username}</strong>
          </div>
          <button className="btn ghost full" onClick={logout}>
            Sign out
          </button>
          <div className="muted small engine">OWASP Coraza &middot; Core Rule Set</div>
        </div>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
