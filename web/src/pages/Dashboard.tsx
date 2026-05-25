import { useState } from "react";
import { api, severityLabel } from "../api";
import { useAsync } from "../hooks";

const WINDOWS = [
  { label: "1h", value: "1h" },
  { label: "24h", value: "24h" },
  { label: "7d", value: "168h" },
];

export function Dashboard() {
  const [window, setWindow] = useState("24h");
  const { data: stats, error } = useAsync(() => api.stats(window), [window], 5000);

  const total = stats?.total_events ?? 0;
  const blocked = stats?.blocked_events ?? 0;
  const rate = total > 0 ? Math.round((blocked / total) * 100) : 0;
  const maxBucket = Math.max(1, ...(stats?.timeline ?? []).map((t) => t.total));

  return (
    <div>
      <header className="page-head">
        <h1>Dashboard</h1>
        <div className="seg">
          {WINDOWS.map((w) => (
            <button key={w.value} className={window === w.value ? "active" : ""} onClick={() => setWindow(w.value)}>
              {w.label}
            </button>
          ))}
        </div>
      </header>

      {error && <div className="banner error">{error}</div>}

      <div className="cards">
        <div className="card stat">
          <div className="stat-value">{total.toLocaleString()}</div>
          <div className="stat-label">Triggered requests</div>
        </div>
        <div className="card stat">
          <div className="stat-value danger">{blocked.toLocaleString()}</div>
          <div className="stat-label">Blocked</div>
        </div>
        <div className="card stat">
          <div className="stat-value">{rate}%</div>
          <div className="stat-label">Block rate</div>
        </div>
      </div>

      <div className="card">
        <h2>Activity</h2>
        {(stats?.timeline?.length ?? 0) === 0 ? (
          <p className="muted">No WAF activity in this window.</p>
        ) : (
          <div className="timeline">
            {stats!.timeline.map((t) => (
              <div key={t.bucket} className="bar-col" title={`${t.bucket}\ntotal ${t.total}, blocked ${t.blocked}`}>
                <div className="bar">
                  <div className="bar-total" style={{ height: `${(t.total / maxBucket) * 100}%` }}>
                    <div className="bar-blocked" style={{ height: `${(t.blocked / Math.max(1, t.total)) * 100}%` }} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="cards two">
        <div className="card">
          <h2>Top rules</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Message</th>
                <th className="num">Hits</th>
              </tr>
            </thead>
            <tbody>
              {(stats?.top_rules ?? []).map((r) => (
                <tr key={r.rule_id}>
                  <td className="mono">{r.rule_id}</td>
                  <td>{r.message || "—"}</td>
                  <td className="num">{r.count}</td>
                </tr>
              ))}
              {(stats?.top_rules?.length ?? 0) === 0 && (
                <tr>
                  <td colSpan={3} className="muted">
                    —
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h2>Top sources</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Client IP</th>
                <th className="num">Hits</th>
              </tr>
            </thead>
            <tbody>
              {(stats?.top_clients ?? []).map((c) => (
                <tr key={c.client_ip}>
                  <td className="mono">{c.client_ip}</td>
                  <td className="num">{c.count}</td>
                </tr>
              ))}
              {(stats?.top_clients?.length ?? 0) === 0 && (
                <tr>
                  <td colSpan={2} className="muted">
                    —
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <p className="muted small">Severity scale: 0 {severityLabel(0)} … 7 {severityLabel(7)} &middot; live, refreshes every 5s</p>
    </div>
  );
}
