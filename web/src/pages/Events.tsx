import { useState } from "react";
import { api, severityLabel, WAFEvent } from "../api";
import { useAsync } from "../hooks";

export function Events() {
  const [domain, setDomain] = useState("");
  const [blockedOnly, setBlockedOnly] = useState(false);
  const { data: events, error, loading } = useAsync(
    () => api.listEvents({ domain: domain || undefined, blocked: blockedOnly, limit: 200 }),
    [domain, blockedOnly],
    5000
  );

  return (
    <div>
      <header className="page-head">
        <h1>Events</h1>
        <div className="filters">
          <input placeholder="Filter by domain" value={domain} onChange={(e) => setDomain(e.target.value)} />
          <label className="check">
            <input type="checkbox" checked={blockedOnly} onChange={(e) => setBlockedOnly(e.target.checked)} />
            Blocked only
          </label>
        </div>
      </header>

      {error && <div className="banner error">{error}</div>}

      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Domain</th>
              <th>Client</th>
              <th>Request</th>
              <th>Rule</th>
              <th>Severity</th>
              <th className="num">Score</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {(events ?? []).map((e: WAFEvent) => (
              <tr key={e.id}>
                <td className="nowrap">{new Date(e.timestamp).toLocaleString()}</td>
                <td>{e.domain}</td>
                <td className="mono">{e.client_ip}</td>
                <td className="req" title={e.uri}>
                  <span className="method">{e.method}</span> {e.uri}
                </td>
                <td className="mono" title={e.message}>
                  {e.rule_id || "—"}
                  <div className="muted small ellipsis">{e.message}</div>
                </td>
                <td>
                  <span className={`sev sev-${e.severity}`}>{severityLabel(e.severity)}</span>
                </td>
                <td className="num">{e.anomaly_score}</td>
                <td>
                  <span className={e.blocked ? "badge block" : "badge detect"}>{e.blocked ? "Blocked" : "Detected"}</span>
                </td>
              </tr>
            ))}
            {!loading && (events?.length ?? 0) === 0 && (
              <tr>
                <td colSpan={8} className="muted">
                  No events match.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
