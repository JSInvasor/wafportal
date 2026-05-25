// Typed client for the wafportal admin API. All paths are relative so the same
// build works whether served by the Go binary or the Vite dev proxy.

export type WAFMode = "on" | "detection" | "off";
export type TLSMode = "auto" | "manual" | "off";

export interface Site {
  id: number;
  domain: string;
  upstream_url: string;
  waf_mode: WAFMode;
  tls_mode: TLSMode;
  cert_file?: string;
  key_file?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CustomRule {
  id: number;
  name: string;
  directive: string;
  description?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface WAFEvent {
  id: number;
  timestamp: string;
  tx_id: string;
  domain: string;
  client_ip: string;
  method: string;
  uri: string;
  blocked: boolean;
  status_code: number;
  rule_id: number;
  message: string;
  severity: number;
  anomaly_score: number;
  matched_rules: number[];
}

export interface Stats {
  total_events: number;
  blocked_events: number;
  top_rules: { rule_id: number; message: string; count: number }[];
  top_clients: { client_ip: string; count: number }[];
  timeline: { bucket: string; total: number; blocked: number }[];
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let msg = `request failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {
      /* non-JSON error body */
    }
    // A lost or expired session bounces the user to the login screen, except
    // when they are already there (so a bad-credentials 401 shows its message).
    if (res.status === 401 && location.pathname !== "/login") {
      location.assign("/login");
    }
    throw new Error(msg);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  login: (username: string, password: string) =>
    req<{ username: string }>("/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  logout: () => req<void>("/logout", { method: "POST" }),
  me: () => req<{ username: string }>("/me"),
  changePassword: (current: string, next: string) =>
    req<void>("/account/password", { method: "POST", body: JSON.stringify({ current, new: next }) }),

  listSites: () => req<Site[]>("/sites"),
  createSite: (s: Partial<Site>) => req<Site>("/sites", { method: "POST", body: JSON.stringify(s) }),
  updateSite: (id: number, s: Partial<Site>) => req<Site>(`/sites/${id}`, { method: "PUT", body: JSON.stringify(s) }),
  deleteSite: (id: number) => req<void>(`/sites/${id}`, { method: "DELETE" }),

  listRules: () => req<CustomRule[]>("/rules"),
  createRule: (r: Partial<CustomRule>) => req<CustomRule>("/rules", { method: "POST", body: JSON.stringify(r) }),
  updateRule: (id: number, r: Partial<CustomRule>) => req<CustomRule>(`/rules/${id}`, { method: "PUT", body: JSON.stringify(r) }),
  deleteRule: (id: number) => req<void>(`/rules/${id}`, { method: "DELETE" }),

  listEvents: (params: { domain?: string; blocked?: boolean; limit?: number } = {}) => {
    const q = new URLSearchParams();
    if (params.domain) q.set("domain", params.domain);
    if (params.blocked) q.set("blocked", "true");
    q.set("limit", String(params.limit ?? 200));
    return req<WAFEvent[]>(`/events?${q.toString()}`);
  },
  stats: (window = "24h") => req<Stats>(`/stats?window=${window}`),
};

export const severityLabel = (s: number): string =>
  ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"][s] ?? "—";
