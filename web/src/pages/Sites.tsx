import { useState } from "react";
import { api, Site, TLSMode, WAFMode } from "../api";
import { useAsync } from "../hooks";

const emptyForm: Partial<Site> = {
  domain: "",
  upstream_url: "",
  waf_mode: "on",
  tls_mode: "auto",
  cert_file: "",
  key_file: "",
  enabled: true,
};

export function Sites() {
  const { data: sites, error, reload } = useAsync(() => api.listSites(), []);
  const [form, setForm] = useState<Partial<Site>>(emptyForm);
  const [editing, setEditing] = useState<number | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function startEdit(s: Site) {
    setEditing(s.id);
    setForm(s);
    setFormError(null);
  }

  function reset() {
    setEditing(null);
    setForm(emptyForm);
    setFormError(null);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    setBusy(true);
    try {
      if (editing) await api.updateSite(editing, form);
      else await api.createSite(form);
      reset();
      reload();
    } catch (err) {
      setFormError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function toggle(s: Site) {
    await api.updateSite(s.id, { ...s, enabled: !s.enabled });
    reload();
  }

  async function remove(s: Site) {
    if (!confirm(`Delete site "${s.domain}"?`)) return;
    await api.deleteSite(s.id);
    reload();
  }

  return (
    <div>
      <header className="page-head">
        <h1>Protected sites</h1>
      </header>

      <div className="card">
        <h2>{editing ? "Edit site" : "Add a site"}</h2>
        <form onSubmit={submit} className="form">
          <div className="row">
            <label className="grow">
              Domain
              <input
                value={form.domain ?? ""}
                onChange={(e) => setForm({ ...form, domain: e.target.value })}
                required
                placeholder="example.com"
              />
            </label>
            <label className="grow">
              Upstream URL
              <input
                value={form.upstream_url ?? ""}
                onChange={(e) => setForm({ ...form, upstream_url: e.target.value })}
                required
                placeholder="http://127.0.0.1:3000"
              />
            </label>
          </div>
          <div className="row">
            <label>
              WAF mode
              <select value={form.waf_mode} onChange={(e) => setForm({ ...form, waf_mode: e.target.value as WAFMode })}>
                <option value="on">On (block)</option>
                <option value="detection">Detection only</option>
                <option value="off">Off</option>
              </select>
            </label>
            <label>
              TLS mode
              <select value={form.tls_mode} onChange={(e) => setForm({ ...form, tls_mode: e.target.value as TLSMode })}>
                <option value="auto">Auto (Let's Encrypt)</option>
                <option value="manual">Manual cert</option>
                <option value="off">Off (HTTP)</option>
              </select>
            </label>
          </div>
          {form.tls_mode === "manual" && (
            <div className="row">
              <label className="grow">
                Certificate file
                <input
                  value={form.cert_file ?? ""}
                  onChange={(e) => setForm({ ...form, cert_file: e.target.value })}
                  placeholder="/etc/wafportal/example.crt"
                />
              </label>
              <label className="grow">
                Key file
                <input
                  value={form.key_file ?? ""}
                  onChange={(e) => setForm({ ...form, key_file: e.target.value })}
                  placeholder="/etc/wafportal/example.key"
                />
              </label>
            </div>
          )}
          {formError && <div className="banner error">{formError}</div>}
          <div className="row">
            <button className="btn primary" disabled={busy}>
              {busy ? "Saving…" : editing ? "Save changes" : "Add site"}
            </button>
            {editing && (
              <button type="button" className="btn ghost" onClick={reset}>
                Cancel
              </button>
            )}
          </div>
        </form>
      </div>

      {error && <div className="banner error">{error}</div>}

      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Upstream</th>
              <th>WAF</th>
              <th>TLS</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(sites ?? []).map((s) => (
              <tr key={s.id}>
                <td>
                  <strong>{s.domain}</strong>
                </td>
                <td className="mono">{s.upstream_url}</td>
                <td>
                  <span className={`pill waf-${s.waf_mode}`}>{s.waf_mode}</span>
                </td>
                <td>
                  <span className="pill">{s.tls_mode}</span>
                </td>
                <td>
                  <button className={`toggle ${s.enabled ? "on" : "off"}`} onClick={() => toggle(s)}>
                    {s.enabled ? "Enabled" : "Disabled"}
                  </button>
                </td>
                <td className="actions">
                  <button className="btn ghost" onClick={() => startEdit(s)}>
                    Edit
                  </button>
                  <button className="btn danger ghost" onClick={() => remove(s)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {(sites?.length ?? 0) === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  No sites yet — add one to start protecting traffic.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
