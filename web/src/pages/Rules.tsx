import { useState } from "react";
import { api, CustomRule } from "../api";
import { useAsync } from "../hooks";

const EXAMPLE = `SecRule REQUEST_URI "@contains /admin" \\
  "id:100001,phase:1,deny,status:403,severity:CRITICAL,msg:'Admin path blocked'"`;

export function Rules() {
  const { data: rules, error, reload } = useAsync(() => api.listRules(), []);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [directive, setDirective] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    setBusy(true);
    try {
      await api.createRule({ name, description, directive, enabled: true });
      setName("");
      setDescription("");
      setDirective("");
      reload();
    } catch (err) {
      setFormError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function toggle(r: CustomRule) {
    try {
      await api.updateRule(r.id, { ...r, enabled: !r.enabled });
      reload();
    } catch (err) {
      setFormError((err as Error).message);
    }
  }

  async function remove(r: CustomRule) {
    if (!confirm(`Delete rule "${r.name}"?`)) return;
    await api.deleteRule(r.id);
    reload();
  }

  return (
    <div>
      <header className="page-head">
        <h1>Custom rules</h1>
      </header>

      <div className="card">
        <h2>Add a rule</h2>
        <p className="muted small">
          SecLang directives applied on top of the Core Rule Set. A directive that fails to compile is rejected, so the
          live engine is never broken.
        </p>
        <form onSubmit={add} className="form">
          <div className="row">
            <label>
              Name
              <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="block-admin" />
            </label>
            <label className="grow">
              Description
              <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="optional" />
            </label>
          </div>
          <label>
            Directive
            <textarea
              value={directive}
              onChange={(e) => setDirective(e.target.value)}
              required
              rows={4}
              spellCheck={false}
              placeholder={EXAMPLE}
            />
          </label>
          {formError && <div className="banner error">{formError}</div>}
          <button className="btn primary" disabled={busy}>
            {busy ? "Validating…" : "Add rule"}
          </button>
        </form>
      </div>

      {error && <div className="banner error">{error}</div>}

      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Directive</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(rules ?? []).map((r) => (
              <tr key={r.id}>
                <td>
                  <strong>{r.name}</strong>
                  {r.description && <div className="muted small">{r.description}</div>}
                </td>
                <td>
                  <pre className="directive">{r.directive}</pre>
                </td>
                <td>
                  <button className={`toggle ${r.enabled ? "on" : "off"}`} onClick={() => toggle(r)}>
                    {r.enabled ? "Enabled" : "Disabled"}
                  </button>
                </td>
                <td>
                  <button className="btn danger ghost" onClick={() => remove(r)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {(rules?.length ?? 0) === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  No custom rules yet — the Core Rule Set is still active.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
