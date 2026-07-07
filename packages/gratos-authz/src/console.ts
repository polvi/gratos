// Self-contained authz management console, served at GET /authz on the
// tenant's own host (same pattern as gratos-multi's /demo). Visitors sign in
// with a tenant-pool passkey; admins manage the schema and tuples in-page.
//
// The page derives its API prefix from its own URL so it works on plain hosts
// (authgravity.example.com/authz), sandbox paths (sandbox.../<id>/authz), and
// the authgravity-listen proxy (localhost:8787/authz).

export function consolePage(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorization Console</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; background: #fafafa; color: #18181b; }
    .container { max-width: 720px; margin: 3rem auto; padding: 0 1.5rem 3rem; }
    h1 { font-size: 1.75rem; font-weight: 700; margin-bottom: 0.5rem; }
    h2 { font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; }
    p { color: #52525b; line-height: 1.6; }
    .card { background: #fff; border: 1px solid #e4e4e7; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1rem; }
    button {
      padding: 0.5rem 1rem; border: 1px solid #d4d4d8; border-radius: 0.375rem;
      font-size: 0.875rem; font-weight: 600; cursor: pointer; background: #fff;
    }
    button:hover { background: #f4f4f5; }
    button.primary { background: #18181b; color: #fff; border: none; }
    button.danger { background: none; border: 1px solid #fca5a5; color: #dc2626; }
    input, textarea {
      width: 100%; padding: 0.5rem; border: 1px solid #d4d4d8; border-radius: 0.375rem;
      font-family: ui-monospace, monospace; font-size: 0.8rem; margin-bottom: 0.5rem;
    }
    textarea { min-height: 16rem; }
    code { background: #f4f4f5; padding: 0.125rem 0.375rem; border-radius: 0.25rem; font-size: 0.8rem; word-break: break-all; }
    .row { display: flex; gap: 0.5rem; align-items: center; }
    .muted { color: #71717a; font-size: 0.8rem; }
    .error { color: #ef4444; font-size: 0.875rem; margin-top: 0.5rem; white-space: pre-wrap; }
    .ok { color: #16a34a; font-size: 0.875rem; margin-top: 0.5rem; }
    .badge { padding: 0.2rem 0.5rem; border-radius: 9999px; font-size: 0.7rem; font-weight: 600; }
    .badge.green { background: #dcfce7; color: #166534; }
    .badge.yellow { background: #fef9c3; color: #854d0e; }
    table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
    td, th { text-align: left; padding: 0.375rem 0.5rem; border-bottom: 1px solid #f4f4f5; font-family: ui-monospace, monospace; }
    th { color: #71717a; font-weight: 600; font-family: system-ui, sans-serif; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Authorization Console</h1>
    <p style="margin-bottom: 1.5rem">Relationship-based access control for this tenant. Sign in with a passkey to manage the schema and relationships.</p>
    <div id="root"></div>
  </div>
  <script type="module">
    import { render, h } from 'https://esm.sh/preact@10.28.2';
    import { useState, useEffect } from 'https://esm.sh/preact@10.28.2/hooks';
    import { startRegistration, startAuthentication } from 'https://esm.sh/@simplewebauthn/browser@13.2.2';

    // ".../authz" -> same-origin API prefix (handles sandbox "/<id>/authz").
    const PREFIX = location.pathname.replace(/\\/authz\\/?$/, '');
    const API = location.origin + PREFIX;
    const opts = { credentials: 'include' };
    const json = { 'Content-Type': 'application/json' };

    function AuthGate({ onUser }) {
      const [error, setError] = useState('');

      const finish = async () => {
        const res = await fetch(API + '/v1/whoami', opts);
        if (res.ok) onUser((await res.json()).user_id);
      };

      const register = async () => {
        setError('');
        try {
          const o = await (await fetch(API + '/v1/register/options', opts)).json();
          const cred = await startRegistration({ optionsJSON: o });
          const res = await fetch(API + '/v1/register/verify', { method: 'POST', headers: json, ...opts, body: JSON.stringify(cred) });
          if (res.ok) await finish(); else setError((await res.json()).error || 'Registration failed');
        } catch (e) { setError(String(e)); }
      };

      const login = async () => {
        setError('');
        try {
          const o = await (await fetch(API + '/v1/login/options', opts)).json();
          const cred = await startAuthentication({ optionsJSON: o });
          const res = await fetch(API + '/v1/login/verify', { method: 'POST', headers: json, ...opts, body: JSON.stringify(cred) });
          if (res.ok) await finish(); else setError((await res.json()).error || 'Login failed');
        } catch (e) { setError(String(e)); }
      };

      return h('div', { class: 'card' },
        h('h2', null, 'Sign in'),
        h('div', { class: 'row' },
          h('button', { class: 'primary', onClick: register }, 'Create Account'),
          h('button', { onClick: login }, 'Login'),
        ),
        error && h('p', { class: 'error' }, error),
      );
    }

    function Status({ status, userId }) {
      const open = status.mode === 'open-sandbox';
      return h('div', { class: 'card' },
        h('h2', null, 'Status'),
        h('p', { class: 'muted', style: 'margin-bottom: 0.5rem' }, 'Signed in as ', h('code', null, userId)),
        h('div', { class: 'row' },
          h('span', { class: 'badge ' + (status.can_manage ? 'green' : 'yellow') },
            open ? 'Open sandbox — all users can manage' : 'Managed tenant'),
          status.schema_version && h('span', { class: 'badge green' }, 'Schema v' + status.schema_version),
        ),
        !status.can_manage && h('p', { class: 'muted', style: 'margin-top: 0.75rem' },
          'Schema and relationships are managed by the tenant owner from the AuthGravity dashboard. ',
          'You can browse relationships and test checks below.'),
      );
    }

    const STARTER = JSON.stringify({ definitions: { document: {
      relations: { owner: { subjects: [{ type: 'user' }] },
                   viewer: { subjects: [{ type: 'user' }] } },
      permissions: { view: { union: [{ rel: 'viewer' }, { rel: 'owner' }] } } } } }, null, 2);

    function SchemaEditor({ refresh }) {
      const [text, setText] = useState('');
      const [msg, setMsg] = useState(null);
      useEffect(() => { (async () => {
        const res = await fetch(API + '/v1/authz/schema', opts);
        setText(res.ok ? JSON.stringify((await res.json()).schema, null, 2) : STARTER);
      })(); }, []);

      const save = async () => {
        setMsg(null);
        let doc;
        try { doc = JSON.parse(text); } catch (e) { setMsg({ error: 'Invalid JSON: ' + e.message }); return; }
        const res = await fetch(API + '/v1/authz/schema', { method: 'PUT', headers: json, ...opts, body: JSON.stringify(doc) });
        const data = await res.json();
        if (res.ok) { setMsg({ ok: 'Saved as version ' + data.version }); refresh(); }
        else setMsg({ error: (data.error || 'Save failed') + (data.details ? '\\n' + data.details.join('\\n') : '') });
      };

      return h('div', { class: 'card' },
        h('h2', null, 'Schema'),
        h('textarea', { value: text, onInput: (e) => setText(e.target.value), spellcheck: false }),
        h('button', { class: 'primary', onClick: save }, 'Save Schema'),
        msg && msg.error && h('p', { class: 'error' }, msg.error),
        msg && msg.ok && h('p', { class: 'ok' }, msg.ok),
      );
    }

    function Tuples({ canManage }) {
      const [filterType, setFilterType] = useState('');
      const [rows, setRows] = useState([]);
      const [form, setForm] = useState({ object: '', relation: '', subject: '' });
      const [msg, setMsg] = useState(null);

      const load = async (type) => {
        setMsg(null);
        if (!type) { setRows([]); return; }
        const res = await fetch(API + '/v1/authz/relationships?object_type=' + encodeURIComponent(type), opts);
        if (res.ok) setRows((await res.json()).relationships);
        else setMsg({ error: (await res.json()).error || 'Load failed' });
      };

      const write = async (op, object, relation, subject) => {
        setMsg(null);
        const res = await fetch(API + '/v1/authz/relationships', {
          method: 'POST', headers: json, ...opts,
          body: JSON.stringify({ updates: [{ op, object, relation, subject }] }),
        });
        const data = await res.json();
        if (!res.ok) { setMsg({ error: (data.error || 'Write failed') + (data.details ? '\\n' + data.details.join('\\n') : '') }); return; }
        await load(filterType || object.split(':')[0]);
      };

      const add = () => {
        if (!form.object || !form.relation || !form.subject) return;
        if (!filterType) setFilterType(form.object.split(':')[0]);
        write('touch', form.object, form.relation, form.subject);
      };

      return h('div', { class: 'card' },
        h('h2', null, 'Relationships'),
        h('div', { class: 'row', style: 'margin-bottom: 0.75rem' },
          h('input', { placeholder: 'object type (e.g. document)', value: filterType,
                       onInput: (e) => setFilterType(e.target.value), style: 'margin: 0' }),
          h('button', { onClick: () => load(filterType) }, 'List'),
        ),
        rows.length > 0 && h('table', { style: 'margin-bottom: 0.75rem' },
          h('thead', null, h('tr', null, h('th', null, 'object'), h('th', null, 'relation'), h('th', null, 'subject'), h('th', null, ''))),
          h('tbody', null, rows.map((r) => h('tr', { key: r.object + r.relation + r.subject },
            h('td', null, r.object), h('td', null, r.relation), h('td', null, r.subject),
            h('td', null, canManage && h('button', { class: 'danger', onClick: () => write('delete', r.object, r.relation, r.subject) }, 'x')),
          ))),
        ),
        canManage && h('p', { class: 'muted', style: 'margin-bottom: 0.375rem' }, 'Add: object ', h('code', null, 'type:id'),
          ', relation, subject ', h('code', null, 'user:id'), ' or ', h('code', null, 'group:id#member')),
        canManage && h('div', { class: 'row' },
          h('input', { placeholder: 'document:readme', value: form.object, onInput: (e) => setForm({ ...form, object: e.target.value }), style: 'margin: 0' }),
          h('input', { placeholder: 'viewer', value: form.relation, onInput: (e) => setForm({ ...form, relation: e.target.value }), style: 'margin: 0' }),
          h('input', { placeholder: 'user:abc', value: form.subject, onInput: (e) => setForm({ ...form, subject: e.target.value }), style: 'margin: 0' }),
          h('button', { class: 'primary', onClick: add }, 'Add'),
        ),
        msg && msg.error && h('p', { class: 'error' }, msg.error),
      );
    }

    function Checker() {
      const [form, setForm] = useState({ object: '', permission: '', subject: '' });
      const [result, setResult] = useState(null);

      const run = async () => {
        setResult(null);
        const res = await fetch(API + '/v1/authz/check', {
          method: 'POST', headers: json, ...opts, body: JSON.stringify(form),
        });
        const data = await res.json();
        setResult(res.ok ? (data.allowed ? 'ALLOWED' : 'DENIED') : (data.error || 'Check failed'));
      };

      return h('div', { class: 'card' },
        h('h2', null, 'Check'),
        h('div', { class: 'row' },
          h('input', { placeholder: 'document:readme', value: form.object, onInput: (e) => setForm({ ...form, object: e.target.value }), style: 'margin: 0' }),
          h('input', { placeholder: 'view', value: form.permission, onInput: (e) => setForm({ ...form, permission: e.target.value }), style: 'margin: 0' }),
          h('input', { placeholder: 'user:abc or self', value: form.subject, onInput: (e) => setForm({ ...form, subject: e.target.value }), style: 'margin: 0' }),
          h('button', { class: 'primary', onClick: run }, 'Check'),
        ),
        result && h('p', { class: result === 'ALLOWED' ? 'ok' : 'error' }, result),
      );
    }

    function App() {
      const [userId, setUserId] = useState(null);
      const [status, setStatus] = useState(null);
      const [loading, setLoading] = useState(true);

      const refresh = async () => {
        const res = await fetch(API + '/v1/authz/status', opts);
        if (res.ok) setStatus(await res.json());
      };

      useEffect(() => { (async () => {
        const res = await fetch(API + '/v1/whoami', opts);
        if (res.ok) setUserId((await res.json()).user_id);
        setLoading(false);
      })(); }, []);
      useEffect(() => { if (userId) refresh(); }, [userId]);

      if (loading) return h('p', null, 'Loading...');
      if (!userId) return h(AuthGate, { onUser: setUserId });
      if (!status) return h('p', null, 'Loading...');

      return h('div', null,
        h(Status, { status, userId }),
        status.can_manage && h(SchemaEditor, { refresh }),
        h(Tuples, { canManage: status.can_manage }),
        h(Checker, null),
        h('p', { class: 'muted', style: 'margin-top: 1rem' },
          'API base: ', h('code', null, API + '/v1/authz'),
          ' — same session cookie as your auth API. GET the base for an endpoint index.'),
      );
    }

    render(h(App), document.getElementById('root'));
  </script>
</body>
</html>`;
}
