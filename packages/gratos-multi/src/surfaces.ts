// Hosted end-user auth surfaces (Ory Kratos / Auth0 Universal Login style),
// served on the tenant's own auth host so a developer ships auth with ZERO UI
// to build: point people at `<endpoint>/login?return_to=<app-url>`, and after a
// successful ceremony the surface sets the first-party session cookie (the auth
// host shares the app's registrable domain) and redirects back.
//
// The account-key / recovery UX follows the hippo.love model: a gentle, large-
// type, "grab a pen and write these 12 words down" flow built for every
// generation (intro → numbered word grid + print → confirm one word). The pages
// dogfood the published @authgravity/browser (account/device keys) and
// @simplewebauthn/browser (passkeys), loaded from esm.sh. Client logic uses
// string concatenation (no template literals) so it embeds cleanly here.

import type { TenantInfo } from './tenant';

// Pinned to the published versions. Bump when @authgravity/browser is released.
const AG_URL = 'https://esm.sh/@authgravity/browser@0.0.7';
const WA_URL = 'https://esm.sh/@simplewebauthn/browser@13.3.0';

export const SURFACE_PATHS = new Set(['/login', '/register', '/logout', '/recover', '/demo', '/consent']);

/**
 * Validate a `return_to` against the tenant's own registrable domain — an
 * open-redirect + post-login phishing guard. Returns the safe URL or null.
 */
export function validateReturnTo(
    returnTo: string | null | undefined,
    tenant: string,
    requestHost: string
): string | null {
    if (!returnTo) return null;
    let u: URL;
    try {
        u = new URL(returnTo);
    } catch {
        return null;
    }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    const host = u.hostname;
    if (host === requestHost) return u.toString(); // same host as the surface — always safe
    if (host === 'localhost' || host === '127.0.0.1') return u.toString(); // dev
    if (tenant === 'localhost') return u.toString();
    if (host === tenant || host.endsWith('.' + tenant)) return u.toString(); // registrable domain
    return null;
}

const STYLES = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; background: #fafafa; color: #18181b; }
  .container { max-width: 30rem; margin: 3.5rem auto; padding: 0 1.5rem; text-align: center; }
  h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: 0.25rem; }
  h2 { font-size: 1.25rem; font-weight: 700; margin-bottom: 0.75rem; }
  .sub { color: #71717a; font-size: 0.95rem; margin-bottom: 1.75rem; }
  .step { font-family: ui-monospace, monospace; font-size: 0.75rem; letter-spacing: 0.08em;
    text-transform: uppercase; color: #a1a1aa; margin-bottom: 0.75rem; }
  /* Large, calm reading text — these pages are for every generation. */
  #root p { font-size: 1.1rem; line-height: 1.6; color: #3f3f46; margin-bottom: 1rem; }
  #root p.muted { font-size: 0.9rem; color: #71717a; }
  #root button { display: block; width: 100%; padding: 0.85rem; margin-bottom: 0.6rem;
    border: 1px solid #d4d4d8; border-radius: 0.6rem; font-size: 1.05rem; font-weight: 600;
    cursor: pointer; background: #fff; }
  #root button:hover { background: #f4f4f5; }
  #root button.primary { background: #18181b; color: #fff; border: none; }
  #root button:disabled { opacity: 0.5; cursor: wait; }
  #root input, #root textarea { width: 100%; padding: 0.75rem 0.85rem; border: 1px solid #d4d4d8;
    border-radius: 0.6rem; font-size: 1.1rem; margin-bottom: 0.6rem; font-family: ui-monospace, monospace; text-align: center; }
  #root textarea { min-height: 5rem; text-align: left; line-height: 1.8; }
  .alt { display: inline-block; margin-top: 1rem; background: none; border: none; color: #71717a;
    font-size: 0.95rem; text-decoration: underline; cursor: pointer; padding: 0.25rem; width: auto !important; }
  .word-grid { list-style-position: inside; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.4rem 1.5rem; margin: 1.25rem auto; padding: 1.1rem 1.25rem; max-width: 22rem; text-align: left;
    background: #fff; border: 1px solid #e4e4e7; border-radius: 0.6rem; }
  .word-grid li { font-size: 1.3rem; line-height: 1.55; color: #18181b; }
  .word-grid li::marker { font-family: ui-monospace, monospace; font-size: 0.8rem; color: #a1a1aa; }
  #status { font-size: 0.95rem; margin-top: 1rem; min-height: 1.2rem; }
  #status.muted { color: #71717a; } #status.error { color: #dc2626; }
  .ok { color: #16a34a; font-weight: 600; }
  code { background: #f4f4f5; padding: 0.1rem 0.35rem; border-radius: 0.25rem; font-size: 0.85rem; word-break: break-all; }
  .powered { margin-top: 2rem; font-size: 0.75rem; color: #a1a1aa; }
  .powered a { color: #a1a1aa; }
  /* Consent surface: left-aligned detail panels for agent requests. */
  .panel { text-align: left; background: #fff; border: 1px solid #e4e4e7; border-radius: 0.6rem;
    padding: 1rem 1.25rem; margin-bottom: 1rem; }
  .panel .lbl { font-family: ui-monospace, monospace; font-size: 0.7rem; letter-spacing: 0.08em;
    text-transform: uppercase; color: #a1a1aa; margin-bottom: 0.2rem; }
  .panel .val { font-size: 1rem; line-height: 1.5; color: #18181b; margin-bottom: 0.75rem; word-break: break-word; }
  .panel .val:last-child { margin-bottom: 0; }
  .budget-row { border-top: 1px solid #f4f4f5; padding-top: 0.75rem; margin-top: 0.75rem; }
  .budget-row input[type="text"] { text-align: left; font-size: 1rem; margin-bottom: 0.4rem; }
  .check-row { display: flex; align-items: center; gap: 0.5rem; font-size: 0.95rem; color: #3f3f46;
    margin-bottom: 0.4rem; text-align: left; }
  .check-row input { width: auto !important; margin: 0 !important; }
  .chat { text-align: left; margin-bottom: 0.75rem; }
  .chat .msg { font-size: 0.95rem; line-height: 1.5; margin-bottom: 0.4rem; }
  .chat .msg .who { font-family: ui-monospace, monospace; font-size: 0.7rem; color: #a1a1aa;
    text-transform: uppercase; margin-right: 0.4rem; }
  /* The print button puts ONLY the key sheet on paper. */
  #print-sheet { display: none; }
  @media print {
    body > .container { display: none !important; }
    #print-sheet { display: block !important; font-family: Georgia, serif; color: #000; padding: 1in; }
    #print-sheet ol { font-size: 1.5rem; line-height: 2; margin-top: 1rem; padding-left: 1.5rem; }
  }
`;

// --- shared client prelude (pure JS, no template literals) ---
const COMMON = `
  const CFG = JSON.parse(document.getElementById('ag-cfg').textContent);
  const PREFIX = location.pathname.replace(/\\/(login|register|logout|recover|demo|consent)\\/?$/, '');
  const API = location.origin + PREFIX;
  const root = document.getElementById('root');
  const statusEl = document.getElementById('status');
  const setStatus = (m, cls) => { statusEl.className = cls || 'muted'; statusEl.textContent = m || ''; };
  const go = () => { if (CFG.returnTo) { location.href = CFG.returnTo; } else { root.innerHTML = '<div class="ok">Done \\u2713</div>'; setStatus(''); } };
  const rt = CFG.returnTo ? ('?return_to=' + encodeURIComponent(CFG.returnTo)) : '';
  // Fill the numbered word grid with id "el" and the hidden print sheet.
  const fillWords = (elId, words) => {
    const grid = document.getElementById(elId);
    const printOl = document.getElementById('print-words');
    grid.innerHTML = ''; if (printOl) printOl.innerHTML = '';
    words.forEach((w) => {
      const li = document.createElement('li'); li.textContent = w; grid.appendChild(li);
      if (printOl) { const p = document.createElement('li'); p.textContent = w; printOl.appendChild(p); }
    });
  };
`;

function page(title: string, sub: string, script: string, returnTo: string | null): string {
    const cfg = JSON.stringify({ returnTo });
    return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${title}</title><style>${STYLES}</style></head>
<body><div class="container">
  <h1>${title}</h1>
  <div class="sub">${sub}</div>
  <div id="root"></div>
  <div id="status" class="muted"></div>
  <div class="powered">Secured by <a href="https://authgravity.org">AuthGravity</a></div>
</div>
<div id="print-sheet" aria-hidden="true">
  <h1>Your account key</h1>
  <p>These 12 words sign you in. Keep this paper somewhere safe \\u2014 like with your important documents.</p>
  <ol id="print-words"></ol>
</div>
<script id="ag-cfg" type="application/json">${cfg}</script>
<script type="module">
import { startRegistration, startAuthentication } from '${WA_URL}';
import { mintKey, decodeKey, registerAccountKey, claimOrRecover, enableDeviceKey, trySilentLogin } from '${AG_URL}';
${COMMON}
${script}
</script></body></html>`;
}

// --- /login ---
const LOGIN = `
  const passkeyLogin = async () => {
    try {
      setStatus('Waiting for your passkey\\u2026');
      const opts = await (await fetch(API + '/v1/login/options', { credentials: 'include' })).json();
      const cred = await startAuthentication({ optionsJSON: opts });
      const res = await fetch(API + '/v1/login/verify', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cred) });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.verified) return go();
      setStatus(data.error || 'That did not verify \\u2014 give it another try.', 'error');
    } catch (e) { setStatus('The passkey prompt was cancelled or failed \\u2014 give it another try.', 'error'); }
  };
  // First-run users land here too: creating an account is offered right on the
  // page, and the 12-words path lives quietly behind "Recover your account".
  const renderLogin = () => {
    root.innerHTML = '<button id="pk" class="primary">Sign in with a passkey</button>'
      + '<button id="create">New here? Create an account</button>'
      + '<button id="rec" class="alt">Recover your account</button>';
    document.getElementById('pk').onclick = passkeyLogin;
    document.getElementById('create').onclick = () => { location.href = PREFIX + '/register' + rt; };
    document.getElementById('rec').onclick = () => { location.href = PREFIX + '/recover' + rt; };
  };
  // A remembered device signs in silently first.
  setStatus('Checking this device\\u2026');
  try {
    const silent = await trySilentLogin(API);
    if (silent && silent.verified) { go(); } else { setStatus(''); renderLogin(); }
  } catch (e) { setStatus(''); renderLogin(); }
`;

// --- /register (create with a passkey OR 12 words; gentle write-it-down flow) ---
const REGISTER = `
  const enableDeviceThenGo = async () => {
    setStatus('Setting up this device\\u2026');
    try { await enableDeviceKey(API, 'this device'); } catch (e) {}
    go();
  };

  let key = null;
  let confirmIndex = 0;
  let mode = 'create';       // 'create' = the 12 words ARE the account; 'recovery' = added after a passkey
  const startWords = (m) => { mode = m; introRecovery(); };

  const introRecovery = () => {
    const isCreate = mode === 'create';
    root.innerHTML =
      '<p class="step">Step 1 of 3</p>'
      + '<h2>' + (isCreate ? 'Your account is 12 secret words' : 'Your recovery key is 12 words') + '</h2>'
      + '<p>On the next screen we will show you 12 words. Write them down on paper and keep that paper somewhere safe \\u2014 like with your important documents.</p>'
      + '<p>The words sign you in, so do not share them. If the paper is lost, no one can look the words up for you.</p>'
      + '<button id="show" class="primary">I have pen and paper \\u2014 show me the words</button>'
      + '<button id="back" class="alt">' + (isCreate ? 'Go back' : 'Skip for now') + '</button>';
    document.getElementById('show').onclick = showWords;
    document.getElementById('back').onclick = isCreate ? renderStart : enableDeviceThenGo;
  };

  const showWords = () => {
    key = mintKey();
    root.innerHTML =
      '<p class="step">Step 2 of 3</p>'
      + '<h2>Write these words on your paper</h2>'
      + '<p>In this order, one by one. Check each word as you go.</p>'
      + '<ol id="wg" class="word-grid"></ol>'
      + '<button id="done" class="primary">Done \\u2014 I have written them down</button>'
      + '<button id="print">Print them instead</button>';
    fillWords('wg', key.words);
    document.getElementById('done').onclick = askConfirm;
    document.getElementById('print').onclick = () => window.print();
  };

  const askConfirm = () => {
    confirmIndex = Math.floor(Math.random() * 12);
    root.innerHTML =
      '<p class="step">Step 3 of 3</p>'
      + '<h2>One quick check</h2>'
      + '<p>Look at your paper: what is word number ' + (confirmIndex + 1) + '?</p>'
      + '<input id="cw" autocomplete="off" autocapitalize="none" spellcheck="false" />'
      + '<button id="save" class="primary">' + (mode === 'create' ? 'Create my account' : 'Save my recovery key') + '</button>'
      + '<button id="again" class="alt">Let me see the words again</button>';
    const input = document.getElementById('cw');
    input.onkeydown = (e) => { if (e.key === 'Enter') saveRecovery(); };
    document.getElementById('save').onclick = saveRecovery;
    document.getElementById('again').onclick = showWords;
    input.focus();
  };

  const saveRecovery = async () => {
    const typed = (document.getElementById('cw').value || '').trim().toLowerCase();
    if (!key || typed !== key.words[confirmIndex]) {
      setStatus('Hmm \\u2014 that does not match word number ' + (confirmIndex + 1) + '. Take another look at your paper and try again.', 'error');
      return;
    }
    setStatus('Making your key\\u2026');
    const res = await registerAccountKey(API, key, mode === 'create' ? 'account key' : 'recovery key');
    if (!res.verified) { setStatus(res.error || 'Something went wrong \\u2014 try once more.', 'error'); return; }
    enableDeviceThenGo();
  };

  const offerRecovery = () => {
    root.innerHTML =
      '<div class="ok">Account created \\u2713</div>'
      + '<p>Make a recovery key in case you lose this device or want to sign in somewhere else? It takes about a minute.</p>'
      + '<button id="mk" class="primary">Set up my recovery key</button>'
      + '<button id="skip">Skip for now</button>';
    document.getElementById('mk').onclick = () => startWords('recovery');
    document.getElementById('skip').onclick = enableDeviceThenGo;
  };

  const createPasskey = async () => {
    try {
      setStatus('Creating your passkey\\u2026');
      const opts = await (await fetch(API + '/v1/register/options', { credentials: 'include' })).json();
      const cred = await startRegistration({ optionsJSON: opts });
      const res = await fetch(API + '/v1/register/verify', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cred) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.verified) { setStatus(data.error || 'Registration failed', 'error'); return; }
      setStatus(''); offerRecovery();
    } catch (e) { setStatus('The passkey prompt was cancelled or failed \\u2014 give it another try.', 'error'); }
  };

  // Passkey-first. The 12-words path stays available as a quiet fallback for
  // devices with no authenticator, but it is no longer a headline option.
  const renderStart = () => {
    root.innerHTML = '<button id="pk" class="primary">Create account with a passkey</button>'
      + '<button id="have" class="alt">Already have an account? Sign in</button>'
      + '<button id="words" class="alt">No passkey on this device? Use 12 words</button>';
    document.getElementById('pk').onclick = createPasskey;
    document.getElementById('words').onclick = () => startWords('create');
    document.getElementById('have').onclick = () => { location.href = PREFIX + '/login' + rt; };
  };
  renderStart();
`;

// --- /recover (sign in / set up with 12 words) ---
const RECOVER = `
  const finish = async (res) => {
    if (!res.verified) { setStatus('That key does not match anyone \\u2014 check the words are in the same order as on your paper.', 'error'); return false; }
    setStatus('Setting up this device\\u2026');
    try { await enableDeviceKey(API); } catch (e) {}
    go(); return true;
  };
  root.innerHTML =
    '<p>Type your 12 words from the paper, with a space between each one. Capital letters do not matter. (An <code>agak1_\\u2026</code> code works too.)</p>'
    + '<textarea id="key" rows="3" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="first second third \\u2026"></textarea>'
    + '<button id="go" class="primary">Open the door</button>'
    + '<button id="back">Go back</button>';
  document.getElementById('back').onclick = () => { location.href = PREFIX + '/login' + rt; };
  document.getElementById('go').onclick = async () => {
    let key;
    try { key = decodeKey(document.getElementById('key').value || ''); }
    catch (e) { setStatus((e && e.message || 'Those words do not look right') + ' \\u2014 check each word against your paper.', 'error'); return; }
    const btn = document.getElementById('go'); btn.disabled = true;
    try {
      setStatus('Trying your key\\u2026');
      await finish(await claimOrRecover(API, key));
    } catch (e) { setStatus(String(e && e.message || e), 'error'); }
    finally { btn.disabled = false; }
  };
`;

// --- /logout ---
const LOGOUT = `
  setStatus('Signing you out\\u2026');
  try { await fetch(API + '/v1/logout', { method: 'POST', credentials: 'include' }); } catch (e) {}
  if (CFG.returnTo) { location.href = CFG.returnTo; } else { root.innerHTML = '<div class="ok">Signed out \\u2713</div>'; setStatus(''); }
`;

// --- /consent (AAuth Person Server: approve agent requests) ---
// Everything an agent sent (descriptions, justifications, questions) is
// UNTRUSTED text: it is only ever rendered via textContent, never innerHTML.
const CONSENT = `
  const qs = new URLSearchParams(location.search);
  let code = (qs.get('code') || '').trim();

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  };
  const kv = (panel, label, value) => {
    panel.appendChild(el('div', 'lbl', label));
    panel.appendChild(el('div', 'val', value));
  };
  const clear = () => { root.innerHTML = ''; };

  const api = async (method, path, body) => {
    const res = await fetch(API + path, {
      method,
      credentials: 'include',
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    return { res, data };
  };

  const done = (msg) => {
    clear();
    root.appendChild(el('div', 'ok', msg + ' \\u2713'));
    const p = el('p', 'muted', 'You can close this page and return to your agent.');
    root.appendChild(p);
    setStatus('');
  };

  const askCode = () => {
    clear();
    root.appendChild(el('p', null, 'Enter the code your agent showed you.'));
    const input = el('input');
    input.autocomplete = 'off'; input.autocapitalize = 'characters'; input.spellcheck = false;
    root.appendChild(input);
    const btn = el('button', 'primary', 'Continue');
    btn.onclick = () => { code = (input.value || '').trim(); if (code) load(); };
    input.onkeydown = (e) => { if (e.key === 'Enter') btn.onclick(); };
    root.appendChild(btn);
    input.focus();
  };

  const decide = async (body, okMsg) => {
    setStatus('Working\\u2026');
    body.code = code;
    const { res, data } = await api('POST', '/v1/aauth/consent', body);
    if (!res.ok) { setStatus(data.error_description || data.error || 'Something went wrong', 'error'); return false; }
    setStatus('');
    if (okMsg) done(okMsg);
    return true;
  };

  const agentLine = (agent) => (agent.sub || 'agent') + ' @ ' + agent.iss;

  const renderChat = (panel, chat) => {
    if (!chat || !chat.length) return;
    const box = el('div', 'chat');
    chat.forEach((m) => {
      const msg = el('div', 'msg');
      msg.appendChild(el('span', 'who', m.from === 'user' ? 'you' : 'agent'));
      msg.appendChild(document.createTextNode(m.text || ''));
      box.appendChild(msg);
    });
    panel.appendChild(el('div', 'lbl', 'Conversation'));
    panel.appendChild(box);
  };

  const questionBox = (refresh) => {
    const wrap = el('div');
    const ta = el('textarea');
    ta.rows = 2; ta.placeholder = 'Ask the agent a question before you decide\\u2026';
    wrap.appendChild(ta);
    const btn = el('button', null, 'Send question');
    btn.onclick = async () => {
      const text = (ta.value || '').trim();
      if (!text) return;
      if (await decide({ answer: text })) { setStatus('Question sent \\u2014 the agent will answer shortly.'); ta.value = '';
        if (refresh) setTimeout(refresh, 4000); }
    };
    wrap.appendChild(btn);
    return wrap;
  };

  const renderToken = (d) => {
    clear();
    const panel = el('div', 'panel');
    kv(panel, 'Agent', agentLine(d.agent));
    kv(panel, 'Wants access to', d.payload.resource);
    if (d.payload.scope) kv(panel, 'Scope', d.payload.scope);
    if (d.payload.justification) kv(panel, 'Why', d.payload.justification);
    root.appendChild(panel);
    const rem = el('label', 'check-row');
    const cb = el('input'); cb.type = 'checkbox'; cb.checked = true;
    rem.appendChild(cb);
    rem.appendChild(document.createTextNode('Remember this approval for next time'));
    root.appendChild(rem);
    const ok = el('button', 'primary', 'Approve');
    ok.onclick = () => decide({ decision: 'approve', remember: cb.checked }, 'Approved');
    root.appendChild(ok);
    const no = el('button', null, 'Deny');
    no.onclick = () => decide({ decision: 'deny' }, 'Denied');
    root.appendChild(no);
  };

  const renderMission = (d) => {
    clear();
    const p = d.proposal;
    const panel = el('div', 'panel');
    kv(panel, 'Agent', agentLine(d.agent));
    kv(panel, 'Mission', p.description);
    if (p.approved_tools && p.approved_tools.length) kv(panel, 'Tools it may use', p.approved_tools.join(', '));
    if (p.resources && p.resources.length) kv(panel, 'Services it will call', p.resources.map((r) => r.resource).join(', '));
    renderChat(panel, d.chat);
    root.appendChild(panel);

    // Budgets: the person may only NARROW — lower an amount, restrict models,
    // or skip an entry entirely. Never add or increase.
    const budgetRows = [];
    if (p.budgets && p.budgets.length) {
      const bp = el('div', 'panel');
      bp.appendChild(el('div', 'lbl', 'Spending limits'));
      p.budgets.forEach((b) => {
        const row = el('div', 'budget-row');
        row.appendChild(el('div', 'val', b.resource));
        const amt = el('input'); amt.type = 'text'; amt.value = b.amount;
        row.appendChild(el('div', 'lbl', 'Up to (' + b.currency + ', max ' + b.amount + ')'));
        row.appendChild(amt);
        const models = [];
        if (b.models && b.models.length) {
          row.appendChild(el('div', 'lbl', 'Models'));
          b.models.forEach((m) => {
            const lr = el('label', 'check-row');
            const mc = el('input'); mc.type = 'checkbox'; mc.checked = true;
            lr.appendChild(mc); lr.appendChild(document.createTextNode(m));
            row.appendChild(lr);
            models.push({ name: m, box: mc });
          });
        }
        const skipRow = el('label', 'check-row');
        const skip = el('input'); skip.type = 'checkbox';
        skipRow.appendChild(skip);
        skipRow.appendChild(document.createTextNode('Skip this one (grant nothing here)'));
        row.appendChild(skipRow);
        bp.appendChild(row);
        budgetRows.push({ resource: b.resource, max: b.amount, amt, models, skip });
      });
      root.appendChild(bp);
    }

    root.appendChild(questionBox(load));

    const ok = el('button', 'primary', 'Approve mission');
    ok.onclick = () => {
      const omit = [];
      const budgets = [];
      for (const r of budgetRows) {
        if (r.skip.checked) { omit.push(r.resource); continue; }
        const entry = { resource: r.resource };
        const v = (r.amt.value || '').trim();
        if (v && v !== r.max) entry.amount = v;
        if (r.models.length) {
          const picked = r.models.filter((m) => m.box.checked).map((m) => m.name);
          if (!picked.length) { setStatus('Pick at least one model or skip the entry.', 'error'); return; }
          if (picked.length !== r.models.length) entry.models = picked;
        }
        if (entry.amount !== undefined || entry.models !== undefined) budgets.push(entry);
      }
      decide({ decision: 'approve', attenuation: { budgets, omit } }, 'Mission approved');
    };
    root.appendChild(ok);
    const no = el('button', null, 'Decline');
    no.onclick = () => decide({ decision: 'deny' }, 'Declined');
    root.appendChild(no);
  };

  const renderPermission = (d) => {
    clear();
    const panel = el('div', 'panel');
    kv(panel, 'Agent', agentLine(d.agent));
    kv(panel, 'Wants to', d.payload.action);
    if (d.payload.description) kv(panel, 'Details', d.payload.description);
    if (d.payload.parameters) kv(panel, 'Parameters', JSON.stringify(d.payload.parameters, null, 2));
    renderChat(panel, d.chat);
    root.appendChild(panel);
    const ok = el('button', 'primary', 'Allow');
    ok.onclick = () => decide({ decision: 'approve' }, 'Allowed');
    root.appendChild(ok);
    const no = el('button', null, 'Deny');
    no.onclick = () => decide({ decision: 'deny' }, 'Denied');
    root.appendChild(no);
  };

  const renderInteraction = (d) => {
    clear();
    const panel = el('div', 'panel');
    kv(panel, 'Agent', agentLine(d.agent));
    const type = d.payload.type;
    if (type === 'completion') {
      kv(panel, 'Says the mission is complete', d.payload.summary || '');
      root.appendChild(panel);
      const ok = el('button', 'primary', 'Accept \\u2014 mission complete');
      ok.onclick = () => decide({ decision: 'approve' }, 'Mission closed');
      root.appendChild(ok);
      const no = el('button', null, 'Not yet');
      no.onclick = () => decide({ decision: 'deny' }, 'Sent back');
      root.appendChild(no);
      return;
    }
    kv(panel, type === 'question' ? 'Asks you' : 'Needs your attention', d.payload.question || d.payload.summary || '');
    renderChat(panel, d.chat);
    root.appendChild(panel);
    const ta = el('textarea');
    ta.rows = 2; ta.placeholder = 'Your answer\\u2026';
    root.appendChild(ta);
    const ok = el('button', 'primary', 'Send answer');
    ok.onclick = () => decide({ decision: 'approve', answer: ta.value || '' }, 'Answer sent');
    root.appendChild(ok);
    const no = el('button', null, 'Dismiss');
    no.onclick = () => decide({ decision: 'deny' }, 'Dismissed');
    root.appendChild(no);
  };

  const load = async () => {
    if (!code) return askCode();
    setStatus('Loading\\u2026');
    const { res, data } = await api('GET', '/v1/aauth/consent?code=' + encodeURIComponent(code));
    if (res.status === 401) {
      location.href = PREFIX + '/login?return_to=' + encodeURIComponent(location.href);
      return;
    }
    if (res.status === 403) { setStatus(''); clear(); root.appendChild(el('p', null, 'This request was addressed to a different account.')); return; }
    if (!res.ok) { setStatus(''); clear(); root.appendChild(el('p', null, 'This code is unknown or has expired. Ask your agent for a fresh one.')); return; }
    setStatus('');
    if (data.kind === 'mission') renderMission(data);
    else if (data.kind === 'permission') renderPermission(data);
    else if (data.kind === 'interaction') renderInteraction(data);
    else renderToken(data);
  };
  load();
`;

export function renderSurface(path: string, returnTo: string | null): string {
    switch (path) {
        case '/login':
            return page('Sign in', 'Welcome back.', LOGIN, returnTo);
        case '/register':
            return page('Create your account', 'One passkey, no password.', REGISTER, returnTo);
        case '/recover':
            return page('Recover your account', 'Sign in with your 12 secret words.', RECOVER, returnTo);
        case '/logout':
            return page('Sign out', '', LOGOUT, returnTo);
        case '/consent':
            return page('Agent request', 'An agent is asking for your approval.', CONSENT, returnTo);
        default:
            return page('Sign in', '', LOGIN, returnTo);
    }
}

/** Unused here but handy for callers wanting the tenant's registrable domain. */
export function tenantOf(info: TenantInfo): string {
    return info.tenant;
}
