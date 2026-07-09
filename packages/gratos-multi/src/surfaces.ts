// Hosted end-user auth surfaces (Ory Kratos / Auth0 Universal Login style),
// served on the tenant's own auth host so a developer ships auth with ZERO UI
// to build: point people at `<endpoint>/login?return_to=<app-url>`, and after a
// successful ceremony the surface sets the first-party session cookie (the auth
// host shares the app's registrable domain) and redirects back.
//
// The pages dogfood the published @authgravity/browser (account/device keys)
// and @simplewebauthn/browser (passkeys), loaded from esm.sh — so there is no
// inlined crypto to drift from the server. Client logic uses string
// concatenation (no template literals) so it embeds cleanly in these strings.

import type { TenantInfo } from './tenant';

// Pinned to the published versions. Bump when @authgravity/browser is released.
const AG_URL = 'https://esm.sh/@authgravity/browser@0.0.7';
const WA_URL = 'https://esm.sh/@simplewebauthn/browser@13.3.0';

export const SURFACE_PATHS = new Set(['/login', '/register', '/logout', '/recover', '/demo']);

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
  .container { max-width: 400px; margin: 4rem auto; padding: 0 1.5rem; }
  h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.25rem; }
  .sub { color: #71717a; font-size: 0.9rem; margin-bottom: 1.5rem; }
  #root button { display: block; width: 100%; padding: 0.7rem; margin-bottom: 0.6rem;
    border: 1px solid #d4d4d8; border-radius: 0.5rem; font-size: 1rem; font-weight: 600;
    cursor: pointer; background: #fff; }
  #root button:hover { background: #f4f4f5; }
  #root button.primary { background: #18181b; color: #fff; border: none; }
  #root input, #root textarea { width: 100%; padding: 0.6rem; border: 1px solid #d4d4d8;
    border-radius: 0.5rem; font-size: 1rem; margin-bottom: 0.6rem; font-family: inherit; }
  #root textarea { min-height: 4.5rem; font-family: ui-monospace, monospace; }
  #root pre { background: #f4f4f5; padding: 0.75rem; border-radius: 0.5rem; font-size: 1.05rem;
    line-height: 1.9; letter-spacing: 0.02em; white-space: pre-wrap; word-break: break-word; margin-bottom: 0.75rem; }
  #root p { color: #52525b; font-size: 0.9rem; line-height: 1.55; margin-bottom: 0.75rem; }
  #root a { color: #2563eb; text-decoration: none; font-size: 0.9rem; }
  .muted { color: #71717a; font-size: 0.85rem; text-align: center; margin: 0.5rem 0; }
  .ok { color: #16a34a; font-weight: 600; }
  .error { color: #ef4444; }
  code { background: #f4f4f5; padding: 0.1rem 0.35rem; border-radius: 0.25rem; font-size: 0.85rem; word-break: break-all; }
  .powered { text-align: center; margin-top: 2rem; font-size: 0.75rem; color: #a1a1aa; }
  .powered a { color: #a1a1aa; }
`;

// --- shared client prelude (pure JS, no template literals) ---
const COMMON = `
  const CFG = JSON.parse(document.getElementById('ag-cfg').textContent);
  const PREFIX = location.pathname.replace(/\\/(login|register|logout|recover|demo)\\/?$/, '');
  const API = location.origin + PREFIX;
  const root = document.getElementById('root');
  const statusEl = document.getElementById('status');
  const setStatus = (m, cls) => { statusEl.className = cls || 'muted'; statusEl.textContent = m || ''; };
  const go = () => { if (CFG.returnTo) { location.href = CFG.returnTo; } else { root.innerHTML = '<div class="ok">Done \\u2713</div>'; setStatus(''); } };
  const rt = CFG.returnTo ? ('?return_to=' + encodeURIComponent(CFG.returnTo)) : '';
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
<script id="ag-cfg" type="application/json">${cfg}</script>
<script type="module">
import { startRegistration, startAuthentication } from '${WA_URL}';
import { mintKey, decodeKey, registerAccountKey, loginWithAccountKey, claimOrRecover, enableDeviceKey, trySilentLogin } from '${AG_URL}';
${COMMON}
${script}
</script></body></html>`;
}

// --- /login ---
const LOGIN = `
  const renderLogin = () => {
    root.innerHTML = '<button id="pk" class="primary">Sign in with a passkey</button>'
      + '<div class="muted">or</div>'
      + '<a href="' + PREFIX + '/recover' + rt + '">Use an account key</a>';
    document.getElementById('pk').onclick = passkeyLogin;
  };
  const passkeyLogin = async () => {
    try {
      setStatus('Waiting for your passkey\\u2026');
      const opts = await (await fetch(API + '/v1/login/options', { credentials: 'include' })).json();
      const cred = await startAuthentication({ optionsJSON: opts });
      const res = await fetch(API + '/v1/login/verify', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cred) });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.verified) return go();
      setStatus(data.error || 'Sign-in failed', 'error');
      renderLogin();
    } catch (e) { setStatus(String(e && e.message || e), 'error'); renderLogin(); }
  };
  // Try a silent device-key login first; fall back to the buttons.
  setStatus('Checking this device\\u2026');
  try {
    const silent = await trySilentLogin(API);
    if (silent && silent.verified) { go(); } else { setStatus(''); renderLogin(); }
  } catch (e) { setStatus(''); renderLogin(); }
`;

// --- /register ---
const REGISTER = `
  const enableDeviceThenGo = async () => {
    setStatus('Enabling quick sign-in on this device\\u2026');
    try { await enableDeviceKey(API, 'this device'); } catch (e) {}
    go();
  };
  const showRecoveryKey = () => {
    const key = mintKey();
    const idx = Math.floor(Math.random() * 12);
    root.innerHTML = '<p>Write these 12 words on paper and keep them safe \\u2014 they are the only way back into your account if you lose this device.</p>'
      + '<pre>' + key.words.join(' ') + '</pre>'
      + '<p class="muted">Compact code: <code>' + key.compact + '</code></p>'
      + '<input id="cw" placeholder="Type word #' + (idx + 1) + ' to confirm" />'
      + '<button id="save" class="primary">I saved it</button>';
    document.getElementById('save').onclick = async () => {
      const val = (document.getElementById('cw').value || '').trim().toLowerCase();
      if (val !== key.words[idx]) { setStatus('That word does not match \\u2014 check your paper.', 'error'); return; }
      setStatus('Saving your recovery key\\u2026');
      const res = await registerAccountKey(API, key, 'recovery key');
      if (!res.verified) { setStatus(res.error || 'Could not save the recovery key', 'error'); return; }
      enableDeviceThenGo();
    };
  };
  const offerRecovery = () => {
    root.innerHTML = '<div class="ok">Account created \\u2713</div>'
      + '<p>Create a recovery key in case you lose this device?</p>'
      + '<button id="mk" class="primary">Create a recovery key</button>'
      + '<button id="skip">Skip for now</button>';
    document.getElementById('mk').onclick = showRecoveryKey;
    document.getElementById('skip').onclick = enableDeviceThenGo;
  };
  const createPasskey = async () => {
    try {
      setStatus('Creating your passkey\\u2026');
      const opts = await (await fetch(API + '/v1/register/options', { credentials: 'include' })).json();
      const label = (document.getElementById('label').value || '').trim();
      if (label) { opts.user.name = label; opts.user.displayName = label; }
      const cred = await startRegistration({ optionsJSON: opts });
      const res = await fetch(API + '/v1/register/verify', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cred) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.verified) { setStatus(data.error || 'Registration failed', 'error'); return; }
      setStatus('');
      offerRecovery();
    } catch (e) { setStatus(String(e && e.message || e), 'error'); }
  };
  root.innerHTML = '<input id="label" placeholder="Name this passkey (optional)" />'
    + '<button id="create" class="primary">Create account with a passkey</button>'
    + '<div class="muted">or</div>'
    + '<a href="' + PREFIX + '/recover' + rt + '">I already have an account key</a>';
  document.getElementById('create').onclick = createPasskey;
`;

// --- /recover (account-key sign-in / claim) ---
const RECOVER = `
  root.innerHTML = '<p>Enter your account key \\u2014 the <code>agak1_\\u2026</code> code or your 12 words.</p>'
    + '<textarea id="key" placeholder="agak1_\\u2026 or 12 words"></textarea>'
    + '<button id="go" class="primary">Continue</button>'
    + '<a href="' + PREFIX + '/login' + rt + '">Back to sign in</a>';
  document.getElementById('go').onclick = async () => {
    let key;
    try { key = decodeKey(document.getElementById('key').value || ''); }
    catch (e) { setStatus('That key does not look right: ' + (e && e.message || e), 'error'); return; }
    setStatus('Signing you in\\u2026');
    try {
      const res = await claimOrRecover(API, key);
      if (res.verified) return go();
      setStatus(res.error || 'Could not sign in with that key', 'error');
    } catch (e) { setStatus(String(e && e.message || e), 'error'); }
  };
`;

// --- /logout ---
const LOGOUT = `
  setStatus('Signing you out\\u2026');
  try { await fetch(API + '/v1/logout', { method: 'POST', credentials: 'include' }); } catch (e) {}
  if (CFG.returnTo) { location.href = CFG.returnTo; } else { root.innerHTML = '<div class="ok">Signed out \\u2713</div>'; setStatus(''); }
`;

export function renderSurface(path: string, returnTo: string | null): string {
    switch (path) {
        case '/login':
            return page('Sign in', 'Use your passkey, or an account key.', LOGIN, returnTo);
        case '/register':
            return page('Create your account', 'One passkey, no password.', REGISTER, returnTo);
        case '/recover':
            return page('Use an account key', 'For a new device or a lost passkey.', RECOVER, returnTo);
        case '/logout':
            return page('Sign out', '', LOGOUT, returnTo);
        default:
            return page('Sign in', '', LOGIN, returnTo);
    }
}

/** Unused here but handy for callers wanting the tenant's registrable domain. */
export function tenantOf(info: TenantInfo): string {
    return info.tenant;
}
