import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { WorkerEntrypoint } from 'cloudflare:workers';

import { resolveTenant } from './tenant';
import { authRoutes } from './auth';
import { sessionRoutes, getSessionId } from './session';
import { keyRoutes } from './keys';
import { getUser } from './db';
import { parseSessionValue, resolveSession } from './sessions';
import { sha256Hex } from './hash';

import type { AuthzRPC } from '../../gratos-authz/src/index';

export type Env = {
    DB: D1Database;
    KV: KVNamespace;
    // gratos-authz worker (no public route); mounted at /authz + /v1/authz/*,
    // plus control-plane RPC (grantTenantOwners/cleanupTenant).
    AUTHZ: Service<AuthzRPC>;
};

export type Variables = {
    userId: string;
};

/**
 * RPC entrypoint for service bindings.
 * Other workers call AUTH.resolveSession(tenant, sessionId) to validate sessions.
 */
export class AuthRPC extends WorkerEntrypoint<Env> {
    /**
     * Resolve a session to a user ID.
     * Returns the user ID if valid, or null if expired/invalid.
     */
    async resolveSession(tenant: string, sessionId: string): Promise<string | null> {
        const session = parseSessionValue(await this.env.KV.get(`session:${tenant}:${sessionId}`));
        if (!session) return null;

        const user = await getUser(this.env.DB, tenant, session.userId);
        if (!user) return null;

        return (user as any).id;
    }

    /**
     * Delete throwaway sandbox pools older than maxAgeMs (default 7 days).
     * Removes users + public_keys for each expired sandbox tenant, then the
     * sandbox record itself. KV sessions expire on their own TTL.
     * Intended to be called from the provisioner's scheduled cron.
     */
    async sweepSandboxes(maxAgeMs: number = 7 * 24 * 60 * 60 * 1000): Promise<{ swept: number }> {
        const cutoff = Date.now() - maxAgeMs;
        // Only anonymous sandboxes are throwaway; owned ones (user_id set)
        // persist until deleted from the dashboard.
        const { results } = await this.env.DB.prepare(
            "SELECT id FROM sandboxes WHERE created_at < ? AND id LIKE 'sandbox.%' AND user_id IS NULL"
        ).bind(cutoff).all();

        let swept = 0;
        for (const row of (results || []) as Array<{ id: string }>) {
            const tenant = row.id;
            await this.env.DB.prepare('DELETE FROM public_keys WHERE tenant = ?').bind(tenant).run();
            await this.env.DB.prepare('DELETE FROM users WHERE tenant = ?').bind(tenant).run();
            await this.env.DB.prepare('DELETE FROM sandboxes WHERE id = ?').bind(tenant).run();
            try {
                await this.env.AUTHZ.cleanupTenant(tenant);
            } catch (e) {
                console.error('authz cleanup failed for swept sandbox', tenant, e);
            }
            swept++;
        }
        return { swept };
    }

    /**
     * Owned sandboxes and their root-pool owners, for the provisioner's
     * authz-ownership reconcile (self-heals failed mint-time grants).
     */
    async listOwnedSandboxes(): Promise<Array<{ tenant: string; userId: string }>> {
        const { results } = await this.env.DB.prepare(
            'SELECT id, user_id FROM sandboxes WHERE user_id IS NOT NULL'
        ).all();
        return ((results || []) as Array<{ id: string; user_id: string }>).map((r) => ({
            tenant: r.id,
            userId: r.user_id,
        }));
    }

    /**
     * Get user count and active session count for a tenant.
     */
    async getTenantStats(tenant: string): Promise<{ users: number; sessions: number }> {
        const userCount = await this.env.DB.prepare(
            'SELECT COUNT(*) as count FROM users WHERE tenant = ?'
        ).bind(tenant).first() as any;

        let sessions = 0;
        let cursor: string | undefined;
        do {
            const list = await this.env.KV.list({
                prefix: `session:${tenant}:`,
                cursor,
            });
            sessions += list.keys.length;
            cursor = list.list_complete ? undefined : (list.cursor as string);
        } while (cursor);

        return {
            users: userCount?.count ?? 0,
            sessions,
        };
    }
}

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.use('/*', async (c, next) => {
    const url = new URL(c.req.url);
    const tenantInfo = resolveTenant(url);

    // Dynamic CORS: allow origins on the same tenant domain
    return cors({
        origin: (origin) => {
            try {
                const host = new URL(origin).hostname;
                if (host === tenantInfo.tenant || host.endsWith('.' + tenantInfo.tenant)) {
                    return origin;
                }
                // Sandbox tenants are driven from a developer's local app.
                if (tenantInfo.sandbox && (host === 'localhost' || host === '127.0.0.1')) {
                    return origin;
                }
            } catch {
                // invalid origin
            }
            // Allow localhost in dev
            if (tenantInfo.tenant === 'localhost') return origin;
            return '';
        },
        allowHeaders: ['Content-Type', 'Authorization'],
        allowMethods: ['POST', 'GET', 'OPTIONS', 'DELETE', 'PUT'],
        exposeHeaders: ['Content-Length'],
        maxAge: 600,
        credentials: true,
    })(c, next);
});

// Health check
app.get('/', (c) => c.json({ status: 'ok' }));

/**
 * Discovery document for this host. An agent pointed at a domain fetches
 * `<host>/.well-known/authgravity` and learns the endpoint + the single
 * `llms.txt` to read — no prompt needs to spell any of this out.
 */
function wellKnown(endpoint: string, tenant: string) {
    return {
        service: 'authgravity',
        tenant,
        endpoint,
        llms_txt: `${endpoint}/llms.txt`,
        console: `${endpoint}/authz`,
        auth: {
            register_options: '/v1/register/options',
            register_verify: '/v1/register/verify',
            login_options: '/v1/login/options',
            login_verify: '/v1/login/verify',
            whoami: '/v1/whoami',
            logout: '/v1/logout',
        },
        authz: '/v1/authz',
    };
}

// Domain/root auth hosts (no path prefix). Sandbox hosts carry the id in the
// path and are handled inside the tenant router below.
app.get('/.well-known/authgravity', (c) => {
    const url = new URL(c.req.url);
    return c.json(wellKnown(url.origin, resolveTenant(url).tenant), 200, {
        'Cache-Control': 'no-cache',
    });
});

// Demo page — self-contained auth demo served from the authgravity subdomain
app.get('/demo', (c) => {
    const url = new URL(c.req.url);
    const apiBaseUrl = url.origin;
    return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Auth Demo</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; background: #fafafa; color: #18181b; }
    .container { max-width: 480px; margin: 3rem auto; padding: 0 1.5rem; }
    h1 { font-size: 1.75rem; font-weight: 700; margin-bottom: 0.5rem; }
    p { color: #52525b; line-height: 1.6; margin-bottom: 1.5rem; }
    .card { background: #fff; border: 1px solid #e4e4e7; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1rem; }
    .card h2 { font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; }
    #auth-root button {
      display: block; width: 100%; padding: 0.625rem; margin-bottom: 0.5rem;
      border: 1px solid #d4d4d8; border-radius: 0.375rem;
      font-size: 1rem; font-weight: 600; cursor: pointer; background: #fff;
    }
    #auth-root button:hover { background: #f4f4f5; }
    .user-info { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 0.5rem; padding: 1rem; }
    .user-info p { color: #15803d; margin: 0; }
    code { background: #f4f4f5; padding: 0.125rem 0.375rem; border-radius: 0.25rem; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Auth Demo</h1>
    <p>This page is served from <code>${url.hostname}</code>. Try registering a passkey or signing in.</p>
    <div id="auth-root"></div>
  </div>
  <script type="module">
    import { render, h } from 'https://esm.sh/preact@10.28.2';
    import { useState, useEffect } from 'https://esm.sh/preact@10.28.2/hooks';
    import { startRegistration, startAuthentication } from 'https://esm.sh/@simplewebauthn/browser@13.2.2';
    import { p256 } from 'https://esm.sh/@noble/curves@2.2.0/nist.js';
    import { sha256 } from 'https://esm.sh/@noble/hashes@2.2.0/sha2.js';
    import { hkdf } from 'https://esm.sh/@noble/hashes@2.2.0/hkdf.js';

    const API = '${apiBaseUrl}';

    // --- account-key spec (matches the published vectors) ---
    const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
    const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
    function b32enc(bytes, chars) {
      let bits = 0, value = 0, out = '';
      for (const byte of bytes) {
        value = (value << 8) | byte; bits += 8;
        while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
      }
      if (bits > 0) out += B32[(value << (5 - bits)) & 31];
      return out.slice(0, chars);
    }
    function b32dec(s, byteLen) {
      let bits = 0, value = 0; const out = [];
      for (const ch of s) {
        const idx = B32.indexOf(ch);
        if (idx === -1) throw new Error('invalid character "' + ch + '"');
        value = (value << 5) | idx; bits += 5;
        if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
      }
      return new Uint8Array(out.slice(0, byteLen));
    }
    function checksum4(entropy) {
      const d = sha256(entropy);
      const v = (d[0] << 12) | (d[1] << 4) | (d[2] >>> 4);
      return B32[(v >>> 15) & 31] + B32[(v >>> 10) & 31] + B32[(v >>> 5) & 31] + B32[v & 31];
    }
    const encodeCompact = (entropy) => 'agak1_' + b32enc(entropy, 26) + checksum4(entropy);
    function decodeCompact(s) {
      const n = s.trim().toLowerCase();
      if (!n.startsWith('agak1_')) throw new Error('not an account key');
      const body = n.slice(6);
      if (body.length !== 30) throw new Error('wrong length');
      const entropy = b32dec(body.slice(0, 26), 16);
      if (checksum4(entropy) !== body.slice(26)) throw new Error('checksum mismatch — check for typos');
      return entropy;
    }
    async function encodeWords(entropy) {
      const words = await (await fetch(API + '/v1/key/wordlist.json')).json();
      const check = sha256(entropy)[0] >>> 4;
      let bits = '';
      for (const b of entropy) bits += b.toString(2).padStart(8, '0');
      bits += check.toString(2).padStart(4, '0');
      const out = [];
      for (let i = 0; i < 12; i++) out.push(words[parseInt(bits.slice(i * 11, (i + 1) * 11), 2)]);
      return out.join(' ');
    }
    async function decodeWords(input) {
      const words = await (await fetch(API + '/v1/key/wordlist.json')).json();
      const parts = input.trim().toLowerCase().split(/\\s+/);
      if (parts.length !== 12) throw new Error('expected 12 words');
      let bits = '';
      for (const w of parts) {
        const idx = words.indexOf(w);
        if (idx === -1) throw new Error('unknown word "' + w + '"');
        bits += idx.toString(2).padStart(11, '0');
      }
      const entropy = new Uint8Array(16);
      for (let i = 0; i < 16; i++) entropy[i] = parseInt(bits.slice(i * 8, (i + 1) * 8), 2);
      if ((sha256(entropy)[0] >>> 4) !== parseInt(bits.slice(128), 2)) throw new Error('checksum mismatch');
      return entropy;
    }
    function derivePriv(entropy, tenant) {
      const enc = new TextEncoder();
      const okm = hkdf(sha256, entropy, enc.encode(tenant), enc.encode('authgravity/softkey/v1'), 40);
      let x = 0n;
      for (const b of okm) x = (x << 8n) | BigInt(b);
      const d = (x % (p256.Point.Fn.ORDER - 1n)) + 1n;
      const bytes = new Uint8Array(32);
      let v = d;
      for (let i = 31; i >= 0; i--) { bytes[i] = Number(v & 0xffn); v >>= 8n; }
      return bytes;
    }
    const payloadFor = (context, challenge, tenant) => context + '\\n' + challenge + '\\n' + tenant;

    async function keyCeremony(kind, priv, extra, endpoint) {
      const opts = await (await fetch(API + '/v1/key/' + endpoint + '/options', { credentials: 'include' })).json();
      const payload = new TextEncoder().encode(payloadFor(opts.context, opts.challenge, opts.tenant));
      let publicKey, signature;
      if (priv instanceof Uint8Array) {
        publicKey = p256.getPublicKey(priv, false);
        signature = p256.sign(payload, priv, { prehash: true });
      } else {
        publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', priv.publicKey));
        signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv.privateKey, payload));
      }
      const res = await fetch(API + '/v1/key/' + endpoint + '/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ challenge: opts.challenge, public_key: b64u(publicKey), signature: b64u(signature), ...extra }),
      });
      return { ok: res.ok, data: await res.json(), tenant: opts.tenant };
    }

    // --- device key storage (non-extractable, origin-scoped) ---
    function idb() {
      return new Promise((resolve, reject) => {
        const req = indexedDB.open('gratos-keys', 1);
        req.onupgradeneeded = () => req.result.createObjectStore('keys');
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
    async function idbGet(k) {
      const db = await idb();
      return new Promise((resolve) => {
        const tx = db.transaction('keys').objectStore('keys').get(k);
        tx.onsuccess = () => resolve(tx.result ?? null);
        tx.onerror = () => resolve(null);
      });
    }
    async function idbSet(k, v) {
      const db = await idb();
      return new Promise((resolve) => {
        const tx = db.transaction('keys', 'readwrite').objectStore('keys').put(v, k);
        tx.onsuccess = () => resolve(true);
        tx.onerror = () => resolve(false);
      });
    }
    async function enableDeviceKey() {
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
      const r = await keyCeremony('devicekey', pair, { kind: 'devicekey', label: 'this device' }, 'register');
      if (r.ok) await idbSet('device', pair);
      return r;
    }

    function App() {
      const [user, setUser] = useState(null);
      const [loading, setLoading] = useState(true);
      const [error, setError] = useState('');
      const [view, setView] = useState('welcome'); // welcome | keypanel | savekey
      const [hasDeviceKey, setHasDeviceKey] = useState(false);
      const [newKey, setNewKey] = useState(null); // {compact, words, confirm}
      const [pasted, setPasted] = useState('');
      const [notice, setNotice] = useState('');

      const checkSession = async () => {
        try {
          const res = await fetch(API + '/v1/whoami', { credentials: 'include' });
          if (res.ok) setUser(await res.json());
        } catch {}
        setLoading(false);
      };

      useEffect(() => {
        checkSession();
        idbGet('device').then((k) => setHasDeviceKey(!!k));
      }, []);

      const register = async () => {
        setError('');
        try {
          const opts = await (await fetch(API + '/v1/register/options', { credentials: 'include' })).json();
          const cred = await startRegistration({ optionsJSON: opts });
          const verRes = await fetch(API + '/v1/register/verify', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
            body: JSON.stringify(cred),
          });
          if (verRes.ok) { await checkSession(); }
          else { const d = await verRes.json(); setError(d.error || 'Registration failed'); }
        } catch (e) { setError(String(e)); }
      };

      const login = async () => {
        setError('');
        try {
          const opts = await (await fetch(API + '/v1/login/options', { credentials: 'include' })).json();
          const cred = await startAuthentication({ optionsJSON: opts });
          const verRes = await fetch(API + '/v1/login/verify', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
            body: JSON.stringify(cred),
          });
          if (verRes.ok) { await checkSession(); }
          else { const d = await verRes.json(); setError(d.error || 'Login failed'); }
        } catch (e) { setError(String(e)); }
      };

      const logout = async () => {
        await fetch(API + '/v1/logout', { method: 'POST', credentials: 'include' });
        setUser(null); setView('welcome'); setNewKey(null); setNotice('');
      };

      // account key: create (signup or recovery enrollment while signed in)
      const createAccountKey = async () => {
        setError('');
        const entropy = crypto.getRandomValues(new Uint8Array(16));
        const compact = encodeCompact(entropy);
        setNewKey({ compact, words: await encodeWords(entropy), entropy, confirm: '' });
        setView('savekey');
      };

      const confirmSaved = async () => {
        setError('');
        try {
          if (newKey.confirm.trim().toLowerCase() !== newKey.compact) {
            setError('Pasted key does not match — copy it again.');
            return;
          }
          const optsRes = await fetch(API + '/v1/key/login/options', { credentials: 'include' });
          const tenant = (await optsRes.json()).tenant;
          const priv = derivePriv(newKey.entropy, tenant);
          const r = await keyCeremony('softkey', priv, { kind: 'softkey', label: user ? 'recovery key' : 'account key' }, 'register');
          if (!r.ok) { setError(r.data.error || 'Registration failed'); return; }
          setNewKey(null); setView('welcome');
          setNotice(user ? 'Recovery key saved to your account.' : '');
          await checkSession();
        } catch (e) { setError(String(e)); }
      };

      // Bring-your-own phrase: claim a new account from an externally-minted
      // seed, or recover an existing one — same words either way. Try register
      // first (creates the account); a 409 means it already exists, so log in.
      const claimWithPhrase = async () => {
        setError('');
        try {
          const input = pasted.trim();
          const tenant = (await (await fetch(API + '/v1/key/login/options', { credentials: 'include' })).json()).tenant;
          const entropy = input.startsWith('agak1_') ? decodeCompact(input) : await decodeWords(input);
          const priv = derivePriv(entropy, tenant);
          const reg = await keyCeremony('softkey', priv, { kind: 'softkey', label: 'imported key' }, 'register');
          if (reg.ok) { setPasted(''); setNotice('Account claimed.'); await checkSession(); return; }
          if (reg.data.error && String(reg.data.error).includes('already registered')) {
            const login = await keyCeremony('softkey', priv, {}, 'login');
            if (login.ok) { setPasted(''); await checkSession(); return; }
            setError(login.data.error || 'Sign-in failed'); return;
          }
          setError(reg.data.error || 'Could not claim account');
        } catch (e) { setError(String(e)); }
      };

      const silentLogin = async () => {
        setError('');
        const pair = await idbGet('device');
        if (!pair) { setHasDeviceKey(false); return; }
        const r = await keyCeremony('devicekey', pair, {}, 'login');
        if (r.ok) await checkSession();
        else setError(r.data.error || 'Silent sign-in failed — the device key may have been removed.');
      };

      const addDeviceKey = async () => {
        setError('');
        const r = await enableDeviceKey();
        if (r.ok) { setHasDeviceKey(true); setNotice('Silent sign-in enabled on this device.'); }
        else setError(r.data.error || 'Could not enable silent sign-in');
      };

      if (loading) return h('p', null, 'Loading...');

      if (view === 'savekey' && newKey) return h('div', { class: 'card' },
        h('h2', null, user ? 'Your recovery key' : 'Your account key'),
        h('p', null, 'Save this now — it is the only way back into the account. It will not be shown again.'),
        h('p', { style: 'font-family: monospace; background: #f4f4f5; padding: 0.5rem; border-radius: 0.25rem; word-break: break-all;' }, newKey.compact),
        h('p', { style: 'font-size: 0.8rem; color: #52525b;' }, 'Or as words: ', h('em', null, newKey.words)),
        h('button', { onClick: () => navigator.clipboard.writeText(newKey.compact) }, 'Copy key'),
        h('p', { style: 'margin-top: 1rem; font-size: 0.875rem;' }, 'Paste it back to confirm you saved it:'),
        h('input', {
          value: newKey.confirm, style: 'width: 100%; padding: 0.5rem; font-family: monospace; margin-bottom: 0.5rem;',
          onInput: (e) => setNewKey({ ...newKey, confirm: e.target.value }),
        }),
        h('button', { onClick: confirmSaved, style: 'background: #18181b; color: white; border: none;' }, 'I saved it'),
        error && h('p', { style: 'color: #ef4444; font-size: 0.875rem; margin-top: 0.5rem;' }, error),
      );

      if (user) return h('div', { class: 'card' },
        h('div', { class: 'user-info' },
          h('p', null, 'Signed in as ', h('strong', null, user.user_id || user.id),
            user.amr ? h('span', { style: 'color: #86efac; font-size: 0.8rem;' }, ' (' + user.amr + ')') : null),
        ),
        notice && h('p', { style: 'color: #16a34a; font-size: 0.875rem; margin-top: 0.5rem;' }, notice),
        h('div', { style: 'display: flex; flex-direction: column; gap: 0.5rem; margin-top: 1rem;' },
          !hasDeviceKey && h('button', { onClick: addDeviceKey }, 'Enable silent sign-in on this device'),
          h('button', { onClick: createAccountKey }, 'Create a recovery key'),
          h('button', { onClick: logout }, 'Sign Out'),
        ),
        error && h('p', { style: 'color: #ef4444; font-size: 0.875rem; margin-top: 0.5rem;' }, error),
      );

      if (view === 'keypanel') return h('div', { class: 'card' },
        h('h2', null, 'Account key'),
        h('p', null, 'No passkey needed — a generated key you keep in your password manager or on paper.'),
        h('div', { style: 'display: flex; flex-direction: column; gap: 0.75rem;' },
          h('button', { onClick: createAccountKey, style: 'background: #18181b; color: white; border: none;' }, 'Create a new account key'),
          h('p', { style: 'text-align: center; color: #a1a1aa; font-size: 0.875rem; margin: 0;' }, 'or bring your own recovery phrase / key'),
          h('input', {
            placeholder: 'agak1_… or your 12 words', value: pasted,
            style: 'width: 100%; padding: 0.5rem; font-family: monospace;',
            onInput: (e) => setPasted(e.target.value),
          }),
          h('button', { onClick: claimWithPhrase }, 'Claim or recover account'),
          h('p', { style: 'font-size: 0.75rem; color: #a1a1aa; margin: 0;' }, 'Creates the account if it is new on this site, or signs you in if it already exists. Works with any standard 12-word phrase.'),
          h('button', { onClick: () => { setView('welcome'); setError(''); }, style: 'border: none; color: #71717a; background: none;' }, 'Back'),
        ),
        error && h('p', { style: 'color: #ef4444; font-size: 0.875rem; margin-top: 0.5rem;' }, error),
      );

      return h('div', null,
        h('h1', { style: 'font-size: 1.75rem; font-weight: 700; margin-bottom: 0.5rem;' }, 'Welcome'),
        h('p', null, 'Sign in or create an account with a passkey.'),
        h('div', { style: 'display: flex; flex-direction: column; gap: 1rem;' },
          hasDeviceKey && h('button', { onClick: silentLogin, style: 'background: #16a34a; color: white; border: none;' }, 'Sign in (this device)'),
          h('button', { onClick: () => register(), style: 'background: #18181b; color: white; border: none;' }, 'Create Account'),
          h('p', { style: 'text-align: center; color: #a1a1aa; font-size: 0.875rem; margin: 0;' }, 'or'),
          h('button', { onClick: login }, 'Login'),
          h('button', { onClick: () => { setView('keypanel'); setError(''); }, style: 'border: none; color: #71717a; background: none; font-size: 0.875rem;' }, 'No passkey? Use an account key'),
        ),
        error && h('p', { style: 'color: #ef4444; font-size: 0.875rem; margin-top: 0.5rem;' }, error),
      );
    }

    render(h(App), document.getElementById('auth-root'));
  </script>
</body>
</html>`);
});

/**
 * Resolve the requester's user id for the tenant of the current request
 * (session cookie or Bearer). Used by the sandbox management endpoints; the
 * dash calls them on its own auth endpoint, so the tenant is e.g.
 * authgravity.org and the user is a dash account.
 */
async function resolveRequestUser(c: any): Promise<string | null> {
    const sessionId = getSessionId(c);
    if (!sessionId) return null;
    const tenantInfo = resolveTenant(new URL(c.req.url));
    const session = await resolveSession(c.env.KV, tenantInfo.tenant, sessionId);
    return session?.userId ?? null;
}

// Mint an instant, zero-DNS sandbox auth endpoint. Unauthenticated so a coding
// agent / CLI can call it directly; with a valid session the sandbox is owned
// by that user (listed in the dashboard, exempt from the anonymous sweep). The
// wildcard route makes the returned host live immediately; the isolated user
// pool is created lazily on first register.
app.post('/sandbox', async (c) => {
    // Light per-IP rate limit to bound abuse of the public mint endpoint.
    // Key on a hash of the IP so no raw IP is ever written to KV (privacy rule:
    // use the public IP in the moment, never store it).
    const ip = c.req.header('CF-Connecting-IP') || 'unknown';
    const rlKey = `sandbox_rl:${await sha256Hex(ip)}`;
    const count = parseInt((await c.env.KV.get(rlKey)) || '0', 10);
    if (count >= 30) {
        return c.json({ error: 'Rate limit exceeded, try again later' }, 429);
    }
    await c.env.KV.put(rlKey, String(count + 1), { expirationTtl: 3600 });

    const id = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
    const url = new URL(c.req.url);
    const isDev =
        url.hostname === 'localhost' ||
        url.hostname === '127.0.0.1' ||
        url.hostname.endsWith('.localhost');

    // Single custom-domain host (auto-certified, no ACM/wildcard); the sandbox
    // id lives in the path: https://sandbox.authgravity.org/<id>
    const sandboxHost = isDev
        ? `sandbox.localhost${url.port ? ':' + url.port : ''}`
        : 'sandbox.authgravity.org';
    const endpoint = `${url.protocol}//${sandboxHost}/${id}`;
    const tenant = `${isDev ? 'sandbox.localhost' : 'sandbox.authgravity.org'}/${id}`;

    // Record the tenant for TTL cleanup / ownership (best-effort).
    const ownerId = await resolveRequestUser(c);
    try {
        await c.env.DB.prepare('INSERT INTO sandboxes (id, created_at, user_id) VALUES (?, ?, ?)')
            .bind(tenant, Date.now(), ownerId)
            .run();
    } catch {
        // table may not exist yet in older deployments; non-fatal
    }

    // Owned sandboxes get a control-plane ownership tuple so the owner can
    // manage the pool's authz from the dash. Best-effort: the provisioner's
    // cron reconcile self-heals a failed grant.
    if (ownerId) {
        try {
            await c.env.AUTHZ.grantTenantOwners([{ tenant, userId: ownerId }]);
        } catch (e) {
            console.error('authz owner grant failed for sandbox', tenant, e);
        }
    }

    return c.json({ id, endpoint, mode: 'sandbox', owned: !!ownerId });
});

// List the requester's owned sandboxes.
app.get('/sandboxes', async (c) => {
    const userId = await resolveRequestUser(c);
    if (!userId) return c.json({ error: 'Not authenticated' }, 401);

    const { results } = await c.env.DB.prepare(
        'SELECT id, created_at FROM sandboxes WHERE user_id = ? ORDER BY created_at DESC'
    ).bind(userId).all();

    const url = new URL(c.req.url);
    const sandboxes = ((results || []) as Array<{ id: string; created_at: number }>).map((row) => {
        const slash = row.id.indexOf('/');
        const host = row.id.slice(0, slash);
        const sid = row.id.slice(slash + 1);
        const endpoint = host.endsWith('.localhost')
            ? `${url.protocol}//${host}${url.port ? ':' + url.port : ''}/${sid}`
            : `https://${host}/${sid}`;
        return { id: sid, tenant: row.id, endpoint, created_at: row.created_at };
    });

    return c.json({ sandboxes });
});

// Delete an owned sandbox and its isolated user pool (mirrors sweepSandboxes).
app.delete('/sandboxes/:sid', async (c) => {
    const userId = await resolveRequestUser(c);
    if (!userId) return c.json({ error: 'Not authenticated' }, 401);

    const sid = c.req.param('sid');
    if (!/^[a-z0-9]{6,32}$/.test(sid)) {
        return c.json({ error: 'Invalid sandbox id' }, 400);
    }

    const row = await c.env.DB.prepare(
        'SELECT id FROM sandboxes WHERE user_id = ? AND id LIKE ?'
    ).bind(userId, `%/${sid}`).first() as { id: string } | null;
    if (!row) return c.json({ error: 'Sandbox not found' }, 404);

    const tenant = row.id;
    await c.env.DB.prepare('DELETE FROM public_keys WHERE tenant = ?').bind(tenant).run();
    await c.env.DB.prepare('DELETE FROM users WHERE tenant = ?').bind(tenant).run();
    await c.env.DB.prepare('DELETE FROM sandboxes WHERE id = ?').bind(tenant).run();
    try {
        await c.env.AUTHZ.cleanupTenant(tenant);
    } catch (e) {
        console.error('authz cleanup failed for sandbox', tenant, e);
    }

    return c.json({ success: true });
});

// Mount tenant-scoped routes per request
app.all('/*', async (c, next) => {
    const url = new URL(c.req.url);
    const tenantInfo = resolveTenant(url);

    const auth = authRoutes(tenantInfo);
    const session = sessionRoutes(tenantInfo);
    const keys = keyRoutes(tenantInfo);

    // For path-based sandbox tenants, strip the "/<id>" prefix so the existing
    // auth/session routes (mounted at root) match "/v1/register/options" etc.
    let req = c.req.raw;
    if (tenantInfo.sandbox && tenantInfo.sandboxId) {
        const u = new URL(c.req.url);
        u.pathname = u.pathname.slice(tenantInfo.sandboxPrefix!.length) || '/';
        req = new Request(u.toString(), c.req.raw);
    }

    // Sandbox discovery: the id-prefixed host resolves here after stripping.
    // The advertised endpoint keeps the "/<id>" so agents fetch the right host.
    const path = new URL(req.url).pathname;
    if (path === '/.well-known/authgravity') {
        const endpoint =
            tenantInfo.sandbox && tenantInfo.sandboxId
                ? `${url.origin}/${tenantInfo.sandboxId}`
                : url.origin;
        return c.json(wellKnown(endpoint, tenantInfo.tenant), 200, { 'Cache-Control': 'no-cache' });
    }

    // Authz routes are served by the gratos-authz worker (which has no public
    // route of its own). Forward with the resolved tenant + user as trusted
    // headers; inbound X-Gratos-* headers are stripped so they can't be forged.
    if (path === '/authz' || path === '/llms.txt' || path === '/v1/authz' || path.startsWith('/v1/authz/')) {
        const headers = new Headers(req.headers);
        for (const key of [...headers.keys()]) {
            if (key.toLowerCase().startsWith('x-gratos-')) headers.delete(key);
        }
        headers.set('X-Gratos-Tenant', tenantInfo.tenant);
        // Sandbox pools: tell authz whether the pool is owned or anonymous
        // (anonymous pools are open to manage). Set only when the sandboxes
        // row exists — a missing row fails closed to managed mode.
        if (tenantInfo.sandbox) {
            const row = (await c.env.DB.prepare('SELECT user_id FROM sandboxes WHERE id = ?')
                .bind(tenantInfo.tenant)
                .first()) as { user_id: string | null } | null;
            if (row) {
                headers.set('X-Gratos-Sandbox', row.user_id ? 'owned' : 'anonymous');
            }
        }
        const sessionId = getSessionId(c);
        if (sessionId) {
            const session = await resolveSession(c.env.KV, tenantInfo.tenant, sessionId);
            if (session && (await getUser(c.env.DB, tenantInfo.tenant, session.userId))) {
                headers.set('X-Gratos-User', session.userId);
                headers.set('X-Gratos-Amr', session.amr);
            }
        }
        return c.env.AUTHZ.fetch(new Request(req, { headers }));
    }

    // Try auth routes first, then key routes, then session routes
    const authResponse = await auth.fetch(req, c.env);
    if (authResponse.status !== 404) return authResponse;

    const keyResponse = await keys.fetch(req, c.env, c.executionCtx);
    if (keyResponse.status !== 404) return keyResponse;

    const sessionResponse = await session.fetch(req, c.env);
    if (sessionResponse.status !== 404) return sessionResponse;

    return next();
});

export default app;
