// The single per-host agent guide served at `<host>/llms.txt`. One document
// per host covers the whole integration — passkey auth, account keys, session
// validation, and authorization rendered from the host's LIVE schema — with the
// auth endpoint pre-filled to this host. An agent reads exactly one URL.
//
// Three framings share the same body:
//   - 'root'    → authgravity.org: onboarding, sandbox-first, promote-to-domain
//   - 'sandbox' → an ephemeral sandbox reached via `authgravity listen`
//   - 'domain'  → a customer's live domain (endpoint pre-filled, first-party)
//
// Served unauthenticated: the schema is structure (like API docs); the
// relationship data itself stays session-gated.

import type { PermissionExpr, StoredSchema, SubjectTypeRef } from './schema';

export type LlmsKind = 'root' | 'sandbox' | 'domain';

export interface LlmsContext {
    /** Tenant key: `authgravity.org` (root), `myapp.com` (domain), or `<host>/<id>` (sandbox). */
    tenant: string;
    kind: LlmsKind;
    /** Base URL agents call for this host, e.g. `https://authgravity.myapp.com`.
     *  Null for the root doc, whose samples use the `PUBLIC_AUTH_ENDPOINT` placeholder. */
    endpoint: string | null;
    /** Authz write mode for this tenant. */
    mode: 'open-sandbox' | 'managed';
    /** The tenant's live schema, or null if none defined yet. */
    stored: StoredSchema | null;
}

/** Render a permission expression compactly: "viewer | editor | parent->view". */
export function fmtExpr(expr: PermissionExpr): string {
    if ('rel' in expr) return expr.rel;
    if ('arrow' in expr) return `${expr.arrow.via}->${expr.arrow.permission}`;
    if ('union' in expr) return expr.union.map(wrap).join(' | ');
    if ('intersection' in expr) return expr.intersection.map(wrap).join(' & ');
    return `${wrap(expr.exclusion.base)} minus ${wrap(expr.exclusion.subtract)}`;
}

function wrap(expr: PermissionExpr): string {
    const s = fmtExpr(expr);
    return 'rel' in expr || 'arrow' in expr ? s : `(${s})`;
}

function fmtSubjects(subjects: SubjectTypeRef[]): string {
    return subjects.map((s) => (s.relation ? `${s.type}#${s.relation}` : s.type)).join(', ');
}

// ---------------------------------------------------------------------------
// Shared sections (identical prose across every kind — one source of truth)
// ---------------------------------------------------------------------------

const AUTH_CODE = `\`\`\`typescript
// src/lib/auth.ts — identical code in dev and production
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

const ENDPOINT = import.meta.env.PUBLIC_AUTH_ENDPOINT;

async function api(path: string, init: RequestInit = {}) {
  return fetch(ENDPOINT + path, { ...init, credentials: 'include' });
}

export async function register() {
  const opts = await (await api('/v1/register/options')).json(); // PublicKeyCredentialCreationOptionsJSON
  const cred = await startRegistration({ optionsJSON: opts });
  const res = await api('/v1/register/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cred), // bare RegistrationResponseJSON — no wrapper
  });
  return res.json(); // { verified, user: { id }, last_used } — session_id cookie is now set
}

export async function login() {
  const opts = await (await api('/v1/login/options')).json(); // PublicKeyCredentialRequestOptionsJSON
  const cred = await startAuthentication({ optionsJSON: opts });
  const res = await api('/v1/login/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cred), // bare AuthenticationResponseJSON — no wrapper
  });
  return res.json(); // { verified, user: { id }, last_used } — session_id cookie is now set
}

// Which button to mark "Last used": the server sets a JS-readable
// ag_last_used cookie ("login.webauthn", "register.key", ...) on your domain
// after every ceremony. lastUsed() from @authgravity/browser does the same.
export function lastUsed(): { action: 'login' | 'register'; method: 'webauthn' | 'device' | 'key' } | null {
  const m = document.cookie.match(/(?:^|; )ag_last_used=([^;]*)/);
  const [action, method] = m ? decodeURIComponent(m[1]).split('.') : [];
  return action === 'login' || action === 'register' ? ({ action, method } as any) : null;
}

export async function whoami() {
  const res = await api('/v1/whoami');
  return res.ok ? res.json() : null; // { user_id } or null
}

export async function logout() {
  await api('/v1/logout', { method: 'POST' });
}
\`\`\``;

const ADD_PASSKEY_CODE = `\`\`\`typescript
// Add a passkey to the signed-in account (same ceremony as register(), plus a label).
export async function addPasskey(label?: string) {
  const q = label ? '?label=' + encodeURIComponent(label) : '';
  const opts = await (await api('/v1/register/options' + q)).json();
  let cred;
  try {
    cred = await startRegistration({ optionsJSON: opts });
  } catch (e: any) {
    if (e?.name === 'InvalidStateError') throw new Error('This device already has a passkey for this account');
    throw e;
  }
  const res = await api('/v1/register/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cred),
  });
  if (res.status === 409) throw new Error('This device already has a passkey for this account');
  return res.json(); // { verified, user: { id }, credential: { id } }
}
\`\`\``;

function authSection(lines: string[]) {
    lines.push('## Auth (passkeys)');
    lines.push('');
    lines.push(
        'Build the sign-in UI in your app, with `@authgravity/browser` or the raw API below. The UI is two buttons — **"Create Account"** (`register()`) and **"Login"** (`login()`) — in your app\'s own look, with no redirect out of the app. No username field, no email field, no forms. The passkey label defaults to "Me"; if you offer a custom label keep it client-side (`opts.user.name` before `startRegistration`) — it is never sent to the server.'
    );
    lines.push('');
    lines.push(AUTH_CODE);
    lines.push('');
    lines.push('HTTP API (spec-shaped WebAuthn JSON — any conforming client library works; always `credentials: \'include\'`):');
    lines.push('');
    lines.push('- `GET /v1/register/options` → `PublicKeyCredentialCreationOptionsJSON`, unmodified');
    lines.push('- `POST /v1/register/verify` bare `RegistrationResponseJSON` → `{verified, user:{id}, last_used}`; sets `session_id` cookie');
    lines.push('- `GET /v1/login/options` → `PublicKeyCredentialRequestOptionsJSON`, unmodified');
    lines.push('- `POST /v1/login/verify` bare `AuthenticationResponseJSON` → `{verified, user:{id}, last_used}`; sets `session_id` cookie');
    lines.push('- `GET /v1/whoami` → `{user_id}` or 401. Accepts the cookie or `Authorization: Bearer <session_id>`');
    lines.push('- `POST /v1/logout` → destroys the session, clears the cookie');
    lines.push('');
    lines.push('The server keys the pending ceremony by the challenge (inside the signed `clientDataJSON`), so there is no correlation id to carry.');
    lines.push('');
    lines.push('### Multiple passkeys per account');
    lines.push('');
    lines.push(
        'An account holds up to 10 credentials. Run the SAME registration ceremony while signed in and the new passkey is ADDED to the session\'s account instead of creating a new one (`register()` above, with the cookie or Bearer present). The options then carry `excludeCredentials` for the passkeys the account already has, so an authenticator that already holds one refuses with `InvalidStateError` in the browser — never a silent overwrite; if a response for a known credential still reaches the server it answers 409. Any authenticator is accepted (platform passkeys, phones, hardware security keys), so "add a backup passkey" is a one-button feature.'
    );
    lines.push('');
    lines.push('- `GET /v1/register/options?label=<name>` — optional owner label (≤64 chars) for the new passkey; otherwise the list shows the provider name derived from the authenticator AAGUID (iCloud Keychain, Google Password Manager, 1Password, YubiKey, …)');
    lines.push('- `POST /v1/register/verify` → also `credential: {id}` (the row id used by DELETE below); when adding to a signed-in user there is no `last_used` (not a sign-up)');
    lines.push('- `GET /v1/credentials` → `{amr, credentials: [{id, kind: "webauthn"|"devicekey"|"softkey", label, provider, display, backed_up, transports, created_at, last_used_at, current}]}` — `display` is what to show (label, else provider, else "Passkey"); `current` marks the credential that minted this session');
    lines.push('- `DELETE /v1/credentials/:id` → `{deleted: true}`; 409 on the last credential (never orphan an account), 403 when the session is weaker than the target (a session from a recovery key cannot remove a passkey — sign in with a passkey first)');
    lines.push('');
    lines.push(
        'Zero-UI option: send signed-in users to `<endpoint>/account?return_to=<url>` — a hosted page (like `/login`) that lists credentials, adds a passkey with an optional name, removes one, and offers the 12-word recovery key. In your own UI use `listCredentials(endpoint)` / `removeCredential(endpoint, id)` from `@authgravity/browser`, and this for the add button:'
    );
    lines.push('');
    lines.push(ADD_PASSKEY_CODE);
    lines.push('');
    lines.push('**"Last used" hint.** Every successful ceremony also sets a JS-readable, one-year `ag_last_used` cookie on your domain (not httpOnly, unlike `session_id`) whose value is `<action>.<method>`: action `login` | `register` (only a ceremony that CREATED the account counts as `register`; adding a passkey or recovery key to a signed-in user leaves it alone), method `webauthn` | `device` | `key` | `otp` (the session `amr` vocabulary). Read it on page load and put a small "Last used" pill on the matching button — returning users then see it on **Login**, first-time users see nothing. `lastUsed()` in `@authgravity/browser` parses it (falls back to `localStorage`, which the SDK fills from the `last_used` verify field when the cookie cannot reach your origin, e.g. a sandbox used without `authgravity listen`; the proxy mirrors the cookie onto localhost). Logout keeps the cookie on purpose. It carries no identity — no user id, no credential id.');
    lines.push('');
}

function accountKeysSection(lines: string[]) {
    lines.push('## Account keys (no-passkey fallback + recovery)');
    lines.push('');
    lines.push(
        'For users without passkey support — and as the recovery path for everyone — a client-generated 128-bit secret rendered as `agak1_…` (base32 + checksum) or 12 BIP39 words, from which the client derives a P-256 key pair per tenant. The server stores only the public key, exactly like a passkey. Daily logins should use a silent **device key** (non-extractable WebCrypto key in IndexedDB, registered as an extra credential) so the account key is only typed at setup and recovery.'
    );
    lines.push('');
    lines.push('Endpoints (mirror the WebAuthn pair; same session semantics):');
    lines.push('');
    lines.push('- `GET /v1/key/register/options` / `GET /v1/key/login/options` → `{challenge, context, tenant}` (single-use, 5 min)');
    lines.push('- `POST /v1/key/register/verify` `{challenge, public_key, signature, kind: "softkey"|"devicekey", label?}` → `{verified, user:{id}, credential_id, last_used?}`; with a session the credential is ADDED to that user (then no `last_used`)');
    lines.push('- `POST /v1/key/login/verify` `{challenge, public_key, signature}` → `{verified, user:{id}, last_used}`');
    lines.push('- `GET /v1/credentials`, `DELETE /v1/credentials/:id` — list/remove every kind (see "Multiple passkeys per account" above for the shape and guards)');
    lines.push('- `GET /v1/key/wordlist.json` — BIP39 English wordlist');
    lines.push('');
    lines.push(
        `Derivation: \`priv = (HKDF-SHA256(entropy, salt=utf8(tenant), info="authgravity/softkey/v1", 40 bytes) mod (n-1)) + 1\` on P-256; \`public_key\` = base64url 65-byte uncompressed point; \`signature\` = base64url 64-byte r||s of ECDSA-SHA256 over utf8 \`\${context}\\n\${challenge}\\n\${tenant}\`. The \`@authgravity/browser\` SDK implements all of this (\`mintKey\`/\`decodeKey\`/\`registerAccountKey\`/\`loginWithAccountKey\`/\`enableDeviceKey\`); the full spec + conformance vectors are at https://authgravity.org/llms.txt.`
    );
    lines.push('');
    lines.push('Sessions carry `amr` (`webauthn` | `device` | `key` | `otp`, strongest first) in `/v1/whoami` and authz responses, so apps can require passkey-strength sessions for sensitive actions. Adding a credential while signed in never raises the session: an `otp` session that enrolls a device key stays `otp` until the next sign-in.');
    lines.push('');
}

const CODE_LOGIN_CODE = `\`\`\`typescript
// Browser — your "sign in with a phone call" screen.
import { startCodeLogin, verifyCode, enableDeviceKey } from '@authgravity/browser';

const ticket = await startCodeLogin(ENDPOINT);          // verifier stays in this tab
await fetch('/api/send-code', { method: 'POST', body: JSON.stringify({ ticket, phone }) });
// …person types the code they heard…
const r = await verifyCode(ENDPOINT, typed);            // session_id cookie, amr "otp"
if (r.verified) await enableDeviceKey(ENDPOINT);        // this computer signs in silently from now on

// Backend — /api/send-code (service token stays server-side).
import { authgravity } from '@authgravity/server';
const ag = authgravity({ endpoint: ENDPOINT, serviceToken: process.env.AUTHGRAVITY_SERVICE_TOKEN });
const userId = await db.userIdForPhone(phone);          // YOUR mapping; AuthGravity never sees the phone
if (userId) {
  const { code } = await ag.mintCode({ ticket, userId });
  await placeVoiceCall(phone, code);                    // or email, or anything
}
return ok();                                            // same response whether or not the number is known
\`\`\``;

function codeLoginSection(lines: string[]) {
    lines.push('## Sign in with a code (app-delivered, for people without passkeys)');
    lines.push('');
    lines.push(
        'For people who cannot use a passkey — no phone, no platform authenticator, not comfortable with one — your app delivers a 6-digit code over a channel it already owns (a voice call to a landline, an email) and the person types it once per computer. Your backend owns the phone/email and its mapping to an AuthGravity user id; AuthGravity only provisions users and mints/verifies codes. **Accounts are provisioned, not self-served**: codes are minted only for users your backend created, so a stranger cannot trigger calls to arbitrary numbers through AuthGravity.'
    );
    lines.push('');
    lines.push(CODE_LOGIN_CODE);
    lines.push('');
    lines.push('- `POST /v1/users` (service token) → `{user_id}` — a user with no credentials yet; store the id against their phone/email');
    lines.push('- `POST /v1/code/start` (browser) → `{ticket, verifier, expires_at}` — send only `ticket` to your backend');
    lines.push('- `POST /v1/code/mint` `{ticket, user_id}` (service token) → `{code, expires_at}` — 6 digits, valid 10 minutes; calling again is a resend (new code, max 3 per ticket; 5 codes per user per hour)');
    lines.push('- `POST /v1/code/verify` `{ticket, verifier, code}` (browser) → `{verified, user:{id}, last_used: "login.otp"}`; sets `session_id` with `amr: "otp"`. 5 wrong codes burn the ticket');
    lines.push('');
    lines.push(
        'Service tokens (`agk_…`) are minted by the tenant owner in the dashboard; any of the tenant\'s tokens may provision users and mint codes. Anonymous sandboxes need no token (open pools). The code is bound to the browser that started the ticket (its `verifier`), so a code overheard or left on voicemail is useless elsewhere.'
    );
    lines.push('');
    lines.push(
        '**This is not phishing-resistant** (NIST SP 800-63B out-of-band): a scammer who starts a sign-in with the person\'s number and then asks them to read the code aloud gets in. So: (1) say it in the message — "Never share this code. We will never call and ask for it."; (2) never leave a code on voicemail (use answering-machine detection); (3) tell a family member or the account holder whenever a code is issued; (4) rate-limit your own send-code endpoint and answer identically for unknown numbers; (5) right after a code sign-in, `enableDeviceKey()` so later sign-ins are silent and codes stay rare; (6) gate sensitive actions with `min_amr` — an `otp` session is the weakest.'
    );
    lines.push('');
}

function sessionValidationSection(lines: string[]) {
    lines.push('## Server-side session validation');
    lines.push('');
    lines.push('Forward the incoming cookie header to `/v1/whoami` from any backend (Astro, Express, Hono, …):');
    lines.push('');
    lines.push('```typescript');
    lines.push('const cookie = request.headers.get("cookie");');
    lines.push('const res = await fetch(ENDPOINT + "/v1/whoami", { headers: cookie ? { cookie } : {} });');
    lines.push('if (!res.ok) return redirectToLogin();');
    lines.push('const { user_id } = await res.json();');
    lines.push('```');
    lines.push('');
}

function personServerSection(lines: string[], ctx: LlmsContext, endpoint: string) {
    lines.push('## Person Server (AAuth)');
    lines.push('');
    lines.push(
        'This host is also an **AAuth Person Server** (draft-hardt-oauth-aauth-protocol, aauth.dev): it represents each user to AI agents. An agent with its own cryptographic identity asks this host for authorization; the person approves once (passkey session), and the server issues a short-lived signed `aa-auth+jwt` the agent presents to third-party resources. The person picks their PS — this one comes free with every AuthGravity pool.'
    );
    lines.push('');
    if (ctx.kind === 'root') {
        lines.push(
            '**Instant PS for agent development:** mint a sandbox (`POST /sandbox` on the product endpoint, or `npx @authgravity/cli listen`) and your agent has a live, public https Person Server at `https://sandbox.authgravity.org/<id>` — no domain, no DNS, ready for real cross-server interop.'
        );
        lines.push('');
    }
    if (ctx.kind === 'sandbox') {
        lines.push(
            `**This sandbox is a live, public Person Server.** Point your agent tooling (e.g. \`@aauth/bootstrap\`, \`@aauth/fetch\`) at \`ps=${endpoint}\` and it can obtain real auth tokens from real resources — the fastest way to develop against AAuth.`
        );
        lines.push('');
    }
    lines.push(`Discovery: \`GET ${endpoint}/.well-known/aauth-person.json\` → issuer, endpoints, JWKS. All signing is Ed25519.`);
    lines.push('');
    lines.push('### Agent flow (token)');
    lines.push('');
    lines.push(
        '1. Agent POSTs `{resource_token, justification?}` to `/v1/aauth/token`, RFC 9421-signed (`Signature-Input`/`Signature` + agent token in `Signature-Key: sig=jwt;jwt="…"`; covered components `"@method" "@authority" "@path" "signature-key"`, plus `"authorization"`/`"aauth-mission"` whenever those headers are sent).'
    );
    lines.push(
        '2. First time: `202 Accepted` with `Location: /v1/aauth/pending/<id>` and `AAuth-Requirement: requirement=interaction; url="' +
            endpoint +
            '/consent"; code="XXXXXXXX"`. Show the person the consent URL + code — **delivering that link is always the proposing agent\'s job**; this server never notifies anyone.'
    );
    lines.push('3. The person opens `/consent?code=…`, signs in with their passkey, reviews, approves (optionally "remember").');
    lines.push('4. Agent polls the pending URL → `200 {auth_token, expires_in}`. Remembered approvals skip straight to `200` next time.');
    lines.push('');
    lines.push('Auth tokens: `aa-auth+jwt`, Ed25519, ≤ 600s, `cnf`-bound to the agent key, verifiable against this host\'s JWKS. Identity is a per-pool UUID `sub` — never email, never PII.');
    lines.push('');
    lines.push('### Missions, budgets, governance');
    lines.push('');
    lines.push(
        'For multi-step or spending work an agent proposes a **mission** at `/v1/aauth/mission`: `{mission: {description, approved_tools?, resources?, budgets?, approver?, expires_in?}}`. Proposals wait for consent up to 7 days (configurable ≤ 30) — approval is asynchronous and may come from a **different person than the proposer** (set `approver` to the intended user\'s UUID to bind it; without it, holding the code IS the capability — treat the code as a secret).'
    );
    lines.push('');
    lines.push(
        '`budgets` entries (AAuth-Budget extension) carry `{resource, amount, currency, models?}` where `resource` is the resource token\'s `iss`. At consent the person may only **narrow**: lower an amount, restrict models, or drop an entry — never add or increase. The approved blob is hash-committed (`s256`); tokens minted under a budgeted mission carry the granted entry verbatim in a `budget` claim and **no identity at all** (no `sub`).'
    );
    lines.push('');
    lines.push(
        '**A budget is a cap + proof of consent, not payment.** Providers gate spend on a funded claim: the token response passes `funded`/`funding_url` through verbatim; until someone claims the mission at `funding_url`, inference returns `402 mission_unfunded`. Relaying that link to a payer is also the agent\'s job.'
    );
    lines.push('');
    lines.push('Governance endpoints (all agent-signed, mission-bound): `POST /v1/aauth/permission` (`{action, mission, …}` → `{permission: "granted"|"denied"}`, auto-granted when the action is in `approved_tools`), `POST /v1/aauth/audit` (fire-and-forget action log → 201), `POST /v1/aauth/interaction` (`{type: "question"|"completion", …}` — questions reach the person; accepted completions close the mission). `GET /v1/aauth/mission/<s256>` returns the approved blob + lifecycle status; spend state lives at the resource\'s own `budget_endpoint`.');
    lines.push('');
    lines.push(
        'Lifecycle errors are distinct so a harness learns promptly: `mission_revoked` | `mission_completed` | `mission_expired`. People manage everything themselves on this host: `GET/DELETE /v1/aauth/grants[/:id]`, `GET /v1/aauth/missions`, `POST /v1/aauth/missions/:id/revoke` (kill-switch).'
    );
    lines.push('');
}

function databaseSection(lines: string[]) {
    lines.push('## Your database');
    lines.push('');
    lines.push('AuthGravity gives you a stable UUID and stores nothing else. Key your users table by it, create rows on first sight, collect email/name later (e.g. at checkout):');
    lines.push('');
    lines.push('```sql');
    lines.push('CREATE TABLE users (');
    lines.push('  id TEXT PRIMARY KEY,   -- the AuthGravity UUID');
    lines.push('  email TEXT, name TEXT, -- collected later, nullable');
    lines.push('  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP');
    lines.push(');');
    lines.push('```');
    lines.push('');
}

// ---------------------------------------------------------------------------
// Authorization section — rendered from the host's LIVE schema
// ---------------------------------------------------------------------------

function authzOverviewSection(lines: string[]) {
    lines.push('## Authorization (relationship-based access control)');
    lines.push('');
    lines.push(
        'Optional Zanzibar/SpiceDB-style permissions for your app\'s resources, served on the same host and session as auth. Subjects are the AuthGravity user UUIDs from `/v1/whoami`. Each host renders its OWN live schema and API in its `<endpoint>/llms.txt` — read that host\'s file for the real object types. The shape:'
    );
    lines.push('');
    lines.push('- Define object types with relations + computed permissions: `PUT /v1/authz/schema`.');
    lines.push('- Write relationship tuples keyed by user UUIDs: `POST /v1/authz/relationships` `{updates:[{op,object,relation,subject}]}`.');
    lines.push('- Check on every gated action: `POST /v1/authz/check` `{object, permission}` — omit the subject to use the session user; returns `{allowed, user_id}`. Batch with `{items:[…]}`.');
    lines.push('- Open sandboxes: any authenticated user may edit the schema and write. Domains: owner-managed — the schema is set in the dashboard and the app backend writes with a service token (`Authorization: Bearer agk_…`).');
    lines.push('- Do not cache allow/deny across requests; a console lives at `<endpoint>/authz`.');
    lines.push('');
}

// The exact JSON accepted by PUT /v1/authz/schema, mirroring validateSchema
// (schema.ts). Keep the two in lockstep: this is what agents author from.
function schemaFormatSection(lines: string[]) {
    lines.push('### Schema document format');
    lines.push('');
    lines.push(
        'The schema is a single JSON object — the whole `PUT /v1/authz/schema` body. Invalid documents return 400 with per-field `details`. Example with every construct:'
    );
    lines.push('');
    // Hand-formatted for compactness (tests parse + validate this block).
    lines.push('```json');
    lines.push(`{ "definitions": {
  "group": {
    "relations": { "member": { "subjects": [{ "type": "user" }] } }
  },
  "folder": {
    "relations": {
      "owner":  { "subjects": [{ "type": "user" }] },
      "viewer": { "subjects": [{ "type": "user" }, { "type": "group", "relation": "member" }] }
    },
    "permissions": {
      "view": { "union": [{ "rel": "owner" }, { "rel": "viewer" }] }
    }
  },
  "document": {
    "relations": {
      "parent": { "subjects": [{ "type": "folder" }] },
      "editor": { "subjects": [{ "type": "user" }] },
      "banned": { "subjects": [{ "type": "user" }] }
    },
    "permissions": {
      "edit": { "rel": "editor" },
      "view": { "exclusion": {
        "base": { "union": [{ "rel": "edit" }, { "arrow": { "via": "parent", "permission": "view" } }] },
        "subtract": { "rel": "banned" }
      } }
    }
  }
} }`);
    lines.push('```');
    lines.push('');
    lines.push(
        '- Top level has exactly one key, `definitions`: a map of object type → `{relations?, permissions?}`. The `user` type is built in — never define it. Type names starting with `gratos_` are reserved.'
    );
    lines.push(
        '- **Relations** are the facts you write as tuples. Each is `{"subjects": [...]}` (non-empty). A subject type ref is `{"type": "user"}` (direct) or `{"type": "group", "relation": "member"}` (a subject set: everyone who is a `member` of that group, transitively). Subject types must be `user` or a type defined in this document; subject-set refs may name relations only, not permissions.'
    );
    lines.push('- **Permissions** are computed at check time. An expression object has exactly ONE of:');
    lines.push('  - `{"rel": "<name>"}` — another relation or permission on the same type');
    lines.push(
        '  - `{"arrow": {"via": "<relation>", "permission": "<name>"}}` — follow `via` tuples to the referenced object(s) and check `<name>` (relation or permission) there, e.g. `parent->view`. The `via` relation must have direct-only subjects (no subject sets).'
    );
    lines.push('  - `{"union": [expr, ...]}` or `{"intersection": [expr, ...]}` — non-empty arrays');
    lines.push('  - `{"exclusion": {"base": expr, "subtract": expr}}` — base minus subtract (deny list)');
    lines.push(
        '- Names (types, relations, permissions) match `^[a-z][a-z0-9_]{0,63}$`. Relations and permissions on a type share one namespace, and permission-to-permission reference cycles within a type are rejected.'
    );
    lines.push(
        '- Limits: ≤100 type definitions, ≤100 relations+permissions per type, ≤50 nodes per permission expression, ≤64 KB document. Each save bumps the schema `version` (echoed as `X-Schema-Version` on checks).'
    );
    lines.push('');
}

function authzSection(lines: string[], ctx: LlmsContext) {
    const defs = ctx.stored?.doc.definitions ?? {};
    const typeNames = Object.keys(defs);

    let exampleObject = 'document:readme';
    let examplePermission = 'view';
    let exampleRelation = 'viewer';
    for (const [typeName, def] of Object.entries(defs)) {
        const perms = Object.keys(def.permissions ?? {});
        const rels = Object.keys(def.relations ?? {});
        if (perms.length && rels.length) {
            exampleObject = `${typeName}:example-id`;
            examplePermission = perms[0];
            exampleRelation = rels[0];
            break;
        }
    }

    lines.push('## Authorization (relationship-based access control)');
    lines.push('');
    lines.push(
        'Optional Zanzibar/SpiceDB-style permissions for your app\'s resources, served on this same host with the same session. Subjects are the AuthGravity user UUIDs from `/v1/whoami`. You define object types with relations and computed permissions, write relationship tuples, and ask `check(object, permission, subject)`.'
    );
    lines.push('');

    lines.push('### The schema (live on this host)');
    lines.push('');
    if (!ctx.stored || typeNames.length === 0) {
        lines.push(
            'No schema is defined yet. ' +
                (ctx.mode === 'open-sandbox'
                    ? 'This is an open sandbox: define one with `PUT /v1/authz/schema` (any authenticated user) using the document format below.'
                    : "The tenant owner defines it from the AuthGravity dashboard's Authorization panel (the document format below is what gets stored).")
        );
        lines.push('');
    } else {
        lines.push(
            `Schema version ${ctx.stored.version}. Objects are written \`type:id\`; subjects are \`user:<uuid>\` or subject sets like \`group:eng#member\`.`
        );
        lines.push('');
        for (const [typeName, def] of Object.entries(defs)) {
            lines.push(`#### ${typeName}`);
            const rels = Object.entries(def.relations ?? {});
            if (rels.length) {
                lines.push('Relations (facts you write as tuples):');
                for (const [name, rel] of rels) {
                    lines.push(`- \`${typeName}:<id>#${name}\` — allowed subjects: ${fmtSubjects(rel.subjects)}`);
                }
            }
            const perms = Object.entries(def.permissions ?? {});
            if (perms.length) {
                lines.push('Permissions (questions you check):');
                for (const [name, expr] of perms) {
                    lines.push(`- \`${name}\` = ${fmtExpr(expr)}`);
                }
            }
            lines.push('');
        }
    }

    schemaFormatSection(lines);

    lines.push('### Checking permissions');
    lines.push('');
    lines.push('Gate every protected route/action with a `check`. With a session, omit the subject (or pass `"self"`) — one round trip authenticates and authorizes and returns the user id:');
    lines.push('');
    lines.push('```');
    lines.push('curl -X POST <this host>/v1/authz/check \\');
    lines.push("  -H \"Authorization: Bearer $SESSION_ID\" -H 'Content-Type: application/json' \\");
    lines.push(`  -d '{ "object": "${exampleObject}", "permission": "${examplePermission}" }'`);
    lines.push('# -> { "allowed": true | false, "user_id": "<the session user\'s uuid>" }');
    lines.push('```');
    lines.push('');
    lines.push('Batch (list pages): `{"items": [{"object": "...", "permission": "..."}, ...]}` (max 50) → `{"results": [...], "user_id": "..."}`, order preserved. Do not cache allow/deny across requests — per-request checks are what make revocation instant.');
    lines.push('');
    lines.push('Require step-up strength for sensitive actions with `min_amr` (`webauthn` | `device` | `key` | `otp`), top-level or per item: `{"object": "...", "permission": "...", "min_amr": "webauthn"}`. A session weaker than required returns `{"allowed": false, "reason": "insufficient_amr"}` (so you can prompt re-auth rather than treat it as a plain deny). `min_amr` is session-only — a service-token check that sends it gets 400. Every check response also carries an `X-Schema-Version` header.');
    lines.push('');
    lines.push('Other endpoints: `GET /v1/authz/status`, `GET /v1/authz/schema`, `GET /v1/authz/relationships?object_type=…`, `POST /v1/authz/relationships` `{updates:[{op:"touch"|"create"|"delete",object,relation,subject}]}` (max 100, atomic).');
    lines.push('');

    lines.push('### Who can write');
    lines.push('');
    if (ctx.mode === 'open-sandbox') {
        lines.push(
            'This is an anonymous sandbox: any authenticated user of this pool may edit the schema and write relationships. Perfect for development — write tuples directly from your app while you build.'
        );
    } else {
        lines.push(
            'This tenant is owner-managed. The schema is administered by the tenant owner (AuthGravity dashboard). Relationship writes come from your **app backend** using a **service token** — minted by the owner in the dashboard\'s Authorization panel, kept as a server secret (e.g. `AUTHZ_SERVICE_TOKEN`), and sent as `Authorization: Bearer agk_...` to `POST /v1/authz/relationships`. End-user sessions can check and read, but their writes get 403.'
        );
        lines.push('');
        lines.push('```');
        lines.push('curl -X POST <this host>/v1/authz/relationships \\');
        lines.push("  -H \"Authorization: Bearer $AUTHZ_SERVICE_TOKEN\" -H 'Content-Type: application/json' \\");
        lines.push(`  -d '{ "updates": [{ "op": "touch", "object": "${exampleObject}", "relation": "${exampleRelation}", "subject": "user:<uuid>" }] }'`);
        lines.push('```');
    }
    lines.push('');
    lines.push('A console for this tenant lives at `/authz` on this host. Object ids are your own identifiers (`[a-zA-Z0-9_@./=+-]`, no `:` or `#`).');
    lines.push('');

    if (ctx.stored && typeNames.length > 0) {
        lines.push('### Schema JSON (current)');
        lines.push('');
        lines.push('```json');
        lines.push(JSON.stringify(ctx.stored.doc, null, 2));
        lines.push('```');
        lines.push('');
    }
}

// ---------------------------------------------------------------------------
// Intro / framing per kind
// ---------------------------------------------------------------------------

function introSection(lines: string[], ctx: LlmsContext) {
    if (ctx.kind === 'root') {
        lines.push('# AuthGravity');
        lines.push('');
        lines.push(
            '> Hosted passkey (WebAuthn) authentication + relationship-based authorization. Zero-knowledge: the server stores only public keys and a UUID per user — no passwords, no usernames, no email. Your app owns all profile data.'
        );
        lines.push('');
        lines.push('## Start in 60 seconds (local dev — no domain, no DNS)');
        lines.push('');
        lines.push('1. Run the local auth proxy next to your dev server and leave it running:');
        lines.push('');
        lines.push('```');
        lines.push('npx @authgravity/cli listen');
        lines.push('# ✔ Minted sandbox <id>');
        lines.push('# ▶ Listening on http://localhost:8787');
        lines.push('```');
        lines.push('');
        lines.push('2. Point your app at it: `PUBLIC_AUTH_ENDPOINT=http://localhost:8787`');
        lines.push('');
        lines.push(
            'The CLI mints an ephemeral, isolated sandbox (rpID=localhost) and converts its session into a first-party httpOnly `session_id` cookie on localhost — so the exact same auth code runs in dev and production. Sandbox passkeys are throwaway; promote to a real domain for production (see the end of this file).'
        );
        lines.push('');
        lines.push(
            '**Every host publishes its own `<endpoint>/llms.txt`** with its live authz schema and pre-filled endpoint. When integrating a specific app, read *that* host\'s file — it is the single source for that integration.'
        );
        lines.push('');
        return;
    }

    if (ctx.kind === 'sandbox') {
        lines.push('# AuthGravity — sandbox');
        lines.push('');
        lines.push(
            `> Ephemeral passkey auth + authz sandbox served at \`${ctx.endpoint}\`. Zero-knowledge: only public keys and a per-user UUID are stored. Throwaway pool for development.`
        );
        lines.push('');
        lines.push('This host is a sandbox. Reach it through the local proxy so your app uses production-identical cookie auth:');
        lines.push('');
        lines.push('```');
        lines.push('npx @authgravity/cli listen');
        lines.push('# ▶ Listening on http://localhost:8787');
        lines.push('```');
        lines.push('');
        lines.push('Set `PUBLIC_AUTH_ENDPOINT=http://localhost:8787`. Promote to your own domain for production — passkeys are rpID-bound, so users re-register on the real domain.');
        lines.push('');
        return;
    }

    // domain
    lines.push(`# AuthGravity — ${ctx.tenant}`);
    lines.push('');
    lines.push(
        `> Passkey auth + authz for **${ctx.tenant}**, served on this host. Zero-knowledge: the server stores only public keys and a UUID per user — no passwords, no usernames, no email. This tenant is an isolated user pool.`
    );
    lines.push('');
    lines.push(`This file is the single integration guide for this host. Your auth endpoint is \`${ctx.endpoint}\`:`);
    lines.push('');
    lines.push(`\`\`\``);
    lines.push(`PUBLIC_AUTH_ENDPOINT=${ctx.endpoint}`);
    lines.push(`\`\`\``);
    lines.push('');
    lines.push('The app and this endpoint share a registrable domain, so the `session_id` cookie is first-party — no proxy, no code changes from dev.');
    lines.push('');
}

function productionSection(lines: string[]) {
    lines.push('## Go to production (your own domain)');
    lines.push('');
    lines.push('```');
    lines.push('# 1. Create a claim (no auth needed):');
    lines.push("curl -X POST https://provision.api.authgravity.org/claims \\");
    lines.push("  -H 'Content-Type: application/json' -d '{\"domain\":\"myapp.com\"}'");
    lines.push('# → { "id":"<claimId>", "cname_name":"authgravity", "cname_target":"cname.authgravity.net" }');
    lines.push('');
    lines.push('# 2. Open in a browser for the human (passkey sign-in + DNS via Domain Connect or CNAME):');
    lines.push('#    https://authgravity.org/signup?claim_id=<claimId>');
    lines.push('');
    lines.push('# 3. Poll until claimed:');
    lines.push('curl https://provision.api.authgravity.org/claims/<claimId>   # → "status":"claimed"');
    lines.push('```');
    lines.push('');
    lines.push('Then set `PUBLIC_AUTH_ENDPOINT=https://authgravity.myapp.com` and deploy under `myapp.com`. Read `https://authgravity.myapp.com/llms.txt` for that host\'s live guide.');
    lines.push('');
}

function notesSection(lines: string[]) {
    lines.push('## Notes');
    lines.push('');
    lines.push('- rpID = your registrable domain; passkeys work across all its subdomains.');
    lines.push('- Each domain is an isolated user pool. Only public key material is stored server-side; never private keys, never PII.');
    lines.push('- Discovery: `GET <host>/.well-known/authgravity` returns this host\'s endpoint + `llms.txt` URL as JSON.');
    lines.push('- Auth on this host is provided by AuthGravity (https://authgravity.org); a small credit near your sign-in UI is appreciated, never required.');
    lines.push('- Powered by the open source Gratos project (AGPLv3): https://github.com/polvi/gratos');
    lines.push('');
}

/**
 * Build the single per-host agent guide. Auth + account keys + validation are
 * shared prose; the authorization section is rendered from the live schema; the
 * intro/production framing varies by kind.
 */
export function buildLlmsTxt(ctx: LlmsContext): string {
    const lines: string[] = [];
    const endpoint = ctx.endpoint ?? 'https://authgravity.<yourdomain>';

    introSection(lines, ctx);
    authSection(lines);
    accountKeysSection(lines);
    codeLoginSection(lines);
    sessionValidationSection(lines);
    if (ctx.kind === 'root') authzOverviewSection(lines);
    else authzSection(lines, ctx);
    personServerSection(lines, ctx, endpoint);
    databaseSection(lines);
    if (ctx.kind !== 'domain') productionSection(lines);
    notesSection(lines);

    return lines.join('\n');
}
