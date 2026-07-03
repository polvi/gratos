# Gratos

Zero-knowledge, serverless, headless passkey authentication. Gratos stores only public key material: no pas
swords, no usernames on the server. User identity lives in the consuming app; Gratos handles WebAuthn credential storage and session management.

Currently powering authgravity.org

Inspired by [Ory Kratos](https://www.ory.sh/kratos/), built on [WebAuthn](https://webauthn.guide/), hat tip to Let's Encrypt, but not affiliated.

## How It Works

Sign up at [authgravity.org](https://authgravity.org), claim your domain, and add the CNAME record provided. The tenant is auto-derived from the request hostname. Users, credentials, and sessions are all isolated per tenant.

```
authgravity.myapp.com  ──CNAME──►  <token>.cname.authgravity.net
                                    (tenant = authgravity.myapp.com)
```

Every domain gets its own user pool. A user who registers on `authgravity.foo.com` has no relationship to a user on `authgravity.bar.com`.

## Architecture

```
Browser
  ├─ your app (@simplewebauthn/browser or any WebAuthn client)
  │
  └─ authgravity.myapp.com (CNAME → Gratos Worker)
       ├─ Hono server on Cloudflare Workers
       ├─ @simplewebauthn/server
       ├─ D1 (users, credentials — scoped by tenant)
       └─ KV (sessions, challenges)
```

## Auth Flow

Because the auth server lives on your domain (via CNAME), everything is same-origin. No iframes, no popups, no cross-domain redirects. The API speaks pure spec-shaped WebAuthn JSON, so any conforming client library works.

1. User clicks **Register** or **Sign In** in your app
2. Your app fetches standard WebAuthn options from `authgravity.myapp.com/v1/...`
3. Browser prompts for passkey (biometric, security key, etc.)
4. Your app posts the credential response back, as-is — no wrapper, no correlation id
5. Worker verifies the credential, creates a session, sets an `httpOnly` cookie

RP ID is the registrable domain (e.g., `authgravity.myapp.com` → RP ID `myapp.com`), so passkeys work across subdomains.

## Session Model

- First-party `httpOnly`, `secure` cookie on the registrable domain
- Sessions stored in Cloudflare KV with configurable TTL (default 7 days)
- Challenges expire after 5 minutes

## Privacy Model

- The server generates a UUID for each user and **never stores usernames**
- Usernames are only used client-side as the WebAuthn authenticator display name
- The `users` table contains only `id` — no email, no name, no PII
- Credentials table stores the public key, never private key material

## Monorepo Structure

```
packages/
  gratos-multi/     Cloudflare Worker — WebAuthn, sessions, multi-tenant
  gratos-dash/      AuthGravity dashboard and docs site (Astro)
  provisioner/      Domain provisioning service
  cli/              @authgravity/cli — local dev proxy (authgravity listen)
```

## Getting Started

### 1. Claim your domain

Sign up at [authgravity.org](https://authgravity.org) and enter your domain. Add the CNAME record provided:

```
authgravity  CNAME  <token>.cname.authgravity.net
```

The target is a unique per-claim token (e.g., `ab3kx7.cname.authgravity.net`) that proves DNS ownership. AuthGravity polls and activates automatically.

### 2. Wire up auth

```ts
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

const API = 'https://authgravity.myapp.com';

export async function register() {
  const opts = await (await fetch(API + '/v1/register/options', { credentials: 'include' })).json();
  const cred = await startRegistration({ optionsJSON: opts });
  return (await fetch(API + '/v1/register/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(cred),
  })).json(); // { verified, user: { id } } — session_id cookie is now set
}

export async function login() {
  const opts = await (await fetch(API + '/v1/login/options', { credentials: 'include' })).json();
  const cred = await startAuthentication({ optionsJSON: opts });
  return (await fetch(API + '/v1/login/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(cred),
  })).json();
}
```

### 3. Check auth state

```ts
const res = await fetch(API + '/v1/whoami', { credentials: 'include' });
const session = res.ok ? await res.json() : null; // { user_id } or null
```

## Development

```bash
bun install
bun --cwd packages/gratos-multi dev      # Auth API on :8789
bun --cwd packages/provisioner dev       # Provisioner on :8788
bun --cwd packages/gratos-dash dev       # Dash on :4322
```

## API Endpoints

Options endpoints return standard WebAuthn options JSON unmodified; verify endpoints accept the bare credential response as the whole POST body.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/register/options` | Standard `PublicKeyCredentialCreationOptionsJSON` |
| POST | `/v1/register/verify` | Verify bare `RegistrationResponseJSON` + create session |
| GET | `/v1/login/options` | Standard `PublicKeyCredentialRequestOptionsJSON` |
| POST | `/v1/login/verify` | Verify bare `AuthenticationResponseJSON` + create session |
| GET | `/v1/whoami` | Get current user from session (cookie or Bearer) |
| POST | `/v1/logout` | Destroy session |
| POST | `/sandbox` | Mint an instant sandbox auth endpoint |

## Full API Documentation

See the [AuthGravity docs](https://authgravity.org/docs) for complete integration guides covering the HTTP API (registration, login, session management) and local development with `npx @authgravity/cli listen`.

A machine-readable version is available at [authgravity.org/llms.txt](https://authgravity.org/llms.txt).

## Key Dependencies

- [@simplewebauthn/browser](https://simplewebauthn.dev/) — client-side WebAuthn
- [@simplewebauthn/server](https://simplewebauthn.dev/) — server-side WebAuthn verification
- [Hono](https://hono.dev/) — Worker HTTP framework
- [Bun](https://bun.sh/) — package manager and runtime
