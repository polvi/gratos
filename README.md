# Gratos

Zero-trust, serverless, headless passkey authentication. Gratos stores only public key material — no passwords, no usernames on the server. User identity lives in the consuming app; Gratos handles WebAuthn credential storage and session management.

Inspired by [Ory Kratos](https://www.ory.sh/kratos/), but solely focused on passkey-based authentication.

## Live Demo

The auth server and two demo apps demonstrate cross-domain passkey authentication:

| Site | Role | Domain |
|------|------|--------|
| **id.letsident.org** | Auth server (Cloudflare Worker) | `letsident.org` |
| **id.proc.io** | Auth server CNAME (alias for id.letsident.org) | `proc.io` |
| [**dash.letsident.org**](https://dash.letsident.org) | Demo app (Cloudflare Worker) | `letsident.org` |
| [**gratos-demo.proc.io**](https://gratos-demo.proc.io) | Demo app (Cloudflare Worker) | `proc.io` |

[dash.letsident.org](https://dash.letsident.org) and [gratos-demo.proc.io](https://gratos-demo.proc.io) are two independent demo apps on **different registrable domains**, both using the same Gratos auth server. A user who registers a passkey on one can sign in on the other using the same credential. `id.proc.io` is a CNAME to `id.letsident.org`, giving the auth server a presence on `proc.io` for setting first-party cookies on that domain.

## How Cross-Domain Auth Works

The key component is `LetsIdent`, a Preact widget that any site can embed. Here's the flow:

```
gratos-demo.proc.io                          id.letsident.org
┌──────────────────────┐                    ┌──────────────────────┐
│                      │                    │                      │
│  LetsIdent component │                    │  Gratos Worker       │
│  ┌────────────────┐  │                    │                      │
│  │ <iframe>       │──┼── /login/prompt ──>│  Serves prompt page  │
│  │ "Sign in"      │  │                    │  inside iframe       │
│  │ "Create acct"  │  │                    │                      │
│  └────────────────┘  │                    │                      │
│                      │                    │                      │
└──────────────────────┘                    └──────────────────────┘
```

### Sign-in (iframe)

1. `LetsIdent` renders an iframe pointing to `id.letsident.org/login/prompt`
2. The iframe uses the `publickey-credentials-get` Permissions Policy to call `navigator.credentials.get()` cross-origin
3. The worker verifies the assertion, creates a session, and generates a one-time code
4. The iframe redirects to `id.proc.io/session/complete?code=<code>`
5. `/session/complete` exchanges the code for a session, sets an `httpOnly` cookie scoped to the demo app's domain, and redirects home
6. The iframe posts `GRATOS_LOGIN_SUCCESS` to the parent; `LetsIdent` calls `/whoami` to confirm

### Registration (popup)

WebAuthn `navigator.credentials.create()` is blocked in cross-origin iframes (`sameOriginWithAncestors` must be `true`). Registration opens in a popup/new tab instead:

1. User clicks "Create account" in the iframe
2. The iframe posts `GRATOS_OPEN_REGISTER` to the parent
3. `LetsIdent` opens `id.letsident.org/register` in a popup (desktop) or new tab (mobile)
4. The registration page runs at top-level on the auth server origin — no iframe restrictions
5. After successful WebAuthn registration + session creation, the popup posts `GRATOS_LOGIN_SUCCESS` to `window.opener` and closes itself
6. `LetsIdent` picks up the message and refreshes user state

### Session Model

- Sessions are cookie-based (`session_id`, `httpOnly`, `secure`, `sameSite=None`)
- Stored in Cloudflare KV with a configurable TTL (default 7 days)
- The one-time code exchange at `/session/complete` lets the consuming app set a session cookie on its own domain, using the `domain_setting` from the client config

### Privacy Model

- The server generates a UUID for each user and **never stores usernames**
- Usernames are only used client-side as the WebAuthn authenticator display name (the `user.name` field is overwritten in the browser before calling `startRegistration`)
- The `users` table contains only `id` — no email, no name, no PII
- Credentials table stores the public key, never private key material

## Architecture

```
Browser
  ├─ @gratos/preact (LetsIdent component)
  │    └─ @simplewebauthn/browser
  │
  └─ iframe / popup ──► Gratos Worker (Hono on Cloudflare Workers)
                           ├─ @simplewebauthn/server
                           ├─ D1 (credentials, users, clients)
                           ├─ KV (sessions, challenges, OIDC codes)
                           └─ OIDC provider (RS256, auto-generated keys)
```

## Monorepo Structure

```
packages/
  worker-runtime/   Cloudflare Worker — WebAuthn, sessions, OIDC
  preact/           @gratos/preact — LetsIdent, AuthContext, Admin
  demo/             Astro SSR app on Cloudflare Workers
  e2e/              Playwright tests with virtual authenticator
```

## Getting Started

```bash
bun install

# Run both in separate terminals:
bun --cwd packages/worker-runtime dev    # Worker on :8787
bun --cwd packages/demo dev              # Demo on :4321
```

## Build & Deploy

```bash
bun --cwd packages/preact build          # Build preact lib
bun run build-demo                       # Build demo (builds preact first)
bun --cwd packages/worker-runtime deploy # Deploy worker
```

## E2E Tests

```bash
bun --cwd packages/e2e test    # Starts both servers, runs Playwright with virtual authenticator
```

## Client Configuration

To add a new consuming site:

1. Register/login on the auth server
2. Go to `/admin` and create a client with:
   - **origin**: the consuming site's origin (e.g., `https://gratos-demo.proc.io`)
   - **domain_setting**: the cookie domain for that site (e.g., `proc.io`)
3. Note the client ID
4. In the consuming app, embed `LetsIdent`:

```tsx
<LetsIdent
  loginBaseUrl="https://id.letsident.org"
  apiBaseUrl="https://id.letsident.org"
  clientId="<your-client-id>"
/>
```

The consuming app must also handle `GET /session/complete?code=<code>&redirect_to=<path>` — this endpoint is served by the Gratos worker and needs to be proxied or the worker must be deployed on a route accessible from the consuming app's domain.

## OIDC

Gratos supports a basic OIDC authorization code flow, primarily for CLI tools:

```
kubectl oidc-login setup --oidc-issuer-url=https://id.proc.io/oidc --oidc-client-id=kubernetes
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/register/options` | Generate WebAuthn registration options |
| POST | `/register/verify` | Verify registration + create session |
| GET | `/login/options` | Generate WebAuthn authentication options |
| POST | `/login/verify` | Verify authentication + create session |
| GET | `/whoami` | Get current user from session |
| POST | `/logout` | Destroy session |
| CRUD | `/clients` | Manage client apps (auth required) |
| GET | `/login` | Full-page auto-login |
| GET | `/login/prompt` | Iframe-embeddable sign-in prompt |
| GET | `/register` | Registration page (popup/standalone) |
| GET | `/login/success` | Posts `GRATOS_LOGIN_SUCCESS` to parent |
| GET | `/session/complete` | One-time code exchange → session cookie |
| GET | `/oidc/.well-known/openid-configuration` | OIDC discovery |
| GET | `/oidc/jwks` | OIDC signing keys |
| GET | `/oidc/authorize` | OIDC authorization |
| POST | `/oidc/token` | OIDC token exchange |

## Key Dependencies

- [@simplewebauthn/browser](https://simplewebauthn.dev/) — Client-side WebAuthn
- [@simplewebauthn/server](https://simplewebauthn.dev/) — Server-side WebAuthn verification
- [Hono](https://hono.dev/) — Worker HTTP framework
- [Bun](https://bun.sh/) — Package manager and runtime
