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
  ├─ @gratos/preact (LoginButton, RegisterButton, etc.)
  │    └─ @simplewebauthn/browser
  │
  └─ authgravity.myapp.com (CNAME → Gratos Worker)
       ├─ Hono server on Cloudflare Workers
       ├─ @simplewebauthn/server
       ├─ D1 (users, credentials — scoped by tenant)
       └─ KV (sessions, challenges)
```

## Auth Flow

Because the auth server lives on your domain (via CNAME), everything is same-origin. No iframes, no popups, no cross-domain redirects.

1. User clicks **Register** or **Sign In** in your app
2. `@gratos/preact` calls `authgravity.myapp.com` for WebAuthn options
3. Browser prompts for passkey (biometric, security key, etc.)
4. `@gratos/preact` sends the response back to `authgravity.myapp.com` for verification
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
  preact/           @gratos/preact: LoginButton, RegisterButton, AuthContext
  gratos-dash/      AuthGravity dashboard and docs site (Astro)
  provisioner/      Domain provisioning service
```

## Getting Started

### 1. Claim your domain

Sign up at [authgravity.org](https://authgravity.org) and enter your domain. Add the CNAME record provided:

```
authgravity  CNAME  <token>.cname.authgravity.net
```

The target is a unique per-claim token (e.g., `ab3kx7.cname.authgravity.net`) that proves DNS ownership. AuthGravity polls and activates automatically.

### 2. Embed the auth components

```tsx
import { AuthProvider, LoginButton, RegisterButton } from '@gratos/preact';

function App() {
  return (
    <AuthProvider apiBaseUrl="https://authgravity.myapp.com">
      <LoginButton />
      <RegisterButton />
    </AuthProvider>
  );
}
```

### 3. Check auth state

```tsx
import { useAuth } from '@gratos/preact';

function Profile() {
  const { user, isLoading } = useAuth();
  if (isLoading) return <p>Loading...</p>;
  if (!user) return <p>Not signed in</p>;
  return <p>User: {user.id}</p>;
}
```

## Development

```bash
bun install

# Run both in separate terminals:
bun --cwd packages/demo dev              # Demo on :4321
```

## Build & Deploy

```bash
bun --cwd packages/preact build          # Build preact lib
bun run build-demo                       # Build demo (builds preact first)
```

## E2E Tests

```bash
bun --cwd packages/e2e test    # Starts both servers, runs Playwright with virtual authenticator
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

## Full API Documentation

See the [AuthGravity docs](https://authgravity.org/docs) for complete integration guides covering both the `@gratos/preact` component library and the native HTTP API (registration, login, session management, client CRUD).

A machine-readable version is available at [authgravity.org/llms.txt](https://authgravity.org/llms.txt).

## Key Dependencies

- [@simplewebauthn/browser](https://simplewebauthn.dev/) — client-side WebAuthn
- [@simplewebauthn/server](https://simplewebauthn.dev/) — server-side WebAuthn verification
- [Hono](https://hono.dev/) — Worker HTTP framework
- [Bun](https://bun.sh/) — package manager and runtime
