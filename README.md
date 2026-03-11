# Gratos

Per-app passkey authentication via CNAME. No shared identity, no passwords, no usernames on the server. Each domain pointing to Gratos is its own isolated tenant.

Currently powering letsident.org

Inspired by [Ory Kratos](https://www.ory.sh/kratos/), built on [WebAuthn](https://webauthn.guide/).

## How It Works

Point a CNAME at the Gratos worker. The tenant is auto-derived from the request hostname — no registration step, no admin panel. Users, credentials, and sessions are all isolated per tenant.

```
your-app.com  ──CNAME──►  gratos worker
                           (tenant = your-app.com)
```

Every domain that resolves to the Gratos worker gets its own user pool. A user who registers on `auth.foo.com` has no relationship to a user on `auth.bar.com`.

## Architecture

```
Browser
  ├─ @gratos/preact (LoginButton, RegisterButton, etc.)
  │    └─ @simplewebauthn/browser
  │
  └─ auth.myapp.com (CNAME → Gratos Worker)
       ├─ Hono server on Cloudflare Workers
       ├─ @simplewebauthn/server
       ├─ D1 (users, credentials — scoped by tenant)
       └─ KV (sessions, challenges)
```

## Auth Flow

Because the auth server lives on your domain (via CNAME), everything is same-origin. No iframes, no popups, no cross-domain redirects.

1. User clicks **Register** or **Sign In** in your app
2. `@gratos/preact` calls `auth.myapp.com` for WebAuthn options
3. Browser prompts for passkey (biometric, security key, etc.)
4. `@gratos/preact` sends the response back to `auth.myapp.com` for verification
5. Worker verifies the credential, creates a session, sets an `httpOnly` cookie

RP ID is the registrable domain (e.g., `auth.myapp.com` → RP ID `myapp.com`), so passkeys work across subdomains.

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
  worker-runtime/   Cloudflare Worker: WebAuthn + sessions
  preact/           @gratos/preact: LoginButton, RegisterButton, AuthContext
  demo/             Astro SSR app on Cloudflare Workers
  e2e/              Playwright tests with virtual authenticator
```

## Getting Started

### 1. Add Gratos to your domain

Create a CNAME record pointing to the Gratos worker:

```
auth.myapp.com  CNAME  your-gratos-worker.workers.dev
```

### 2. Embed the auth components

```tsx
import { AuthProvider, LoginButton, RegisterButton } from '@gratos/preact';

function App() {
  return (
    <AuthProvider apiBaseUrl="https://auth.myapp.com">
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

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/register/options` | Generate WebAuthn registration options |
| POST | `/register/verify` | Verify registration + create session |
| GET | `/login/options` | Generate WebAuthn authentication options |
| POST | `/login/verify` | Verify authentication + create session |
| GET | `/whoami` | Get current user from session |
| POST | `/logout` | Destroy session |

## Key Dependencies

- [@simplewebauthn/browser](https://simplewebauthn.dev/) — client-side WebAuthn
- [@simplewebauthn/server](https://simplewebauthn.dev/) — server-side WebAuthn verification
- [Hono](https://hono.dev/) — Worker HTTP framework
- [Bun](https://bun.sh/) — package manager and runtime
