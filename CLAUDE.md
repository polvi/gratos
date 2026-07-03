# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Gratos

Gratos is a zero-trust, serverless, headless passkey authentication service. It stores only public key material (no passwords, no usernames on server). User identity/profile lives in the consuming app; Gratos handles WebAuthn credential storage and session management via first-party cookies.

## Commands

**Install dependencies:** `bun install`

**Development:**
- Auth API: `bun --cwd packages/gratos-multi dev` (port 8789)
- Provisioner: `bun --cwd packages/provisioner dev` (port 8788)
- Dash (Astro): `bun --cwd packages/gratos-dash dev`

**Build/deploy:**
- Preact lib: `bun --cwd packages/preact build`
- Each Worker deploys with `wrangler deploy --env prod` from its package dir (dash builds preact + astro first).

## Monorepo Structure

Bun workspace, `packages/*`:

- **packages/gratos-multi** — The auth API Worker (Hono, `@simplewebauthn/server`). Multi-tenant: the tenant/rpId/cookieDomain are derived from the request Host (`src/tenant.ts`). Isolated user pool per tenant. Deployed at `authgravity.authgravity.org`. Also exports a `WorkerEntrypoint` RPC class `AuthRPC` (`resolveSession`, `getTenantStats`, `sweepSandboxes`) used by other Workers via service binding.
- **packages/provisioner** — Domain-claim Worker (Hono + cron). Users claim a domain by adding `CNAME authgravity.<domain> → cname.authgravity.net`; the provisioner verifies DNS and creates a Cloudflare Custom Hostname. Deployed at `provision.api.authgravity.org`; has a service binding `AUTH → gratos-multi`.
- **packages/gratos-dash** — Astro SSR site (`@astrojs/cloudflare`, `@astrojs/preact`) at `authgravity.org`. Pages: `/`, `/about`, `/docs`, `/domains`, `/login`, `/signup`. Env: `PUBLIC_GRATOS_SERVER`, `PUBLIC_PROVISIONER_SERVER`.
- **packages/preact** — Published as `@gratos/preact`. Auth UI components (LoginButton, RegisterButton, LogoutButton, UserProfile, Admin) consuming `AuthContext` (`apiBaseUrl` + user state).
- **packages/cli** — Published as `@authgravity/cli` (binary `authgravity`, Stripe-style subcommands). `authgravity listen` runs a local dev proxy (Bun + Hono, default port 8787): mints an instant sandbox, reverse-proxies auth calls to it, and translates the sandbox's Bearer session into a first-party httpOnly `session_id` cookie on `localhost` — so local apps run the exact same cookie-based auth code as production (including SSR `/whoami` checks).

Note: there is no `packages/demo` or `packages/e2e`; an older single-tenant `worker-runtime` (with OIDC/`/clients`) was removed.

## Architecture

**Auth flow:** Browser → `@simplewebauthn/browser` → gratos-multi Worker → `@simplewebauthn/server` → D1 (users/public_keys) + KV (sessions/challenges).

**Multi-tenant:** `resolveTenant(url)` strips the first Host label, so `authgravity.<domain>` → tenant/rpId/cookieDomain `<domain>`. Sessions are namespaced `session:{tenant}:{sessionId}` in KV.

**Session model:** Cookie-based (`session_id`, httpOnly, secure, sameSite=None, 7-day KV TTL). `/whoami` also accepts `Authorization: Bearer <session_id>`. Challenges expire in 5 minutes.

**Instant sandbox (agent onboarding):** `POST /sandbox` mints `https://sandbox.authgravity.org/<id>` — a single Workers custom domain (auto DNS + cert, no ACM/wildcard) with the isolated sandbox id in the path. Tenant is `sandbox.authgravity.org/<id>` (`resolveTenant` reads the first path segment; the `/<id>` prefix is stripped before dispatching auth/session routes). Sandbox tenants use `rpID=localhost` and return `session_id` in the verify body (Bearer-usable) with **no domain and no DNS**. Local apps don't consume the Bearer directly: `authgravity listen` (packages/cli) proxies the sandbox on `localhost:8787` and terminates the session as a first-party `session_id` cookie, so app code is cookie-only and identical to production. Throwaway; swept by `AuthRPC.sweepSandboxes`. The full agent recipe (`src/lib/auth.ts`, `authgravity listen`, sandbox → domain promotion) lives in `packages/gratos-dash/public/llms.txt`.

**Privacy:** Usernames are only used client-side for the authenticator display name. The server generates a UUID per user and never stores usernames.

## Worker API Endpoints (gratos-multi)

- `GET/POST /register/options, /register/verify` — WebAuthn registration
- `GET/POST /login/options, /login/verify` — WebAuthn authentication
- `GET /whoami`, `POST /logout` — Session management (cookie or Bearer)
- `POST /sandbox` — Mint an instant sandbox auth endpoint (unauthenticated)
- `GET /`, `GET /demo` — Health + self-contained demo page

Domain claiming lives in the provisioner: `POST /claims`, `GET /claims/:id`, `POST /claims/:id/activate`, `GET /domains`, etc.

## Docs

Keep packages/gratos-dash/public/llms.txt and packages/gratos-dash/src/pages/docs.astro in sync as the dash features change. 

## Spec

In a seperate agent, keep the specs/ file up to date using TLA+. This involves making changes to the .tla file whenever the architecture changes. Then validate the change using the the tla checker at:

~/Downloads/tla2tools.jar

Be sure that specs are finite and if the checker runs for more than 30s, kill it and figure out why states blew up. Do this in the background and do not block the users UI when you're doing this. 
