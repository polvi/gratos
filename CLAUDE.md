# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Gratos

Gratos is a zero-trust, serverless, headless passkey authentication service. It stores only public key material (no passwords, no usernames on server). User identity/profile lives in the consuming app; Gratos handles WebAuthn credential storage and session management via first-party cookies.

## Commands

**Install dependencies:** `bun install`

**Development (run both in separate terminals):**
- Worker: `bun --cwd packages/worker-runtime dev` (port 8787)
- Demo: `bun --cwd packages/demo dev` (port 4321)

**Build:**
- Preact lib: `bun --cwd packages/preact build`
- Demo (builds preact first): `bun run build-demo`
- Worker deploy: `bun --cwd packages/worker-runtime deploy`

**E2E tests:** `bun --cwd packages/e2e test` (auto-starts both servers via Playwright)

## Monorepo Structure

Four packages in a Bun workspace:

- **packages/worker-runtime** — Cloudflare Worker (Hono server). Handles WebAuthn registration/authentication, session management (KV), credential storage (D1), client CRUD, and a basic OIDC provider. Config via wrangler.jsonc bindings.
- **packages/preact** — Published as `@gratos/preact`. Preact components for auth UI (LoginButton, RegisterButton, LogoutButton, UserProfile, Admin, LetsIdent). All components consume `AuthContext` which provides user state and `apiBaseUrl`.
- **packages/demo** — Astro SSR app using `@astrojs/preact` and `@astrojs/cloudflare`. Three pages: `/` (main), `/login`, `/admin`. Environment vars in `.env.local` (`PUBLIC_GRATOS_SERVER`, `PUBLIC_GRATOS_DOMAIN_SERVER`, `PUBLIC_CLIENT_ID`).
- **packages/e2e** — Playwright tests using Chromium's virtual authenticator (CDP) to test full passkey flows.

## Architecture

**Auth flow:** Browser → Preact components → `@simplewebauthn/browser` → Worker API → `@simplewebauthn/server` → D1 (credentials) + KV (sessions/challenges)

**Session model:** Cookie-based (`session_id`, httpOnly, secure, sameSite=None). Sessions stored in KV with TTL (default 7 days). Challenges expire in 5 minutes.

**Cross-domain auth:** The `LetsIdent` component renders an iframe pointing to the auth server's `/login/prompt` page. On successful login, the worker generates a one-time code, redirects to the client's `/session/complete` endpoint which sets a session cookie scoped to that client's `domain_setting`.

**OIDC:** Basic authorization code flow for CLI tools (e.g., `kubectl oidc-login`). RS256 signing keys auto-generated and stored in KV. Endpoints under `/oidc/`.

**Privacy:** Usernames are only used client-side for the authenticator display name. The server generates a UUID for each user and never stores usernames.

## Database (D1)

Three tables: `users(id)`, `public_keys(id, user_id, credential_id, public_key, user_backed_up, transports)`, `clients(id, user_id, origin, domain_setting, created_at)`. Migrations in `packages/worker-runtime/migrations/`.

## Worker API Endpoints

- `GET/POST /register/options, /register/verify` — WebAuthn registration
- `GET/POST /login/options, /login/verify` — WebAuthn authentication
- `GET /whoami`, `POST /logout` — Session management
- `CRUD /clients` — Client management (auth required)
- `GET /oidc/.well-known/openid-configuration`, `/oidc/jwks`, `/oidc/authorize`, `POST /oidc/token` — OIDC
- `GET /login`, `/login/prompt`, `/login/success` — Server-rendered auth pages
- `GET /session/complete` — Cross-domain session establishment
