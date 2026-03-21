# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Gratos

Gratos is a zero-trust, serverless, headless passkey authentication service. It stores only public key material (no passwords, no usernames on server). User identity/profile lives in the consuming app; Gratos handles WebAuthn credential storage and session management via first-party cookies.

## Commands

**Install dependencies:** `bun install`

**Development (run both in separate terminals):**

**Build:**
- Preact lib: `bun --cwd packages/preact build`
- Demo (builds preact first): `bun run build-demo`

**E2E tests:** `bun --cwd packages/e2e test` (auto-starts both servers via Playwright)

## Monorepo Structure

Four packages in a Bun workspace:

- **packages/preact** — Published as `@gratos/preact`. Preact components for auth UI (LoginButton, RegisterButton, LogoutButton, UserProfile, Admin, AuthGravity). All components consume `AuthContext` which provides user state and `apiBaseUrl`.
- **packages/demo** — Astro SSR app using `@astrojs/preact` and `@astrojs/cloudflare`. Three pages: `/` (main), `/login`, `/admin`. Environment vars in `.env.local` (`PUBLIC_GRATOS_SERVER`, `PUBLIC_GRATOS_DOMAIN_SERVER`, `PUBLIC_CLIENT_ID`).
- **packages/e2e** — Playwright tests using Chromium's virtual authenticator (CDP) to test full passkey flows.

## Architecture

**Auth flow:** Browser → Preact components → `@simplewebauthn/browser` → Worker API → `@simplewebauthn/server` → D1 (credentials) + KV (sessions/challenges)

**Session model:** Cookie-based (`session_id`, httpOnly, secure, sameSite=None). Sessions stored in KV with TTL (default 7 days). Challenges expire in 5 minutes.

**Cross-domain auth:** The `AuthGravity` component renders an iframe pointing to the auth server's `/login/prompt` page. On successful login, the worker generates a one-time code, redirects to the client's `/session/complete` endpoint which sets a session cookie scoped to that client's `domain_setting`.

**OIDC:** Basic authorization code flow for CLI tools (e.g., `kubectl oidc-login`). RS256 signing keys auto-generated and stored in KV. Endpoints under `/oidc/`.

**Privacy:** Usernames are only used client-side for the authenticator display name. The server generates a UUID for each user and never stores usernames.

## Database (D1)


## Worker API Endpoints

- `GET/POST /register/options, /register/verify` — WebAuthn registration
- `GET/POST /login/options, /login/verify` — WebAuthn authentication
- `GET /whoami`, `POST /logout` — Session management
- `CRUD /clients` — Client management (auth required)
- `GET /oidc/.well-known/openid-configuration`, `/oidc/jwks`, `/oidc/authorize`, `POST /oidc/token` — OIDC
- `GET /login`, `/login/prompt`, `/login/success` — Server-rendered auth pages
- `GET /session/complete` — Cross-domain session establishment

## Docs

Keep packages/gratos-dash/public/llms.txt and packages/gratos-dash/src/pages/docs.astro in sync as the dash features change. 
