# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Gratos

Gratos is a zero-trust, serverless, headless passkey authentication service. It stores only public key material (no passwords, no usernames on server). User identity/profile lives in the consuming app; Gratos handles WebAuthn credential storage and session management via first-party cookies.

## Commands

**Install dependencies:** `bun install`

**Development:**
- Auth API: `bun --cwd packages/gratos-multi dev` (port 8789)
- Authz: `bun --cwd packages/gratos-authz dev` (port 8790; run alongside gratos-multi — the dev registry wires the AUTHZ service binding)
- Provisioner: `bun --cwd packages/provisioner dev` (port 8788)
- Dash (Astro): `bun --cwd packages/gratos-dash dev`

**Build/deploy:**
- Each Worker deploys with `wrangler deploy --env prod` from its package dir (dash builds astro first).

## Monorepo Structure

Bun workspace, `packages/*`:

- **packages/gratos-multi** — The auth API Worker (Hono, `@simplewebauthn/server`). Multi-tenant: the tenant/rpId/cookieDomain are derived from the request Host (`src/tenant.ts`). Isolated user pool per tenant. Deployed at `authgravity.authgravity.org`. Also exports a `WorkerEntrypoint` RPC class `AuthRPC` (`resolveSession`, `getTenantStats`, `sweepSandboxes`) used by other Workers via service binding.
- **packages/gratos-authz** — Zanzibar/SpiceDB-style authorization Worker (Hono, own D1 `gratos-authz-db`, tenant-column pattern). **Internal-only**: no routes, `workers_dev: false`; gratos-multi mounts it at `/authz` (console) and `/v1/authz/*` on every tenant host via the `AUTHZ` service binding (entrypoint `AuthzRPC`), forwarding trusted `X-Gratos-Tenant`/`X-Gratos-User`/`X-Gratos-Sandbox` headers after resolving the session. Tenants get a JSON schema (relations + permissions with union/intersection/exclusion/arrow), relationship tuples, and checks. **Control plane**: the ROOT_TENANT space (`authgravity.org` prod / `localhost` dev) holds `gratos_tenant:<tenant>#owner@user:<dash-uuid>` tuples written ONLY via `AuthzRPC.grantTenantOwners` by onboarding (domain claim, owned-sandbox mint) and removed by `AuthzRPC.cleanupTenant`. Mutations are allowed for the tenant's owner via on-behalf routes `/v1/authz/tenants/:target/*` (dash session on the root host) or for anyone in an **anonymous** sandbox (open pools); there is no bootstrap and no in-tenant admin concept. `gratos_tenant` is never readable/writable/checkable over HTTP. `AuthzRPC.check(tenant, object, permission, subject)` is available to other Workers; `AuthzRPC.verifyServiceToken(tenant, secret)` lets gratos-multi accept `agk_` tokens on its own backend-facing endpoints (user provisioning, sign-in codes). Deploy order: gratos-authz → gratos-multi → provisioner. Dev note: to make a tenant manageable locally, seed an owner tuple in the root space (`wrangler d1 execute gratos-authz-db --local --command "INSERT OR IGNORE INTO relationships VALUES ('localhost','gratos_tenant','<tenant>','owner','user','<uuid>','',0)"`).
- **packages/provisioner** — Domain-claim Worker (Hono + cron). Users claim a domain by adding `CNAME authgravity.<domain> → cname.authgravity.net`; the provisioner verifies DNS and creates a Cloudflare Custom Hostname. On claim it grants the claimer authz ownership via `AUTHZ.grantTenantOwners`; the cron also reconciles owner tuples (domains + owned sandboxes) and runs `AUTH.sweepSandboxes()`. Deployed at `provision.api.authgravity.org`; service bindings `AUTH → gratos-multi (AuthRPC)`, `AUTHZ → gratos-authz (AuthzRPC)`.
- **packages/gratos-dash** — Astro SSR site (`@astrojs/cloudflare`, `@astrojs/preact`) at `authgravity.org`. Pages: `/`, `/about`, `/docs`, `/domains`, `/login`, `/signup`. Env: `PUBLIC_GRATOS_SERVER`, `PUBLIC_PROVISIONER_SERVER`. Auth UI (AuthProvider/useAuth, LoginButton, RegisterButton) lives in `src/components/auth.tsx`; external apps integrate via the llms.txt recipe, not a published component library.
- **packages/cli** — Published as `@authgravity/cli` (binary `authgravity`, Stripe-style subcommands). `authgravity listen` runs a local dev proxy (Bun + Hono, default port 8787): mints an instant sandbox, reverse-proxies auth calls to it, and translates the sandbox's Bearer session into a first-party httpOnly `session_id` cookie on `localhost` — so local apps run the exact same cookie-based auth code as production (including SSR `/whoami` checks).

Note: there is no `packages/demo` or `packages/e2e`; an older single-tenant `worker-runtime` (with OIDC/`/clients`) was removed.

## Architecture

**Auth flow:** Browser → `@simplewebauthn/browser` → gratos-multi Worker → `@simplewebauthn/server` → D1 (users/public_keys) + KV (sessions/challenges).

**Multi-tenant:** `resolveTenant(url)` strips the first Host label, so `authgravity.<domain>` → tenant/rpId/cookieDomain `<domain>`. Sessions are namespaced `session:{tenant}:{sessionId}` in KV.

**Session model:** Cookie-based (`session_id`, httpOnly, secure, sameSite=None, 7-day KV TTL). `/v1/whoami` also accepts `Authorization: Bearer <session_id>`. Challenges expire in 5 minutes and are single-use; pending-ceremony state is keyed in KV by the challenge value itself (`reg_challenge:{tenant}:{challenge}` → userId, `auth_challenge:{tenant}:{challenge}`), which verify recovers from the signed `clientDataJSON.challenge` — no correlation id. A second, JS-readable `ag_last_used` cookie (`<login|register>.<amr>`, 1 year, same domain, kept on logout; also returned as `last_used` in verify JSON and mirrored onto localhost by `authgravity listen`) is set by every session-minting ceremony so sign-in UIs can show a "Last used" hint (`src/last-used.ts`; `lastUsed()` in `@authgravity/browser`; the hosted `/login` and `/register` surfaces render the pill).

**Instant sandbox (agent onboarding):** `POST /sandbox` mints `https://sandbox.authgravity.org/<id>` — a single Workers custom domain (auto DNS + cert, no ACM/wildcard) with the isolated sandbox id in the path. Tenant is `sandbox.authgravity.org/<id>` (`resolveTenant` reads the first path segment; the `/<id>` prefix is stripped before dispatching auth/session routes). Sandbox tenants use `rpID=localhost` and return `session_id` in the verify body (Bearer-usable) with **no domain and no DNS**. Local apps don't consume the Bearer directly: `authgravity listen` (packages/cli) proxies the sandbox on `localhost:8787` and terminates the session as a first-party `session_id` cookie, so app code is cookie-only and identical to production. Anonymous sandboxes are throwaway (swept by `AuthRPC.sweepSandboxes` after 7 days); sandboxes minted with a dash session are owned (`sandboxes.user_id`), listed/deleted from the dashboard, and persist until deleted. The full agent recipe (`src/lib/auth.ts`, `authgravity listen`, sandbox → domain promotion) is generated per-host by `buildLlmsTxt` and served at every host's `/llms.txt`.

**Privacy:** Usernames are only used client-side for the authenticator display name. The server generates a UUID per user and never stores usernames.

## Worker API Endpoints (gratos-multi)

v1 — spec-shaped WebAuthn JSON (options returned unmodified; verify takes the bare credential response as the whole body):

- `GET /v1/register/options[?label=]`, `POST /v1/register/verify` — WebAuthn registration. With a valid session it ADDS a passkey to that user (multi-passkey): options carry `excludeCredentials` for the user's existing passkeys, any authenticator attachment is allowed, the `MAX_CREDENTIALS_PER_USER` cap (10, `src/db.ts`) applies, and a known credential id gets 409. Passkeys store `label` (from `?label=`), `aaguid` (→ provider name via `src/aaguid.ts`), `transports`, and the signature `counter` (migration 0008); verify returns `credential: {id}` (row id)
- `GET /v1/login/options`, `POST /v1/login/verify` — WebAuthn authentication
- `GET|POST /v1/key/(register|login)/(options|verify)` — Account-key/device-key credentials (`src/keys.ts`): client-derived P-256 keys (128-bit `agak1_…` secret or 12 BIP39 words, HKDF salted by tenant — spec + vectors in `tests/keyspec-ref.ts`/`keyspec.test.ts`); server stores public keys only in `public_keys` with `kind` = webauthn|devicekey|softkey. Bring-your-own external BIP39 phrases work with no server change: client decodes → register (claim) → on 409, login (recover) — create-or-recover is purely client-side
- `GET /v1/credentials`, `DELETE /v1/credentials/:id` — Credential management (session; rows carry `kind, label, provider, display, backed_up, transports, created_at, last_used_at, current`; `current` = the credential that minted this session, which sessions now record as `c`; rank rule: a session can't remove a credential stronger than its own `amr`; last credential undeletable)
- `GET /v1/key/wordlist.json` — BIP39 English wordlist (encoding only)
- `GET /v1/whoami`, `POST /v1/logout` — Session management (cookie or Bearer). Sessions are JSON `{u, amr, c?}` in KV (`src/sessions.ts`; `c` = row id of the minting credential, surfaced as `current` in `/v1/credentials`; legacy bare-userId values parse as amr=webauthn, an unknown amr fails closed); `whoami` and authz `status` report `amr` (webauthn > device > key > otp). Adding a credential while signed in re-mints the session at `min(session amr, new credential amr)`, never higher
- App-delivered sign-in codes (`src/codes.ts`, for users without passkeys; admin-provisioned accounts only): `POST /v1/users` (service token → `{user_id}`, no credentials), `POST /v1/code/start` (browser → `{ticket, verifier}`; D1 `code_tickets` (migration 0009) stores only hashes, and tries/claim are conditional UPDATE/DELETE … RETURNING so they stay atomic under parallel guesses), `POST /v1/code/mint {ticket, user_id}` (service token → 6-digit `code`, 10 min, ≤3 per ticket, ≤5/user/hour), `POST /v1/code/verify {ticket, verifier, code}` (≤5 tries; mints an `otp` session). The app owns the phone/email → user_id mapping and delivery; Gratos never sees either. Service-token routes accept `Bearer agk_…` via `AUTHZ.verifyServiceToken`, and anonymous sandboxes need none. SDK: `startCodeLogin`/`verifyCode` (browser), `createUser`/`mintCode` (server)

Unversioned:

- `POST /sandbox` — Mint an instant sandbox auth endpoint (anonymous OK; with a valid session the sandbox is owned by that user)
- `GET /sandboxes`, `DELETE /sandboxes/:sid` — List/delete the requester's owned sandboxes (session required)
- `GET /`, `GET /demo` — Health + self-contained demo page (alias → `/login`)
- Hosted surfaces (`src/surfaces.ts`, `?return_to=`): `/login`, `/register` (`?mode=recovery` jumps to the 12-words flow for a signed-in user), `/recover`, `/account` (session-gated: list credentials, add a passkey with optional name, remove, recovery-key link; bounces through `/login` on 401), `/logout`, `/consent`

Authz (served on every tenant host, forwarded to gratos-authz; session required; writes require manage = tenant owner via on-behalf routes, or any user in an anonymous sandbox):

- `GET /v1/authz/status` — `{user_id, mode: "open-sandbox"|"managed", can_manage, schema_version}`
- `GET|PUT /v1/authz/schema` — Tenant schema document (PUT is manage-gated, validated)
- `POST|GET /v1/authz/relationships` — Batch tuple writes (manage-gated, atomic) / filtered reads
- `POST /v1/authz/check` — `{object, permission, subject?}` → `{allowed, user_id?}` (subject omitted/`"self"` = session user; explicit required with service tokens). Batch: `{items: [...]}` (≤50, concurrent) → `{results, user_id?}`
- `GET|PUT|POST /v1/authz/tenants/:tenant/(status|schema|relationships|check)` — Owner management (root-host dash session; `:tenant` URL-encoded)
- `POST /v1/authz/tenants/:tenant/generate-schema` — AI schema draft: crawls the tenant's site (Browser Rendering `/crawl` API with homepage-fetch fallback; needs `CF_ACCOUNT_ID` var + `CF_API_TOKEN` secret on gratos-authz), drafts a schema with Workers AI (`@cf/moonshotai/kimi-k2.7-code`, validated + one retry), and returns `{schema, description, pages, model}` without saving
- `GET /authz` — Self-contained console (like `/demo`; full editor only for open sandboxes)
- `GET /llms.txt` — **Unified per-host agent guide** (auth + account keys + session validation + authz rendered from the live schema), endpoint pre-filled. One generator (`gratos-authz/src/llmstxt.ts` `buildLlmsTxt`) with three framings by host kind: `root` (authgravity.org — onboarding), `sandbox`, `domain`. Unauthenticated; served by gratos-authz, forwarded like `/authz`. The dash surfaces one copy-paste prompt (`gratos-dash/src/components/agentPrompt.ts`) that just points an agent at this file
- `GET /.well-known/authgravity` — Host discovery JSON (endpoint + `llms.txt` URL); served by gratos-multi for domain/sandbox hosts so "point your agent at the endpoint" is self-describing
- **Service tokens**: owner-minted per-tenant credentials (`agk_…`, SHA-256 hashes in `service_tokens`) that let the tenant's app backend write/read/check relationships at runtime via `Authorization: Bearer agk_…` on the tenant host (schema changes stay owner-only). Managed via `POST|GET|DELETE /v1/authz/tenants/:tenant/tokens[/:id]` and the dash panel; removed by `cleanupTenant`

Domain claiming lives in the provisioner: `POST /claims`, `GET /claims/:id`, `POST /claims/:id/activate`, `GET /domains`, etc.

**AAuth Person Server** (`src/aauth/` in gratos-multi; served on every tenant host like `/v1/authz`): each pool is an AAuth PS (draft-hardt-oauth-aauth-protocol + AAuth-Budget/TPX-A). Cross-service wire shapes are PINNED by `~/Code/ologico/india/mgmt/contracts/aauth-seams.md` — it wins on any conflict. Discovery `GET /.well-known/aauth-person.json` (issuer = origin + sandbox prefix); agent-facing `POST /v1/aauth/(token|mission|permission|audit|interaction)` + `GET /v1/aauth/mission/:s256` + `GET|POST|DELETE /v1/aauth/pending/:id`, all RFC 9421-signed (Ed25519 ONLY; agent token in `Signature-Key`; `authorization`/`aauth-mission` must be covered when present; hand-rolled verifier in `aauth/httpsig.ts`). Consent is session-gated: hosted `/consent?code=` surface + `GET|POST /v1/aauth/consent`, `GET|DELETE /v1/aauth/grants[/:id]`, `GET /v1/aauth/missions` + `POST /v1/aauth/missions/:id/revoke`. Tokens: `aa-auth+jwt`, Ed25519, ≤600s, base profile (`sub` = pool UUID, nothing else) or budgeted profile (NO sub — `agent`/`mission`/`budget`). Missions are D1-backed (proposals wait days; third-party approval via optional intended-approver binding); budgets attenuate narrow-only at consent; s256 = sha256 over the exact stored approved blob. Budget entries match resource token **`iss`** (never `aud`); `aud` routes mint-vs-relay (four-party relay POSTs `{resource_token, agent_token, budget_attestation}` to the AS and passes `funded`/`funding_url` through). Per-tenant Ed25519 signing keys live KEK-wrapped in D1 (`ps_keys`; secret `PS_KEK`, dev fallback when unset); sandbox sweep + `AuthRPC.sweepAauth` (provisioner cron) clean up.

## Docs

There is a single source of truth for the machine-readable docs: the `buildLlmsTxt` generator in `gratos-authz/src/llmstxt.ts`. Every host serves its own `/llms.txt` from it; `authgravity.org/llms.txt` is the dash SSR route `gratos-dash/src/pages/llms.txt.ts`, which proxies the product tenant's own host doc (root framing) so there's one canonical URL and no duplicated prose. When auth/authz features change, update the generator only.

`gratos-dash/src/pages/docs.astro` is **human-oriented** (big picture, mental model, how to build with a coding agent — Claude Code as the reference example). Keep it conceptual and point to `/llms.txt` for implementation detail; do not paste API/curl specifics back into it.

## Spec

In a seperate agent, keep the specs/ file up to date using TLA+. This involves making changes to the .tla file whenever the architecture changes. Then validate the change using the the tla checker at:

~/Downloads/tla2tools.jar

Be sure that specs are finite and if the checker runs for more than 30s, kill it and figure out why states blew up. Do this in the background and do not block the users UI when you're doing this. 

