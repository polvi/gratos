# Shared Notes — an AuthGravity reference app

A minimal, real multi-user app that shows how little you write to get passkey
auth **and** per-resource authorization with AuthGravity. It has **no login UI of
its own**: sign-in happens on AuthGravity's hosted surfaces, and every note is
gated by a relationship check.

What it demonstrates:

1. **Zero-build auth (hosted surfaces).** `src/middleware.ts` protects `/app` by
   forwarding the session cookie to `/v1/whoami`; if there's no session it
   redirects to `${PUBLIC_AUTH_ENDPOINT}/login?return_to=<back-here>`. AuthGravity
   hosts the passkey + account-key UI; you build none of it.
2. **Server-side session validation.** The same `/v1/whoami` forward gives you the
   stable user UUID — you own your data keyed by it (here, notes in KV).
3. **Authorization with `@authgravity/server`.** Listing notes is one batch
   `check` (`src/pages/app.astro`); creating a note writes an `owner` tuple; the
   owner can add a `viewer` (`src/pages/api/*`). Schema in `schema.json`.

## Run it locally

```bash
# 1. Run the AuthGravity dev proxy in another terminal (mints an instant sandbox):
npx @authgravity/cli listen           # → http://localhost:8787

# 2. Apply the authz schema to the sandbox (open sandboxes accept any user's PUT;
#    sign in once at http://localhost:8787/register, then:)
curl -X PUT http://localhost:8787/v1/authz/schema \
  -H 'Content-Type: application/json' --data @schema.json \
  # add: -H "Authorization: Bearer <session_id>"  (or run from the /authz console)

# 3. Create a KV namespace and put its id in wrangler.jsonc:
wrangler kv namespace create NOTES

# 4. Start the app (PUBLIC_AUTH_ENDPOINT defaults to http://localhost:8787):
bun run dev                            # → http://localhost:4323
```

Open the app, click "Sign in", complete the passkey on the hosted surface, and
you're back in your notes. Create one, then open a second browser profile,
register a different user, copy their UUID, and share a note with them.

## Production

Point `PUBLIC_AUTH_ENDPOINT` at your domain's auth host
(`https://authgravity.yourapp.com`) and set a service token as a secret:
`wrangler secret put AUTHZ_SERVICE_TOKEN` (mint it in the dashboard's
Authorization panel). In an open sandbox the token is optional — writes fall back
to the user's session.

Full API details: `https://authgravity.yourapp.com/llms.txt`.
