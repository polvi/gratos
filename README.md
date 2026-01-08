# Gratos

Gratos is an open-source, serverless, headless, first-party authentication service for the post-password era. It provides modern, privacy-focused user authentication using passkeys, designed to run easily at the edge.

Gratos is inspired by [Ory Kratos](https://www.ory.sh/kratos/), however it is solely focused on passkey based authentication. The user identity layer is intended to be stored in the app, with Gratos only storing and verifying public key information from webauthn, creating first party sessions leveraging the domain attribute, and allowing for third party oauth flows.

This project is organized as follows:
- packages/preact, with includes preact components published at @gratos/preact
- packages/worker-runtime, which includes the cloudflare worker implementing the server side componets, leveraging D1 for users, public keys and KV for limiting the TTL limited challenges and sessions

The project leverages the following packages:
- @simplewebauthn/browser for the component libraries
- @simplewebauthn/server for the cloudflare worker implementation
- [passkey guidance](https://simplewebauthn.dev/docs/advanced/passkeys)
- Hono for worker server
- bun as an npm replacement

## Getting Started

Install dependencies and start the local development server:

```bash
bun install
bun --cwd packages/worker-runtime dev
bun --cwd packages/demo dev
```
