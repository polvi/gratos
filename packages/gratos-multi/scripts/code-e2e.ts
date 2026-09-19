// End-to-end exercise of app-delivered sign-in codes against a local
// `wrangler dev` (gratos-multi :8789 + gratos-authz :8790, tenant "localhost").
// Needs a service token for tenant "localhost" in the local gratos-authz-db:
//
//   TOKEN=agk_e2e_$(openssl rand -hex 16)
//   HASH=$(printf %s "$TOKEN" | shasum -a 256 | cut -d' ' -f1)
//   (cd ../gratos-authz && bunx wrangler d1 execute gratos-authz-db --local --command \
//     "INSERT INTO service_tokens (id, tenant, name, token_hash, created_at) VALUES ('e2e','localhost','e2e','$HASH',0)")
//   TOKEN=$TOKEN bun scripts/code-e2e.ts

import { derivePrivateKey, publicKeyFor, signPayload, b64u } from '../tests/keyspec-ref';
import { keySignaturePayload, KEY_REGISTER_CONTEXT, KEY_LOGIN_CONTEXT } from '../src/keys';

const BASE = process.env.BASE ?? 'http://localhost:8789';
const TENANT = 'localhost';
const TOKEN = process.env.TOKEN;
if (!TOKEN) throw new Error('set TOKEN to a service token for tenant "localhost" (see header)');

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
    if (cond) console.log(`  ✓ ${name}`);
    else {
        failures++;
        console.error(`  ✗ ${name}`, extra ?? '');
    }
}

function sessionFrom(res: Response): string | null {
    const m = (res.headers.get('set-cookie') ?? '').match(/session_id=([^;]+)/);
    return m ? m[1] : null;
}

async function post(path: string, body: unknown, headers: Record<string, string> = {}) {
    const res = await fetch(`${BASE}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json().catch(() => ({}))) as any, session: sessionFrom(res) };
}

const service = { Authorization: `Bearer ${TOKEN}` };

async function whoami(session: string) {
    const res = await fetch(`${BASE}/v1/whoami`, { headers: { Authorization: `Bearer ${session}` } });
    return (await res.json()) as any;
}

async function keyCeremony(phase: 'register' | 'login', priv: Uint8Array, bearer?: string) {
    const auth = bearer ? { Authorization: `Bearer ${bearer}` } : {};
    const opts = (await (await fetch(`${BASE}/v1/key/${phase}/options`, { headers: auth })).json()) as any;
    const ctx = phase === 'register' ? KEY_REGISTER_CONTEXT : KEY_LOGIN_CONTEXT;
    const payload = keySignaturePayload(ctx, opts.challenge, TENANT);
    return post(
        `/v1/key/${phase}/verify`,
        {
            challenge: opts.challenge,
            public_key: b64u(publicKeyFor(priv)),
            signature: b64u(signPayload(priv, payload)),
            ...(phase === 'register' ? { kind: 'devicekey', label: 'e2e computer' } : {}),
        },
        auth
    );
}

console.log('provisioning');
check('POST /v1/users without a token → 401', (await post('/v1/users', {})).status === 401);
check('POST /v1/users with a forged token → 401', (await post('/v1/users', {}, { Authorization: 'Bearer agk_nope' })).status === 401);
const created = await post('/v1/users', {}, service);
check('POST /v1/users with the service token → 201 {user_id}', created.status === 201 && !!created.body.user_id, created);
const userId: string = created.body.user_id;

console.log('code sign-in');
const start = await post('/v1/code/start', {});
check('start → ticket + verifier', !!start.body.ticket && !!start.body.verifier, start.body);
const { ticket, verifier } = start.body;
check('mint without a token → 401', (await post('/v1/code/mint', { ticket, user_id: userId })).status === 401);
check(
    'mint for an unknown user → 404',
    (await post('/v1/code/mint', { ticket, user_id: crypto.randomUUID() }, service)).status === 404
);
const minted = await post('/v1/code/mint', { ticket, user_id: userId }, service);
check('mint → 6-digit code', /^\d{6}$/.test(minted.body.code ?? ''), minted.body);
const code: string = minted.body.code;
const wrong = String((Number(code) + 1) % 1_000_000).padStart(6, '0');

check(
    'the right code without the verifier → 400',
    (await post('/v1/code/verify', { ticket, verifier: 'x'.repeat(43), code })).status === 400
);
for (let i = 0; i < 4; i++) await post('/v1/code/verify', { ticket, verifier, code: wrong });
const ok = await post('/v1/code/verify', { ticket, verifier, code });
check('4 wrong codes, then the right one → verified', ok.status === 200 && ok.body.verified === true, ok.body);
check('last_used is login.otp', ok.body.last_used === 'login.otp', ok.body);
check('session cookie set', !!ok.session);
const otpSession = ok.session!;
const me = await whoami(otpSession);
check('whoami: same user, amr otp', me.user_id === userId && me.amr === 'otp', me);
check('the code is single-use', (await post('/v1/code/verify', { ticket, verifier, code })).status === 400);

console.log('device key enrollment from a code session');
const priv = derivePrivateKey(crypto.getRandomValues(new Uint8Array(16)), TENANT);
const enrolled = await keyCeremony('register', priv, otpSession);
check('device key attached to the code user', enrolled.status === 200 && enrolled.body.user?.id === userId, enrolled.body);
const capped = await whoami(enrolled.session!);
check('re-minted session stays otp (no upgrade)', capped.amr === 'otp', capped);
const silent = await keyCeremony('login', priv);
const silentMe = await whoami(silent.session!);
check('later silent login → amr device', silentMe.user_id === userId && silentMe.amr === 'device', silentMe);

console.log('lockout');
const t2 = (await post('/v1/code/start', {})).body;
const c2 = (await post('/v1/code/mint', { ticket: t2.ticket, user_id: userId }, service)).body.code as string;
const w2 = String((Number(c2) + 1) % 1_000_000).padStart(6, '0');
for (let i = 0; i < 5; i++) await post('/v1/code/verify', { ticket: t2.ticket, verifier: t2.verifier, code: w2 });
check(
    'after 5 wrong codes the right one is refused',
    (await post('/v1/code/verify', { ticket: t2.ticket, verifier: t2.verifier, code: c2 })).status === 400
);

if (failures) {
    console.error(`\n${failures} check(s) failed`);
    process.exit(1);
}
console.log('\nall checks passed');
