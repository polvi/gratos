// End-to-end exercise of the account-key/device-key flows against a local
// `wrangler dev` (port 8789, tenant "localhost"). Acts as a conforming client
// using the reference implementation. Run: bun scripts/key-e2e.ts

import { p256 } from '@noble/curves/nist.js';
import {
    decodeCompact,
    decodeWords,
    encodeCompact,
    encodeWords,
    derivePrivateKey,
    publicKeyFor,
    signPayload,
    b64u,
} from '../tests/keyspec-ref';
import { keySignaturePayload, KEY_REGISTER_CONTEXT, KEY_LOGIN_CONTEXT } from '../src/keys';

const BASE = process.env.BASE ?? 'http://localhost:8789';
const TENANT = 'localhost';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
    if (cond) console.log(`  ✓ ${name}`);
    else {
        failures++;
        console.error(`  ✗ ${name}`, extra ?? '');
    }
}

function sessionFrom(res: Response): string | null {
    const setCookie = res.headers.get('set-cookie') ?? '';
    const m = setCookie.match(/session_id=([^;]+)/);
    return m ? m[1] : null;
}

async function getChallenge(path: string, bearer?: string): Promise<string> {
    const res = await fetch(`${BASE}${path}`, {
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : {},
    });
    const data = (await res.json()) as any;
    if (!data.challenge) throw new Error(`no challenge from ${path}: ${JSON.stringify(data)}`);
    return data.challenge;
}

async function registerKey(priv: Uint8Array, kind: 'softkey' | 'devicekey', label: string, bearer?: string) {
    const challenge = await getChallenge('/v1/key/register/options', bearer);
    const payload = keySignaturePayload(KEY_REGISTER_CONTEXT, challenge, TENANT);
    const res = await fetch(`${BASE}/v1/key/register/verify`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
        },
        body: JSON.stringify({
            challenge,
            public_key: b64u(publicKeyFor(priv)),
            signature: b64u(signPayload(priv, payload)),
            kind,
            label,
        }),
    });
    return { status: res.status, body: (await res.json()) as any, session: sessionFrom(res) };
}

async function loginKey(priv: Uint8Array) {
    const challenge = await getChallenge('/v1/key/login/options');
    const payload = keySignaturePayload(KEY_LOGIN_CONTEXT, challenge, TENANT);
    const body = {
        challenge,
        public_key: b64u(publicKeyFor(priv)),
        signature: b64u(signPayload(priv, payload)),
    };
    const res = await fetch(`${BASE}/v1/key/login/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as any, session: sessionFrom(res), replay: body };
}

async function api(path: string, bearer: string, init: RequestInit = {}) {
    const res = await fetch(`${BASE}${path}`, {
        ...init,
        headers: { ...(init.headers as any), Authorization: `Bearer ${bearer}` },
    });
    return { status: res.status, body: (await res.json()) as any };
}

// --- the run ---

console.log('1. account-key signup (no passkey path)');
const entropy = crypto.getRandomValues(new Uint8Array(16));
const compact = encodeCompact(entropy);
check('compact round-trips', b64u(decodeCompact(compact)) === b64u(entropy));
const accountPriv = derivePrivateKey(entropy, TENANT);
const reg = await registerKey(accountPriv, 'softkey', 'account key');
check('register verified', reg.status === 200 && reg.body.verified === true, reg.body);
check('session cookie minted', !!reg.session);
const userId = reg.body.user.id;
const sessionA = reg.session!;

console.log('2. whoami reports amr=key');
const who = await api('/v1/whoami', sessionA);
check('user matches', who.body.user_id === userId, who.body);
check('amr is key', who.body.amr === 'key', who.body);

console.log('3. attach device key while authenticated');
const devicePriv = (p256.utils as any).randomSecretKey?.() ?? (p256.utils as any).randomPrivateKey();
const dev = await registerKey(devicePriv, 'devicekey', 'e2e laptop', sessionA);
check('attached to SAME user', dev.status === 200 && dev.body.user.id === userId, dev.body);

console.log('4. credential list shows both');
const creds = await api('/v1/credentials', sessionA);
check('two credentials', creds.body.credentials?.length === 2, creds.body);
const softkeyCred = creds.body.credentials.find((c: any) => c.kind === 'softkey');
const deviceCred = creds.body.credentials.find((c: any) => c.kind === 'devicekey');
check('kinds present', !!softkeyCred && !!deviceCred);
check('display falls back to the label', softkeyCred.display === softkeyCred.label && !!softkeyCred.label, softkeyCred);
check('keys have no provider', softkeyCred.provider === null && deviceCred.provider === null, creds.body);
check('current marks the credential that minted this session', softkeyCred.current === true && deviceCred.current === false, creds.body);
check('verify returned the row id', dev.body.credential?.id === deviceCred.id, dev.body);

console.log('5. rank rule: key-session cannot delete the stronger device key');
const denied = await api(`/v1/credentials/${deviceCred.id}`, sessionA, { method: 'DELETE' });
check('403 on stronger credential', denied.status === 403, denied.body);

console.log('6. silent device login (amr=device)');
const devLogin = await loginKey(devicePriv);
check('device login ok', devLogin.status === 200 && devLogin.body.verified === true, devLogin.body);
const sessionB = devLogin.session!;
const whoB = await api('/v1/whoami', sessionB);
check('amr is device', whoB.body.amr === 'device', whoB.body);

console.log('7. challenge replay rejected');
const replayRes = await fetch(`${BASE}/v1/key/login/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(devLogin.replay),
});
check('replay 400', replayRes.status === 400, await replayRes.json());

console.log('8. wrong-tenant derivation cannot log in');
const wrongPriv = derivePrivateKey(entropy, 'wrong.example');
const wrongLogin = await loginKey(wrongPriv);
check('unknown credential 400', wrongLogin.status === 400, wrongLogin.body);

console.log('9. device-session (rank 2) may delete the account key (rank 1)');
const delSoft = await api(`/v1/credentials/${softkeyCred.id}`, sessionB, { method: 'DELETE' });
check('deleted', delSoft.status === 200, delSoft.body);

console.log('10. last-credential guard');
const delLast = await api(`/v1/credentials/${deviceCred.id}`, sessionB, { method: 'DELETE' });
check('409 on last credential', delLast.status === 409, delLast.body);

console.log('11. recovery re-enrollment: new account key attached, then logs in');
const entropy2 = crypto.getRandomValues(new Uint8Array(16));
const priv2 = derivePrivateKey(entropy2, TENANT);
const reg2 = await registerKey(priv2, 'softkey', 'recovery', sessionB);
check('attached to same user', reg2.status === 200 && reg2.body.user.id === userId, reg2.body);
const recLogin = await loginKey(priv2);
check('recovery login ok', recLogin.status === 200 && recLogin.body.user.id === userId, recLogin.body);

console.log('12. bring-your-own external phrase: claim then recover');
// A standard 12-word BIP39 phrase minted OUTSIDE this system. We round-trip
// through the words encoding to prove the import path (decodeWords validates
// the BIP39 checksum); unique per run so it re-claims cleanly.
const externalWords = encodeWords(crypto.getRandomValues(new Uint8Array(16))).join(' ');
const importedEntropy = decodeWords(externalWords.split(' '));
const importedPriv = derivePrivateKey(importedEntropy, TENANT);
const claim = await registerKey(importedPriv, 'softkey', 'imported key');
check('claim creates a fresh account', claim.status === 200 && claim.body.verified === true, claim.body);
const importedUser = claim.body.user.id;
// Claiming again = "already registered", so the client would recover via login.
const claimAgain = await registerKey(importedPriv, 'softkey', 'imported key');
check('re-claim returns 409', claimAgain.status === 409, claimAgain.body);
const recover = await loginKey(importedPriv);
check('recover logs into the SAME account', recover.status === 200 && recover.body.user.id === importedUser, recover.body);

console.log('13. legacy bare-string session still parses (amr=webauthn)');
const legacy = await api('/v1/whoami', 'sess1');
check('legacy user resolves', legacy.body.user_id === 'test-user-1', legacy.body);
check('legacy amr defaults to webauthn', legacy.body.amr === 'webauthn', legacy.body);

console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
