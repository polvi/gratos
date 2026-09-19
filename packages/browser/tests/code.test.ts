import { afterEach, describe, expect, test } from 'bun:test';
import { startCodeLogin, verifyCode } from '../src/code';

const realFetch = globalThis.fetch;
afterEach(() => {
    globalThis.fetch = realFetch;
});

describe('code sign-in', () => {
    test('the verifier stays in the browser and is sent only to verify', async () => {
        const bodies: Record<string, any> = {};
        globalThis.fetch = (async (input: any, init?: RequestInit) => {
            const url = String(input);
            if (url.endsWith('/v1/code/start')) return Response.json({ ticket: 'T', verifier: 'V', expires_at: 0 });
            bodies[url] = JSON.parse(String(init?.body));
            return Response.json({ verified: true, user: { id: 'u1' }, last_used: 'login.otp' });
        }) as any;

        expect(await startCodeLogin('https://a.example')).toBe('T');
        const r = await verifyCode('https://a.example', '123456');
        expect(r).toMatchObject({ verified: true, user: { id: 'u1' } });
        expect(bodies['https://a.example/v1/code/verify']).toEqual({ ticket: 'T', verifier: 'V', code: '123456' });
        // Cleared on success.
        expect(await verifyCode('https://a.example', '123456')).toMatchObject({ verified: false });
    });

    test('a wrong code keeps the ticket for another try', async () => {
        let calls = 0;
        globalThis.fetch = (async (input: any) => {
            if (String(input).endsWith('/start')) return Response.json({ ticket: 'T2', verifier: 'V2' });
            calls++;
            return calls === 1
                ? Response.json({ verified: false, error: 'Invalid or expired code' }, { status: 400 })
                : Response.json({ verified: true, user: { id: 'u1' } });
        }) as any;
        await startCodeLogin('https://b.example');
        expect(await verifyCode('https://b.example', '000000')).toEqual({ verified: false, error: 'Invalid or expired code' });
        expect(await verifyCode('https://b.example', '111111')).toMatchObject({ verified: true });
    });
});
