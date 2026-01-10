import { Hono } from 'hono';
// @ts-ignore
import { Buffer } from 'node:buffer';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
    GenerateRegistrationOptionsOpts,
    GenerateAuthenticationOptionsOpts,
} from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';

import { cors } from 'hono/cors';
import { setCookie, getCookie, deleteCookie } from 'hono/cookie';

type Env = {
    DB: D1Database;
    KV: KVNamespace;
    RP_NAME?: string;
    RP_ID?: string;
    ORIGIN?: string;
    CORS_ALLOW_ORIGIN?: string;
    SESSION_TTL?: string;
    CHALLENGE_TTL?: string;
    COOKIE_DOMAIN?: string;
};

const app = new Hono<{ Bindings: Env }>();

app.use('/*', (c, next) => {
    const origins = (c.env.CORS_ALLOW_ORIGIN || 'http://localhost:4321,http://localhost:5173').split(',');
    return cors({
        origin: origins,
        allowHeaders: ['Content-Type'],
        allowMethods: ['POST', 'GET', 'OPTIONS'],
        exposeHeaders: ['Content-Length'],
        maxAge: 600,
        credentials: true,
    })(c, next);
});

// Helper to get config values
function getConfig(c: any) {
    const url = new URL(c.req.url);
    const RP_ID = c.env.RP_ID || url.hostname;
    const ORIGIN = c.env.ORIGIN || url.origin;
    const RP_NAME = c.env.RP_NAME || 'Gratos Auth';
    const SESSION_TTL = parseInt(c.env.SESSION_TTL || '604800', 10); // Default 7 days
    const CHALLENGE_TTL = parseInt(c.env.CHALLENGE_TTL || '300', 10); // Default 5 mins
    const COOKIE_DOMAIN = c.env.COOKIE_DOMAIN; // Optional

    return { RP_ID, ORIGIN, RP_NAME, SESSION_TTL, CHALLENGE_TTL, COOKIE_DOMAIN };
}

app.get('/', (c) => c.text('Gratos Worker Running'));

// --- Helpers ---

async function getUser(db: D1Database, id: string) {
    return await db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
}

async function getUserCredentials(db: D1Database, userId: string): Promise<any[]> {
    const { results } = await db.prepare('SELECT * FROM public_keys WHERE user_id = ?').bind(userId).all();
    return results || [];
}

async function saveCredential(db: D1Database, userId: string, verification: any, clientCredentialID: string) {
    const { registrationInfo } = verification;
    const { credentialBackedUp, credential } = registrationInfo;
    const credentialPublicKey = credential.publicKey;

    const id = crypto.randomUUID();

    // Use the ID from the client response, which we know is a string
    const storedCredentialID = clientCredentialID;

    await db.prepare(`
    INSERT INTO public_keys (id, user_id, credential_id, public_key, user_backed_up, transports)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
        id,
        userId,
        storedCredentialID,
        Buffer.from(credentialPublicKey).toString('base64'),
        credentialBackedUp ? 1 : 0,
        ''
    ).run();
}

// --- Registration ---

app.get('/register/options', async (c) => {
    const { RP_ID, RP_NAME, CHALLENGE_TTL } = getConfig(c);

    // We do NOT take a username from the client to avoid PII leaking to server.
    // The client will overwrite the user.name/displayName locally before calling the authenticator.
    const userId = crypto.randomUUID();

    const excludeCredentials: any[] = [];
    // Cannot check for existing credentials by username since we don't store it

    const opts: GenerateRegistrationOptionsOpts = {
        rpName: RP_NAME,
        rpID: RP_ID,
        userID: isoUint8Array.fromUTF8String(userId),
        userName: 'Anonymous User', // Placeholder
        excludeCredentials,
        authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'preferred',
            authenticatorAttachment: 'platform',
        },
    };

    const options = await generateRegistrationOptions(opts);

    // Key by userId for the verify step
    await c.env.KV.put(`reg_challenge:${userId}`, options.challenge, { expirationTtl: CHALLENGE_TTL });

    // We return the generated userId so the client can pass it back
    return c.json({ ...options, userId });
});

app.post('/register/verify', async (c) => {
    const config = getConfig(c);

    const body = await c.req.json();
    const { response, userId } = body;

    if (!userId) return c.json({ error: 'User ID required' }, 400);

    const storedChallenge = await c.env.KV.get(`reg_challenge:${userId}`);

    if (!storedChallenge) {
        return c.json({ error: 'Challenge not found or expired' }, 400);
    }

    const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: storedChallenge,
        expectedOrigin: config.ORIGIN,
        expectedRPID: config.RP_ID,
    });

    if (verification.verified && verification.registrationInfo) {
        let user = await getUser(c.env.DB, userId);
        if (!user) {
            // No username stored
            await c.env.DB.prepare('INSERT INTO users (id) VALUES (?)').bind(userId).run();
            user = { id: userId };
        }

        await saveCredential(c.env.DB, userId, verification, response.id);

        // Create Session
        const sessionId = crypto.randomUUID();

        await c.env.KV.put(`session:${sessionId}`, userId, { expirationTtl: config.SESSION_TTL });

        setCookie(c, 'session_id', sessionId, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            path: '/',
            maxAge: config.SESSION_TTL,
            domain: config.COOKIE_DOMAIN,
        });

        // cleanup
        await c.env.KV.delete(`reg_challenge:${userId}`);

        return c.json({ verified: true, user });
    }

    return c.json({ verified: false, error: 'Verification failed' }, 400);
});

// --- Authentication ---

app.get('/login/options', async (c) => {
    const { RP_ID, CHALLENGE_TTL } = getConfig(c);
    const opts: GenerateAuthenticationOptionsOpts = {
        rpID: RP_ID,
        userVerification: 'preferred',
    };

    const options = await generateAuthenticationOptions(opts);

    const challengeId = crypto.randomUUID();
    await c.env.KV.put(`auth_challenge:${challengeId}`, options.challenge, { expirationTtl: CHALLENGE_TTL });

    return c.json({ ...options, challengeId });
});

app.post('/login/verify', async (c) => {
    const { RP_ID, ORIGIN, SESSION_TTL, COOKIE_DOMAIN } = getConfig(c);
    const { response, challengeId } = await c.req.json();

    const expectedChallenge = await c.env.KV.get(`auth_challenge:${challengeId}`);
    if (!expectedChallenge) {
        return c.json({ error: 'Challenge expired or invalid' }, 400);
    }

    const credentialId = response.id;
    const credential = await c.env.DB.prepare('SELECT * FROM public_keys WHERE credential_id = ?').bind(credentialId).first() as any;

    if (!credential) {
        // Dump all credentials to help debug
        const allCreds = await c.env.DB.prepare('SELECT credential_id FROM public_keys').all();
        return c.json({ error: 'Credential not found' }, 400);
    }

    // Verify
    const credentialObj = {
        id: credentialId,
        publicKey: new Uint8Array(Buffer.from(credential.public_key, 'base64')),
        counter: 0,
    };

    const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        credential: credentialObj,
    });

    if (verification.verified) {
        const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(credential.user_id).first();
        // cleanup
        await c.env.KV.delete(`auth_challenge:${challengeId}`);

        // Create Session
        const sessionId = crypto.randomUUID();

        if (user) {
            await c.env.KV.put(`session:${sessionId}`, (user as any).id, { expirationTtl: SESSION_TTL });
        }

        setCookie(c, 'session_id', sessionId, {
            httpOnly: true,
            secure: true,
            sameSite: 'None', // Needed for cross-origin if frontend is separate during dev
            path: '/',
            maxAge: SESSION_TTL,
            domain: COOKIE_DOMAIN,
        });

        return c.json({ verified: true, user });
    }

    return c.json({ verified: false }, 400);
});

app.get('/whoami', async (c) => {
    const sessionId = getCookie(c, 'session_id');
    if (!sessionId) {
        return c.json({ error: 'Not authenticated' }, 401);
    }

    const userId = await c.env.KV.get(`session:${sessionId}`);
    if (!userId) {
        return c.json({ error: 'Session expired' }, 401);
    }

    const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
    if (!user) {
        return c.json({ error: 'User not found' }, 404);
    }

    return c.json({ user });
});

app.post('/logout', async (c) => {
    const { COOKIE_DOMAIN } = getConfig(c);
    const sessionId = getCookie(c, 'session_id');
    if (sessionId) {
        await c.env.KV.delete(`session:${sessionId}`);
        deleteCookie(c, 'session_id', {
            path: '/',
            domain: COOKIE_DOMAIN,
        });
    }
    return c.json({ success: true });
});


export default app;
