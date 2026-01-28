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
    OIDC_CLIENT_ID?: string;
    OIDC_REDIRECT_URI?: string;
    LOGIN_URL?: string;
};

type Variables = {
    userId: string;
}

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.use('/*', (c, next) => {
    const origins = (c.env.CORS_ALLOW_ORIGIN || 'http://localhost:4321,http://localhost:5173').split(',');
    return cors({
        origin: origins,
        allowHeaders: ['Content-Type'],
        allowMethods: ['POST', 'GET', 'OPTIONS', 'DELETE', 'PUT'],
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



function isValidCookieDomain(origin: string, cookieDomain: string): boolean {
    let hostname = origin;
    try {
        const url = new URL(origin);
        hostname = url.hostname;
    } catch (e) {
        // Fallback if not a valid URL (backward compatibility for plain domains)
        hostname = origin;
    }

    const cleanCookieDomain = cookieDomain.startsWith('.') ? cookieDomain.slice(1) : cookieDomain;
    
    // Validate it's not a TLD (must have at least one dot, unless it's localhost)
    if (cleanCookieDomain !== 'localhost' && !cleanCookieDomain.includes('.')) {
        return false;
    }

    if (hostname === cookieDomain) return true;
    if (hostname.endsWith('.' + cookieDomain)) return true;
    // Also handle leading dot in cookieDomain if user provided it
    if (cookieDomain.startsWith('.') && hostname.endsWith(cookieDomain)) return true;
    
    return false;
}

app.get('/', (c) => c.text('Gratos Worker Running'));

// --- Middleware ---

const authMiddleware = async (c: any, next: any) => {
    const sessionId = getCookie(c, 'session_id');
    if (!sessionId) {
        return c.json({ error: 'Not authenticated' }, 401);
    }

    const userId = await c.env.KV.get(`session:${sessionId}`);
    if (!userId) {
        return c.json({ error: 'Session expired' }, 401);
    }

    c.set('userId', userId);
    await next();
};

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

async function saveClient(db: D1Database, userId: string, origin: string, domainSetting: string) {
    const id = crypto.randomUUID();
    const createdAt = Date.now();

    await db.prepare(`
    INSERT INTO clients (id, user_id, origin, domain_setting, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(
        id,
        userId,
        origin,
        domainSetting,
        createdAt
    ).run();

    return { id, origin, domain_setting: domainSetting, created_at: createdAt };
}



async function getClients(db: D1Database, userId: string) {
    const { results } = await db.prepare('SELECT * FROM clients WHERE user_id = ? ORDER BY created_at DESC').bind(userId).all();
    return results || [];
}

async function getClient(db: D1Database, id: string) {
    return await db.prepare('SELECT * FROM clients WHERE id = ?').bind(id).first();
}


async function updateClient(db: D1Database, userId: string, clientId: string, origin: string, domainSetting: string) {
    await db.prepare(`
    UPDATE clients SET origin = ?, domain_setting = ? WHERE id = ? AND user_id = ?
  `).bind(origin, domainSetting, clientId, userId).run();
    return { id: clientId, origin, domainSetting };
}

async function deleteClient(db: D1Database, userId: string, clientId: string) {
    await db.prepare('DELETE FROM clients WHERE id = ? AND user_id = ?').bind(clientId, userId).run();
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

        // Handle Redirect / Client ID Flow
        const { clientId, returnTo } = await c.req.json();
        if (clientId) {
            const client = await getClient(c.env.DB, clientId) as any;
            if (client && client.origin) {
                // Generate Code
                const code = crypto.randomUUID();
                await c.env.KV.put(`oidc_code:${code}`, JSON.stringify({
                    userId: (user as any).id,
                    clientId,
                    createdAt: Date.now()
                    // Add other OIDC fields if needed
                }), { expirationTtl: 600 });

                // Construct Redirect URL
                let origin = client.origin;
                if (!origin.startsWith('http')) {
                    origin = `https://${origin}`;
                }
                
                // Remove trailing slash if present to avoid double slash
                if (origin.endsWith('/')) {
                    origin = origin.slice(0, -1);
                }
                
                const redirectUrl = `${origin}/session/complete?code=${code}&redirect_to=${encodeURIComponent(returnTo || '/')}`;
                return c.json({ verified: true, user, redirectUrl });
            }
        }

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

// --- Clients API ---

app.use('/clients/*', authMiddleware);

app.post('/clients', async (c) => {
    const userId = c.get('userId');

    // 2. Parse Body and Validate
    const body = await c.req.json();
    let { origin, domain, domain_setting } = body;

    // Backward compatibility: map domain to origin if origin is missing
    if (!origin && domain) {
        origin = domain;
    }

    if (!origin || typeof origin !== 'string') {
        return c.json({ error: 'Invalid or missing "origin"' }, 400);
    }
    if (!domain_setting || typeof domain_setting !== 'string') {
        return c.json({ error: 'Invalid or missing "domain_setting"' }, 400);
    }



    if (!isValidCookieDomain(origin, domain_setting)) {
        return c.json({ error: 'Invalid cookie domain. Must be the same as or a parent of the domain.' }, 400);
    }

    // 3. Create Client
    try {
        const client = await saveClient(c.env.DB, userId, origin, domain_setting);
        return c.json(client);
    } catch (e) {
        console.error('Failed to create client', e);
        return c.json({ error: 'Failed to create client' }, 500);
    }
});

app.get('/clients', async (c) => {
    const userId = c.get('userId');
    const clients = await getClients(c.env.DB, userId);
    return c.json({ clients });
});

app.put('/clients/:id', async (c) => {
    const userId = c.get('userId');
    const clientId = c.req.param('id');
    const body = await c.req.json();
    let { origin, domain, domain_setting } = body;

    if (!origin && domain) {
        origin = domain;
    }

    if (!origin || typeof origin !== 'string') return c.json({ error: 'Invalid origin' }, 400);
    if (!domain_setting || typeof domain_setting !== 'string') return c.json({ error: 'Invalid domain_setting' }, 400);

    if (!isValidCookieDomain(origin, domain_setting)) {
        return c.json({ error: 'Invalid cookie domain. Must be the same as or a parent of the domain.' }, 400);
    }

    try {
        const client = await updateClient(c.env.DB, userId, clientId, origin, domain_setting);
        return c.json(client);
    } catch (e) {
        return c.json({ error: 'Failed to update client' }, 500);
    }
});

app.delete('/clients/:id', async (c) => {
    const userId = c.get('userId');
    const clientId = c.req.param('id');
    await deleteClient(c.env.DB, userId, clientId);
    return c.json({ success: true });
});

// --- OIDC ---

import {
    generateDiscoveryDocument,
    generateJWKS,
    handleAuthorize,
    handleToken
} from './oidc';
import { loginPage, promptPage } from './auth-pages';





app.get('/oidc/.well-known/openid-configuration', async (c) => {
    return c.json(await generateDiscoveryDocument(c));
});

app.get('/oidc/jwks', async (c) => {
    return c.json(await generateJWKS(c));
});


app.get('/login', (c) => {
    const returnTo = c.req.query('return_to');
    const clientId = c.req.query('client_id');
    return c.html(loginPage(returnTo || '/', clientId || null));
});

app.get('/login/prompt', (c) => {
    const returnTo = c.req.query('return_to');
    const clientId = c.req.query('client_id');
    return c.html(promptPage(returnTo || '/', clientId || null));
});



app.get('/session/complete', async (c) => {
    const url = new URL(c.req.url);
    const code = url.searchParams.get('code');
    const { SESSION_TTL, COOKIE_DOMAIN } = getConfig(c);

    if (!code) {
        return c.text(`Missing code. URL: ${c.req.url}. Params: ${[...url.searchParams.keys()].join(',')}`, 400);
    }



    // Retrieve code data
    // Note: We use the shared KV, so this works across domains if they share the KV binding.
    const storedData = await c.env.KV.get(`oidc_code:${code}`, 'json');
    if (!storedData) {
        return c.text('Invalid or expired code', 400);
    }

    // Cleanup code
    await c.env.KV.delete(`oidc_code:${code}`);

    const { userId, clientId } = storedData as any;

    if (!userId) return c.text('Invalid code data', 400);

    // Create session for THIS domain
    const sessionId = crypto.randomUUID();
    await c.env.KV.put(`session:${sessionId}`, userId, { expirationTtl: SESSION_TTL });

    // Determine Cookie Domain from Client Config if available
    let cookieDomain = COOKIE_DOMAIN;
    if (clientId) {
        const client = await getClient(c.env.DB, clientId);
        if (client && client.domain_setting) {
            cookieDomain = client.domain_setting;
        }
    }

    setCookie(c, 'session_id', sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        path: '/',
        maxAge: SESSION_TTL,
        domain: cookieDomain,
    });

    const redirectTo = c.req.query('redirect_to');
    return c.redirect(redirectTo || '/');
});




app.get('/oidc/authorize', handleAuthorize);
app.post('/oidc/token', handleToken);

export default app;

