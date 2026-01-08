import { Hono } from 'hono';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
    GenerateRegistrationOptionsOpts,
    VerifyRegistrationResponseOpts,
    GenerateAuthenticationOptionsOpts,
    VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';

type Env = {
    DB: D1Database;
    KV: KVNamespace;
};

const app = new Hono<{ Bindings: Env }>();

const RP_NAME = 'Gratos Auth';
// In a real app, this should be your production domain
const RP_ID = 'localhost';
const ORIGIN = `http://${RP_ID}:5173`;

app.get('/', (c) => c.text('Gratos Worker Running'));

// --- Registration ---

app.get('/register/options', async (c) => {
    const username = c.req.query('username');
    if (!username) return c.json({ error: 'Username required' }, 400);

    // Check if user exists, if not create a stub or handle appropriately
    // For simplicity, we'll assume a new user or fetch existing user ID from DB
    // Here we just generate a random ID for the session/flow
    const userId = crypto.randomUUID();

    // Retrieve user's existing credentials to prevent re-registration
    // const userCredentials = await getUserCredentials(c.env.DB, userId);

    const opts: GenerateRegistrationOptionsOpts = {
        rpName: RP_NAME,
        rpID: RP_ID,
        userID: userId,
        userName: username,
        // excludeCredentials: userCredentials.map((cred) => ({
        //   id: cred.credentialID,
        //   type: 'public-key',
        //   transports: cred.transports,
        // })),
        authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'preferred',
            authenticatorAttachment: 'platform',
        },
    };

    const options = await generateRegistrationOptions(opts);

    // Store checks in KV for verification
    await c.env.KV.put(`reg_challenge:${userId}`, options.challenge, { expirationTtl: 60 * 5 }); // 5 minutes

    return c.json(options);
});

app.post('/register/verify', async (c) => {
    const { username, response } = await c.req.json();
    // In a real flow, you'd pass the userId or session ID to link the challenge
    // For this simplified example, we'd need a consistent way to track the user across requests
    // For now, let's assume the client passes back the user ID (not secure for real apps, but good for demo)
    // OR we use a session cookie.

    // TODO: persistent session management

    // Mock verification for now as we need to set up the DB helpers
    return c.json({ verified: true });
});

// --- Authentication ---

app.get('/login/options', async (c) => {
    const opts: GenerateAuthenticationOptionsOpts = {
        rpID: RP_ID,
        userVerification: 'preferred',
    };

    const options = await generateAuthenticationOptions(opts);

    // Store challenge
    const challengeId = crypto.randomUUID();
    await c.env.KV.put(`auth_challenge:${challengeId}`, options.challenge, { expirationTtl: 60 * 5 });

    return c.json({ ...options, challengeId });
});


export default app;
