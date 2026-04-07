// @ts-ignore
import { Buffer } from 'node:buffer';
import { Hono } from 'hono';
import { setCookie } from 'hono/cookie';
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

import type { Env, Variables } from './index';
import type { TenantInfo } from './tenant';
import { getUser, createUser, saveCredential, getCredentialById } from './db';

const SESSION_TTL = 604800; // 7 days
const CHALLENGE_TTL = 300; // 5 minutes

/**
 * Get the allowed origin for WebAuthn verification.
 * The browser's WebAuthn response contains the *page's* origin (e.g. the dash),
 * not the API server's origin. We use the request's Origin header and validate
 * it belongs to the tenant's domain.
 */
function getExpectedOrigin(c: any, tenantInfo: TenantInfo): string {
    const requestOrigin = c.req.header('Origin');
    if (requestOrigin) {
        try {
            const host = new URL(requestOrigin).hostname;
            if (
                tenantInfo.tenant === 'localhost' ||
                host === tenantInfo.tenant ||
                host.endsWith('.' + tenantInfo.tenant)
            ) {
                return requestOrigin;
            }
        } catch {
            // invalid origin header
        }
    }
    // Fallback to worker's own origin
    return tenantInfo.origin;
}

export function authRoutes(tenantInfo: TenantInfo) {
    const app = new Hono<{ Bindings: Env; Variables: Variables }>();

    // --- Registration ---

    app.get('/register/options', async (c) => {
        const userId = crypto.randomUUID();

        const opts: GenerateRegistrationOptionsOpts = {
            rpName: tenantInfo.tenant,
            rpID: tenantInfo.rpId,
            userID: isoUint8Array.fromUTF8String(userId),
            userName: 'Anonymous User',
            excludeCredentials: [],
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred',
                authenticatorAttachment: 'platform',
            },
        };

        const options = await generateRegistrationOptions(opts);

        await c.env.KV.put(
            `reg_challenge:${tenantInfo.tenant}:${userId}`,
            options.challenge,
            { expirationTtl: CHALLENGE_TTL }
        );

        return c.json({ ...options, userId });
    });

    app.post('/register/verify', async (c) => {
        const body = await c.req.json();
        const { response, userId } = body;

        if (!userId) return c.json({ error: 'User ID required' }, 400);

        const storedChallenge = await c.env.KV.get(
            `reg_challenge:${tenantInfo.tenant}:${userId}`
        );
        if (!storedChallenge) {
            return c.json({ error: 'Challenge not found or expired' }, 400);
        }

        const expectedOrigin = getExpectedOrigin(c, tenantInfo);
        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: storedChallenge,
            expectedOrigin,
            expectedRPID: tenantInfo.rpId,
        });

        if (verification.verified && verification.registrationInfo) {
            let user = await getUser(c.env.DB, tenantInfo.tenant, userId);
            if (!user) {
                await createUser(c.env.DB, tenantInfo.tenant, userId);
                user = { id: userId };
            }

            await saveCredential(c.env.DB, tenantInfo.tenant, userId, verification, response.id);

            // Create session
            const sessionId = crypto.randomUUID();
            await c.env.KV.put(
                `session:${tenantInfo.tenant}:${sessionId}`,
                userId,
                { expirationTtl: SESSION_TTL }
            );

            setCookie(c, 'session_id', sessionId, {
                httpOnly: true,
                secure: true,
                sameSite: 'None',
                path: '/',
                maxAge: SESSION_TTL,
                domain: tenantInfo.cookieDomain,
            });

            // Cleanup
            await c.env.KV.delete(`reg_challenge:${tenantInfo.tenant}:${userId}`);

            return c.json({ verified: true, user: { id: userId } });
        }

        return c.json({ verified: false, error: 'Verification failed' }, 400);
    });

    // --- Authentication ---

    app.get('/login/options', async (c) => {
        const opts: GenerateAuthenticationOptionsOpts = {
            rpID: tenantInfo.rpId,
            userVerification: 'preferred',
        };

        const options = await generateAuthenticationOptions(opts);

        const challengeId = crypto.randomUUID();
        await c.env.KV.put(
            `auth_challenge:${tenantInfo.tenant}:${challengeId}`,
            options.challenge,
            { expirationTtl: CHALLENGE_TTL }
        );

        return c.json({ ...options, challengeId });
    });

    app.post('/login/verify', async (c) => {
        const { response, challengeId } = await c.req.json();

        const expectedChallenge = await c.env.KV.get(
            `auth_challenge:${tenantInfo.tenant}:${challengeId}`
        );
        if (!expectedChallenge) {
            return c.json({ error: 'Challenge expired or invalid' }, 400);
        }

        const credentialId = response.id;
        const credential = await getCredentialById(c.env.DB, tenantInfo.tenant, credentialId) as any;

        if (!credential) {
            return c.json({ error: 'Credential not found' }, 400);
        }

        const credentialObj = {
            id: credentialId,
            publicKey: new Uint8Array(Buffer.from(credential.public_key, 'base64')),
            counter: 0,
        };

        const expectedOrigin = getExpectedOrigin(c, tenantInfo);
        const verification = await verifyAuthenticationResponse({
            response,
            expectedChallenge,
            expectedOrigin,
            expectedRPID: tenantInfo.rpId,
            credential: credentialObj,
        });

        if (verification.verified) {
            const user = await getUser(c.env.DB, tenantInfo.tenant, credential.user_id);

            // Cleanup
            await c.env.KV.delete(`auth_challenge:${tenantInfo.tenant}:${challengeId}`);

            // Create session
            const sessionId = crypto.randomUUID();
            if (user) {
                await c.env.KV.put(
                    `session:${tenantInfo.tenant}:${sessionId}`,
                    (user as any).id,
                    { expirationTtl: SESSION_TTL }
                );
            }

            setCookie(c, 'session_id', sessionId, {
                httpOnly: true,
                secure: true,
                sameSite: 'None',
                path: '/',
                maxAge: SESSION_TTL,
                domain: tenantInfo.cookieDomain,
            });

            return c.json({ verified: true, user });
        }

        return c.json({ verified: false }, 400);
    });

    return app;
}
