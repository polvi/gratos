import { Context } from 'hono';
import { generateKeyPair, exportJWK, SignJWT, importJWK, JWK } from 'jose';

// Define Env interface locally to match index.ts or import if possible.
// For now, redefining subset needed.
type Env = {
    KV: KVNamespace;
    RP_ID?: string;
    OIDC_CLIENT_ID?: string;
    OIDC_CLIENT_SECRET?: string;
    OIDC_REDIRECT_URI?: string;
};

// Helper: Get or Generate Signing Key Pair (RS256)
async function getOrGenerateKeyPair(env: Env) {
    let privateKeyJwk = await env.KV.get('oidc:private_key', 'json');
    let publicKeyJwk = await env.KV.get('oidc:public_key', 'json');

    if (!privateKeyJwk || !publicKeyJwk) {
        try {
            const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
            privateKeyJwk = await exportJWK(privateKey);
            publicKeyJwk = await exportJWK(publicKey);
            await env.KV.put('oidc:private_key', JSON.stringify(privateKeyJwk));
            await env.KV.put('oidc:public_key', JSON.stringify(publicKeyJwk));
        } catch (e: any) {
            console.error('Error in key generation:', e);
            throw e;
        }
    }

    try {
        const privateKey = await importJWK(privateKeyJwk as any, 'RS256');
        return { privateKey, publicKeyJwk: publicKeyJwk as JWK };
    } catch (e: any) {
        console.error('Error in key import:', e);
        throw e;
    }
}

export async function generateDiscoveryDocument(c: Context) {
    const url = new URL(c.req.url);
    const origin = url.origin;
    const issuer = `${origin}/oidc`;

    return {
        issuer: issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        scopes_supported: ['openid'],
        claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat'],
        token_endpoint_auth_methods_supported: ['none'],
    };
}

export async function generateJWKS(c: Context) {
    const { publicKeyJwk } = await getOrGenerateKeyPair(c.env);
    // Ensure kid is present or add one if static
    if (!publicKeyJwk.kid) {
        publicKeyJwk.kid = 'default-kid';
        publicKeyJwk.use = 'sig';
        publicKeyJwk.alg = 'RS256';
    }

    return {
        keys: [publicKeyJwk],
    };
}

export async function handleAuthorize(c: Context) {
    // 1. Validate parameters
    const query = c.req.query();
    const { response_type, client_id, redirect_uri, state, nonce } = query;

    if (response_type !== 'code') {
        return c.text('Unsupported response_type', 400);
    }

    // Check Client ID
    const envClientId = c.env.OIDC_CLIENT_ID;
    if (envClientId && client_id !== envClientId) {
        return c.text('Invalid client_id', 400);
    }

    // Check Redirect URI
    const envRedirectUri = c.env.OIDC_REDIRECT_URI;
    if (envRedirectUri && redirect_uri !== envRedirectUri) {
        return c.text('Invalid redirect_uri', 400);
    }

    // 2. Check Authentication (Session)
    // We assume the main app middleware or logic handles cookie parsing looks for 'session_id'
    // Re-using logic from index.ts would be ideal, but for now we look at cookie manualy
    // or assume we are called after some auth check.
    // However, the standard OIDC flow is: Redirect to /authorize -> Check Cookie -> If valid, redirect back with code.
    // If invalid, show login page.

    // Since this is an API worker, we can't easily show a "Login Page" unless we redirect to a frontend.
    // For the Kubernetes CLI usecase, the user usually logs in via browser.

    // Let's import getCookie from hono/cookie
    const { getCookie } = await import('hono/cookie');
    const sessionId = getCookie(c, 'session_id');

    if (!sessionId) {
        // Not authenticated. Redirect to login.
        const loginUrl = c.env.LOGIN_URL || 'http://localhost:4321/login';
        const returnTo = c.req.url; // Current URL (authorize endpoint with params)
        return c.redirect(`${loginUrl}?return_to=${encodeURIComponent(returnTo)}`);
    }

    const userId = await c.env.KV.get(`session:${sessionId}`);
    if (!userId) {
        // Session expired. Redirect to login.
        const loginUrl = c.env.LOGIN_URL || 'http://localhost:4321/login';
        const returnTo = c.req.url;
        return c.redirect(`${loginUrl}?return_to=${encodeURIComponent(returnTo)}`);
    }

    // 3. Generate Auth Code
    const code = crypto.randomUUID();
    // Store code with context (client_id, redirect_uri, nonce, userId)
    await c.env.KV.put(`oidc_code:${code}`, JSON.stringify({
        client_id,
        redirect_uri,
        nonce,
        userId,
        created_at: Date.now()
    }), { expirationTtl: 600 }); // 10 min

    // 4. Redirect with code
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (state) redirectUrl.searchParams.set('state', state);

    return c.redirect(redirectUrl.toString());
}

export async function handleToken(c: Context) {
    const body = await c.req.parseBody();
    let { grant_type, code, redirect_uri, client_id } = body;

    // Support Basic Auth (to extract client_id even if secret is ignored)
    const authHeader = c.req.header('Authorization');
    if (authHeader && authHeader.startsWith('Basic ')) {
        const base64Credentials = authHeader.split(' ')[1];
        try {
            // In browser/worker env, use atob
            const credentials = atob(base64Credentials).split(':');
            const basicClientId = credentials[0];
            // const basicClientSecret = credentials[1]; // Ignored

            if (!client_id) {
                client_id = basicClientId;
            } else if (client_id !== basicClientId) {
                return c.json({ error: 'invalid_request', error_description: 'Mismatching client_id' }, 400);
            }
        } catch (e) {
            // Ignore malformed header if we don't strictly require it?
            // But if sent, it should be valid.
            return c.json({ error: 'invalid_request', error_description: 'Invalid Basic Auth header' }, 400);
        }
    }

    if (grant_type !== 'authorization_code') {
        return c.json({ error: 'unsupported_grant_type' }, 400);
    }

    if (!code || typeof code !== 'string') {
        return c.json({ error: 'invalid_request' }, 400);
    }

    const storedData = await c.env.KV.get(`oidc_code:${code}`, 'json');
    if (!storedData) {
        return c.json({ error: 'invalid_grant1' }, 400);
    }

    // cleanup code (one time use)
    await c.env.KV.delete(`oidc_code:${code}`);

    const { client_id: storedClientId, redirect_uri: storedRedirectUri, nonce, userId } = storedData as any;

    const clientIdStr = typeof client_id === 'string' ? client_id : undefined;

    // Validate Client ID (Env Check + Stored Check)
    const envClientId = c.env.OIDC_CLIENT_ID;
    if (envClientId) {
        if (clientIdStr !== envClientId) {
            return c.json({ error: 'invalid_client' }, 401);
        }
        if (storedClientId !== envClientId) {
            return c.json({ error: 'invalid_client' }, 401);
        }
    } else {
        // Fallback or optional check if env not set
        if (clientIdStr && storedClientId && clientIdStr !== storedClientId) {
            return c.json({ error: 'invalid_client' }, 401);
        }
    }

    // Validate Client Secret logic REMOVED.

    // Validate Redirect URI (Env Check)
    const envRedirectUri = c.env.OIDC_REDIRECT_URI;
    if (envRedirectUri && storedRedirectUri !== envRedirectUri) {
        // This implies the code was issued for a different URI than what we expect globally?
        // Or just that we ensure the code was originally issued for the correct URI.
        // Actually, token endpoint checks that 'redirect_uri' param matches what was in auth request.
        // storedRedirectUri has what was in auth request.
        // We should ensure that matches our allowed env var.
        return c.json({ error: 'invalid_grant2' }, 400);
    }

    // Also check that the redirect_uri passed to token endpoint matches stored one
    // (Standard OIDC requirement)
    if (redirect_uri && redirect_uri !== storedRedirectUri) {
        return c.json({ error: 'invalid_grant3' }, 400);
    }

    // Forgetting strict redirect_uri check for now to be permissive, but ideally check it.

    // Generate ID Token
    const { privateKey, publicKeyJwk } = await getOrGenerateKeyPair(c.env);
    const origin = new URL(c.req.url).origin;
    const issuer = `${origin}/oidc`;

    const jwt = await new SignJWT({
        nonce: nonce
    })
        .setProtectedHeader({ alg: 'RS256', kid: publicKeyJwk.kid || 'default-kid' })
        .setIssuedAt()
        .setIssuer(issuer)
        .setAudience(clientIdStr || 'kubernetes')
        .setExpirationTime('1h')
        .setSubject(userId)
        .sign(privateKey);

    return c.json({
        access_token: 'dummy_access_token', // We don't really use access tokens for this simple K8s auth yet
        token_type: 'Bearer',
        id_token: jwt,
        expires_in: 3600
    });
}
