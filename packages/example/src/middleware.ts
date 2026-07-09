import { defineMiddleware } from 'astro:middleware';

// The whole auth story for this app: gate /app by forwarding the session cookie
// to /v1/whoami. If there's no valid session, bounce the user to AuthGravity's
// HOSTED /login surface with a return_to back here — no login UI in this app.
export const onRequest = defineMiddleware(async (context, next) => {
    if (context.url.pathname.startsWith('/app')) {
        const env = context.locals.runtime.env;
        const endpoint = env.PUBLIC_AUTH_ENDPOINT;
        const cookie = context.request.headers.get('cookie');
        const res = await fetch(`${endpoint}/v1/whoami`, { headers: cookie ? { cookie } : {} });
        if (!res.ok) {
            const returnTo = context.url.origin + context.url.pathname + context.url.search;
            return context.redirect(`${endpoint}/login?return_to=${encodeURIComponent(returnTo)}`);
        }
        const data = (await res.json()) as { user_id?: string };
        context.locals.userId = data.user_id;
    }
    return next();
});
