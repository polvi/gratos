import { defineMiddleware } from "astro:middleware";
import { env } from "cloudflare:workers";

export const onRequest = defineMiddleware(async (context, next) => {
    // Only intercept requests for the /domains path
    console.log(`[Middleware] in middleware`);
    const path = context.url.pathname;
    if (path.startsWith("/domains") || path.startsWith("/signup")) {
        console.log(`[Middleware] Intercepting request for: ${context.url.pathname}`);
        // Read the API URL from environment (Cloudflare runtime fallback to build-time)
        const apiBaseUrl = env.PUBLIC_GRATOS_SERVER || import.meta.env.PUBLIC_GRATOS_SERVER;
        console.log(`[Middleware] Using API Server: ${apiBaseUrl}`);
        
        // Grab the cookie header from the inbound request
        const cookieHeader = context.request.headers.get("cookie");
        console.log(`[Middleware] Cookie present: ${!!cookieHeader}`);

        try {
            // Forward the cookie to the Gratos check auth endpoint
            console.log(`[Middleware] Fetching session state from ${apiBaseUrl}/whoami...`);
            const res = await fetch(`${apiBaseUrl}/whoami`, {
                headers: cookieHeader ? { cookie: cookieHeader } : {},
            });

            console.log(`[Middleware] Auth fetch returned status: ${res.status}`);

            if (!res.ok) {
                // Invalid or missing session, redirect to login page
                console.log(`[Middleware] Invalid session, redirecting to /login`);
                return context.redirect("/login");
            }
            
            console.log(`[Middleware] Valid session, passing through`);
        } catch (error) {
            console.error("[Middleware] Auth middleware fetch error:", error);
            // On fetch failure, redirect to ensure security
            return context.redirect("/login");
        }
    }

    // Continue to next middleware or route handler
    return next();
});
