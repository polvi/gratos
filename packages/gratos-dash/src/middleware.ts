import { defineMiddleware } from "astro:middleware";
import { env } from "cloudflare:workers";

export const onRequest = defineMiddleware(async (context, next) => {
    // Protect authenticated routes
    const path = context.url.pathname;
    if (path.startsWith("/domains") || path.startsWith("/signup")) {
        // Read the API URL from environment (Cloudflare runtime fallback to build-time)
        const apiBaseUrl = env.PUBLIC_GRATOS_SERVER || import.meta.env.PUBLIC_GRATOS_SERVER;
        
        // Grab the cookie header from the inbound request
        const cookieHeader = context.request.headers.get("cookie");

        try {
            // Forward the cookie to the Gratos check auth endpoint
            const res = await fetch(`${apiBaseUrl}/whoami`, {
                headers: cookieHeader ? { cookie: cookieHeader } : {},
            });

            if (!res.ok) {
                // Invalid or missing session, redirect to login page
                return context.redirect("/login");
            }
        } catch (error) {
            console.error("Auth middleware error:", error);
            // On fetch failure, redirect to ensure security
            return context.redirect("/login");
        }
    }

    // Continue to next middleware or route handler
    return next();
});
