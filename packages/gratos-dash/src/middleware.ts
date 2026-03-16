import { defineMiddleware } from "astro:middleware";

export const onRequest = defineMiddleware(async (context, next) => {
    // Only intercept requests for the /domains path
    if (context.url.pathname.startsWith("/domains")) {
        // Read the API URL from environment
        const apiBaseUrl = import.meta.env.PUBLIC_GRATOS_SERVER;
        
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
