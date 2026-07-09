import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';

export const prerender = false;

// authgravity.org/llms.txt is the root onboarding guide. It is the AuthGravity
// product tenant's own host doc, produced by the one generator in gratos-authz
// (tenant = ROOT_TENANT → 'root' framing). We proxy it so there is a single
// source of truth and a single canonical URL humans cite.
export const GET: APIRoute = async () => {
    const base =
        (env as Record<string, string>).PUBLIC_GRATOS_SERVER ||
        import.meta.env.PUBLIC_GRATOS_SERVER;

    try {
        const res = await fetch(`${base}/llms.txt`);
        const text = await res.text();
        return new Response(text, {
            status: res.status,
            headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-cache' },
        });
    } catch {
        return new Response('# AuthGravity\n\nDocs temporarily unavailable — retry shortly.', {
            status: 502,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
        });
    }
};
