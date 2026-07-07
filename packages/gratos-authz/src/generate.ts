// AI schema generation: crawl the tenant's site, infer what kind of product
// it is, and draft an authz schema for it. The draft is returned to the owner
// for review — nothing is saved until they apply it through PUT /schema.

import { ApiError } from './model';
import { SchemaDocument, validateSchema } from './schema';

export const AI_MODEL = '@cf/moonshotai/kimi-k2.7-code';

const CRAWL_PAGE_LIMIT = 8;
const CRAWL_POLL_INTERVAL_MS = 3000;
const CRAWL_TIMEOUT_MS = 75_000;
// Keep the prompt well inside the context window.
const MAX_SITE_CHARS = 24_000;
const MAX_PAGE_CHARS = 6_000;

export type GenerateEnv = {
    AI: Ai;
    /** Account for the Browser Rendering crawl REST API. */
    CF_ACCOUNT_ID?: string;
    /** API token with Browser Rendering permission. Optional: without it we
     *  fall back to fetching the homepage directly. */
    CF_API_TOKEN?: string;
};

export type CrawledPage = { url: string; content: string };

// --- crawling ---

/**
 * Crawl the site with Browser Rendering's /crawl endpoint (markdown output).
 * Falls back to a plain fetch of the homepage when no crawl credentials are
 * configured, so dev and unconfigured deployments still work.
 */
export async function crawlSite(env: GenerateEnv, domain: string): Promise<{ pages: CrawledPage[]; method: string }> {
    if (env.CF_ACCOUNT_ID && env.CF_API_TOKEN) {
        try {
            const pages = await crawlViaApi(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, domain);
            if (pages.length > 0) return { pages, method: 'crawl' };
        } catch (e) {
            console.error(`crawl API failed for ${domain}, falling back to fetch:`, e);
        }
    }
    return { pages: await fetchHomepage(domain), method: 'fetch' };
}

async function crawlViaApi(accountId: string, token: string, domain: string): Promise<CrawledPage[]> {
    const base = `https://api.cloudflare.com/client/v4/accounts/${accountId}/browser-rendering/crawl`;
    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    const startRes = await fetch(base, {
        method: 'POST',
        headers,
        body: JSON.stringify({
            url: `https://${domain}/`,
            limit: CRAWL_PAGE_LIMIT,
            formats: ['markdown'],
        }),
    });
    const start = (await startRes.json()) as any;
    if (!startRes.ok || start?.success === false) {
        throw new Error(`crawl start failed (${startRes.status}): ${JSON.stringify(start?.errors ?? start)}`);
    }
    const jobId = start?.result?.id ?? start?.result?.job_id ?? start?.id;
    if (!jobId) throw new Error('crawl start returned no job id');

    const deadline = Date.now() + CRAWL_TIMEOUT_MS;
    let lastResult: any = null;
    while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, CRAWL_POLL_INTERVAL_MS));
        const pollRes = await fetch(`${base}/${jobId}`, { headers });
        if (!pollRes.ok) continue;
        const poll = (await pollRes.json()) as any;
        lastResult = poll?.result ?? poll;
        const status = String(lastResult?.status ?? '').toLowerCase();
        if (status && !['completed', 'complete', 'finished', 'done'].includes(status)) {
            if (['failed', 'error', 'cancelled'].includes(status)) {
                throw new Error(`crawl job ${status}`);
            }
            continue;
        }
        break;
    }

    return extractPages(lastResult);
}

/** Normalize the crawl job result into url+markdown pairs. */
function extractPages(result: any): CrawledPage[] {
    const raw: any[] = result?.pages ?? result?.results ?? result?.data ?? [];
    const pages: CrawledPage[] = [];
    for (const p of raw) {
        const content = p?.markdown ?? p?.formats?.markdown ?? p?.content;
        const url = p?.url ?? p?.page_url ?? '';
        if (typeof content === 'string' && content.trim()) {
            pages.push({ url, content: content.slice(0, MAX_PAGE_CHARS) });
        }
        if (pages.length >= CRAWL_PAGE_LIMIT) break;
    }
    return pages;
}

/** Fallback: fetch the homepage and crudely strip it to text. */
async function fetchHomepage(domain: string): Promise<CrawledPage[]> {
    const url = `https://${domain}/`;
    let res: Response;
    try {
        res = await fetch(url, { headers: { Accept: 'text/html' }, redirect: 'follow' });
    } catch {
        throw new ApiError(422, `could not reach https://${domain}/`);
    }
    if (!res.ok) throw new ApiError(422, `https://${domain}/ answered ${res.status}`);
    const html = await res.text();
    const text = html
        .replace(/<script[\s\S]*?<\/script>/gi, ' ')
        .replace(/<style[\s\S]*?<\/style>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    if (!text) throw new ApiError(422, `https://${domain}/ has no readable content`);
    return [{ url, content: text.slice(0, MAX_PAGE_CHARS * 2) }];
}

// --- AI generation ---

const SCHEMA_FORMAT_SPEC = `The schema is a JSON document: {"definitions": {"<type>": {"relations": {...}, "permissions": {...}}}}.
- Type, relation, and permission names match ^[a-z][a-z0-9_]{0,63}$.
- A relation declares which subjects may be written into tuples: {"subjects": [{"type": "user"}, {"type": "group", "relation": "member"}]}. "user" is built in (the app's end users); every other referenced type must be defined in the document. A subject entry with "relation" allows subject sets (e.g. all members of a group).
- A permission is an expression:
  {"rel": "<name>"} — another relation or permission on the same type
  {"union": [expr, ...]} / {"intersection": [expr, ...]}
  {"exclusion": {"base": expr, "subtract": expr}}
  {"arrow": {"via": "<relation>", "permission": "<name>"}} — follow a parent-style relation and check a permission there. The via relation's subjects must be direct types only (no "relation" entries).
- Within a type, relations and permissions share one namespace (no duplicates).
- Do NOT define or reference types named "user" (built in) or starting with "gratos_" (reserved).`;

function extractJson(text: string): unknown {
    let t = text.trim();
    const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fence) t = fence[1].trim();
    const start = t.indexOf('{');
    const end = t.lastIndexOf('}');
    if (start === -1 || end <= start) throw new Error('no JSON object in model output');
    return JSON.parse(t.slice(start, end + 1));
}

/**
 * Run the model in streaming mode and accumulate the result. Streaming keeps
 * the inference connection alive — a one-shot sync call to a large model can
 * exceed the AI gateway timeout (504) before the first byte arrives.
 */
async function runModel(env: GenerateEnv, messages: Array<{ role: string; content: string }>): Promise<string> {
    const stream = (await env.AI.run(AI_MODEL as any, {
        messages,
        stream: true,
        // Generous: the model spends tokens on reasoning before the answer,
        // and both count against this cap.
        max_tokens: 8192,
    } as any)) as ReadableStream;

    const reader = stream.getReader();
    const decoder = new TextDecoder();
    let raw = '';
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        raw += decoder.decode(value, { stream: true });
    }
    raw += decoder.decode();

    let text = '';
    for (const line of raw.split('\n')) {
        if (!line.startsWith('data:')) continue;
        const payload = line.slice(5).trim();
        if (!payload || payload === '[DONE]') continue;
        try {
            const chunk = JSON.parse(payload) as any;
            text += chunk?.response ?? chunk?.choices?.[0]?.delta?.content ?? '';
        } catch {
            // partial/keepalive frame — ignore
        }
    }
    if (!text.trim()) throw new Error('empty model response');
    return text;
}

function siteDigest(pages: CrawledPage[]): string {
    let out = '';
    for (const p of pages) {
        const chunk = `\n\n--- ${p.url} ---\n${p.content}`;
        if (out.length + chunk.length > MAX_SITE_CHARS) break;
        out += chunk;
    }
    return out.trim();
}

export type GeneratedSchema = {
    schema: SchemaDocument;
    description: string;
    pages: string[];
    method: string;
    model: string;
};

/**
 * Crawl `domain`, draft an authz schema for it, and produce a human-readable
 * description. Validates the model's schema with the real validator and
 * retries once with the validation errors before giving up.
 */
export async function generateSchemaForDomain(env: GenerateEnv, domain: string): Promise<GeneratedSchema> {
    const { pages, method } = await crawlSite(env, domain);
    const digest = siteDigest(pages);

    const system = `You are an authorization engineer designing a Zanzibar-style relationship-based access control schema for a website's application resources.

${SCHEMA_FORMAT_SPEC}

Study the site content, infer what kind of product it is and what resources its users interact with (documents, posts, listings, orders, teams, projects, ...), and design a practical schema: 2-5 object types, ownership/editor/viewer style relations where they fit, group- or team-based sharing only when the product suggests collaboration, and permissions composed from the relations (including parent->child inheritance via "arrow" when there is a natural hierarchy).

Respond with ONLY a JSON object of this shape, no prose and no markdown fences:
{"schema": <the schema document>, "description": "<plain-text explanation for non-experts: one sentence on what kind of site this appears to be, then one short line per object type explaining who can do what; under 150 words>"}`;

    const user = `Website: https://${domain}/\n\nSite content:\n${digest}`;

    const messages = [
        { role: 'system', content: system },
        { role: 'user', content: user },
    ];

    let schema: SchemaDocument | null = null;
    let description = '';
    let lastErrors: string[] = [];
    for (let attempt = 0; attempt < 2 && !schema; attempt++) {
        const text = await runModel(env, messages);
        let candidate: any;
        try {
            candidate = extractJson(text);
        } catch (e) {
            lastErrors = [String(e)];
            messages.push({ role: 'assistant', content: text });
            messages.push({
                role: 'user',
                content: 'That was not parseable JSON. Respond with ONLY the {"schema": ..., "description": "..."} JSON object.',
            });
            continue;
        }
        const result = validateSchema(candidate?.schema ?? candidate);
        if (result.ok) {
            schema = result.doc;
            description = typeof candidate?.description === 'string' ? candidate.description : '';
        } else {
            lastErrors = result.errors;
            messages.push({ role: 'assistant', content: text });
            messages.push({
                role: 'user',
                content: `That schema failed validation:\n- ${result.errors.join('\n- ')}\n\nFix these problems and respond with ONLY the corrected {"schema": ..., "description": "..."} JSON object.`,
            });
        }
    }
    if (!schema) {
        throw new ApiError(422, 'the model could not produce a valid schema', lastErrors);
    }

    return {
        schema,
        description: description.trim(),
        pages: pages.map((p) => p.url).filter(Boolean),
        method,
        model: AI_MODEL,
    };
}
