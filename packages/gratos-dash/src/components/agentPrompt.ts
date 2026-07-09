// One prompt for every AuthGravity integration surface. It carries only the
// one thing an agent can't derive — the endpoint — and points at that host's
// single llms.txt, which now documents passkey auth AND authorization with the
// endpoint pre-filled. Everything else (API, design guidance, live schema)
// lives in that file, so the prompt can't drift.

export interface AgentPrompt {
    endpoint: string;
    url: string;
    prompt: string;
}

/** Derive the endpoint + prompt for a tenant. Sandbox tenants are keyed
 *  "<host>/<id>"; domain tenants get the "authgravity.<domain>" host. */
export function agentPromptFor(tenant: string): AgentPrompt {
    const isSandbox = tenant.includes('/');
    const endpoint = isSandbox ? `https://${tenant}` : `https://authgravity.${tenant}`;
    const url = `${endpoint}/llms.txt`;

    const prompt =
        `Integrate AuthGravity (passkey auth + authorization) into my app.\n\n` +
        `Endpoint: ${endpoint}\n\n` +
        `Read ${url} in full and follow it exactly — it documents this host's live ` +
        `auth and authorization API, the exact request/response shapes, and the design ` +
        `guidance, with the endpoint already filled in. Discovery lives at ` +
        `${endpoint}/.well-known/authgravity.` +
        (isSandbox
            ? `\n\nIf I'm running \`authgravity listen\`, use http://localhost:8787 as the endpoint instead.`
            : '');

    return { endpoint, url, prompt };
}
