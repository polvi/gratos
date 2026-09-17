// Minimal four-party federation (seam §4): when a budgeted resource token's
// `aud` is the provider's Access Server rather than us, the PS relays the
// token request there with a PS-signed budget attestation, and passes the
// AS-issued token — plus the funding fields — back to the agent verbatim.

import { AAuthError } from './encoding';
import { checkOutboundUrl } from './jwksfetch';
import { mintBudgetAttestation, type BudgetEntry, type MissionRef } from './jwt';
import type { SigningKey } from './pskeys';

export type RelayResult = {
    auth_token: string;
    token_type?: string;
    expires_in?: number;
    funded?: boolean;
    funding_url?: string;
};

export async function relayBudgetTokenRequest(opts: {
    key: SigningKey;
    tenantIss: string;
    asUrl: string;
    resourceToken: string;
    agentToken: string;
    resource: string;
    mission: MissionRef;
    agentJkt: string;
    budget: BudgetEntry;
}): Promise<RelayResult> {
    checkOutboundUrl(opts.asUrl);
    const budget_attestation = await mintBudgetAttestation({
        key: opts.key,
        iss: opts.tenantIss,
        aud: opts.asUrl,
        resource: opts.resource,
        mission: opts.mission,
        agentJkt: opts.agentJkt,
        budget: opts.budget,
    });

    let res: Response;
    try {
        res = await fetch(opts.asUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({
                resource_token: opts.resourceToken,
                agent_token: opts.agentToken,
                budget_attestation,
            }),
            signal: AbortSignal.timeout(10000),
        });
    } catch {
        throw new AAuthError('federation_failed', 'could not reach the resource access server', 502);
    }

    const body = (await res.json().catch(() => null)) as RelayResult | { error?: string; error_description?: string } | null;
    if (!res.ok) {
        const err = (body ?? {}) as { error?: string; error_description?: string };
        throw new AAuthError(
            err.error || 'federation_failed',
            err.error_description || `access server returned ${res.status}`,
            res.status === 402 || res.status === 403 ? (res.status as 403) : 502
        );
    }
    if (!body || typeof (body as RelayResult).auth_token !== 'string') {
        throw new AAuthError('federation_failed', 'access server response missing auth_token', 502);
    }
    const ok = body as RelayResult;
    // funded / funding_url pass through verbatim (claim-by-mission-ref, seam §5).
    return {
        auth_token: ok.auth_token,
        token_type: ok.token_type,
        expires_in: ok.expires_in,
        funded: ok.funded,
        funding_url: ok.funding_url,
    };
}
