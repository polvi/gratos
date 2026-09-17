// AAuth Person Server routes, served on every tenant host (dispatched from the
// index.ts catch-all like /v1/authz). Agent-facing endpoints require an RFC
// 9421-signed request carrying an aa-agent+jwt in Signature-Key; user-facing
// consent/grants/missions endpoints ride the existing passkey session.

import { Hono } from 'hono';

import type { Env, Variables } from '../index';
import type { TenantInfo } from '../tenant';
import { getSessionId } from '../session';
import { resolveSession } from '../sessions';
import { getUser } from '../db';
import { sha256Hex } from '../hash';

import { AAuthError, sha256B64u } from './encoding';
import { ensureTenantJwks, getSigningKey } from './pskeys';
import {
    verifyAgentToken,
    verifyResourceToken,
    mintAuthToken,
    agentId,
    AUTH_TOKEN_TTL_S,
    type AgentIdentity,
    type MissionRef,
} from './jwt';
import { parseSignatureHeaders, verifyHttpSignature, type ParsedSignature } from './httpsig';
import { findGrant, touchGrant, upsertGrant, listGrants, revokeGrant, scopeCovered, normalizeScope } from './grants';
import {
    createPending,
    getPending,
    putPending,
    deletePending,
    getPendingIdByCode,
    consumeCode,
    type PendingRecord,
} from './pending';
import {
    validateProposal,
    proposeMission,
    getMissionById,
    getMissionByS256,
    getMissionByCode,
    effectiveStatus,
    approveMission,
    declineMission,
    closeMission,
    requireActiveMission,
    budgetEntryFor,
    logMission,
    missionLog,
    type BudgetAttenuation,
    type MissionRow,
} from './missions';
import { relayBudgetTokenRequest } from './federation';

const RATE_LIMIT_PER_HOUR = 120;
const MAX_TOKEN_LEN = 8192;
const MAX_TEXT_LEN = 4096;

/** Parse `AAuth-Mission: approver="...";s256="..."` (seam §3). */
function parseMissionHeader(value: string | undefined): MissionRef | null {
    if (!value) return null;
    const approver = value.match(/approver="([^"]+)"/);
    const s256 = value.match(/s256="([^"]+)"/);
    if (!approver || !s256) throw new AAuthError('invalid_request', 'malformed AAuth-Mission header');
    return { approver: approver[1], s256: s256[1] };
}

function missionRefOf(tenantIss: string, row: MissionRow): MissionRef {
    return { approver: tenantIss, s256: row.s256! };
}

function missionHeader(ref: MissionRef): string {
    return `approver="${ref.approver}"; s256="${ref.s256}"`;
}

export function aauthRoutes(tenantInfo: TenantInfo) {
    const app = new Hono<{ Bindings: Env; Variables: Variables }>();

    // The host identity: origin plus the sandbox "/<id>" prefix. This is the
    // token `iss`, the base of every advertised URL, and what base-path
    // resource tokens must be addressed to.
    const endpoint = tenantInfo.origin + (tenantInfo.sandboxPrefix ?? '');
    const tenantIss = endpoint;

    app.onError((err, c) => {
        if (err instanceof AAuthError) return c.json(err.body(), err.status);
        console.error('aauth error', err);
        return c.json({ error: 'server_error', error_description: 'unexpected error' }, 500);
    });

    /**
     * Authenticate a signed agent request: rate limit, parse signature
     * headers, verify the agent token, verify the HTTP signature against its
     * cnf.jwk (proof of possession), replay-guard on the signature bytes.
     */
    async function authenticateAgent(c: any): Promise<{ agent: AgentIdentity; parsed: ParsedSignature }> {
        const ip = c.req.header('CF-Connecting-IP') || 'unknown';
        const rlKey = `aauth_rl:${await sha256Hex(ip)}`;
        const count = parseInt((await c.env.KV.get(rlKey)) || '0', 10);
        if (count >= RATE_LIMIT_PER_HOUR) {
            throw new AAuthError('rate_limited', 'too many requests, try again later', 429);
        }
        await c.env.KV.put(rlKey, String(count + 1), { expirationTtl: 3600 });

        const parsed = parseSignatureHeaders(c.req.raw.headers);
        const agent = await verifyAgentToken(c.env.KV, parsed.agentJwt);

        // The sub-app sees the sandbox-stripped request; the SIGNED path
        // includes the "/<id>" prefix (seam §1) — reconstruct it.
        const url = new URL(c.req.url);
        const signedPath = (tenantInfo.sandboxPrefix ?? '') + url.pathname;
        await verifyHttpSignature({
            parsed,
            method: c.req.method,
            authority: url.host,
            protocol: url.protocol as 'http:' | 'https:',
            path: signedPath,
            headers: c.req.raw.headers,
            publicJwk: agent.cnfJwk,
        });

        const replayKey = `aauth_replay:${await sha256B64u(parsed.signatureBytes)}`;
        if (await c.env.KV.get(replayKey)) {
            throw new AAuthError('invalid_signature', 'signature replay detected', 401);
        }
        await c.env.KV.put(replayKey, '1', { expirationTtl: 360 });

        return { agent, parsed };
    }

    /** Resolve the session user for user-facing endpoints (cookie or Bearer). */
    async function sessionUser(c: any): Promise<string | null> {
        const sessionId = getSessionId(c);
        if (!sessionId) return null;
        const session = await resolveSession(c.env.KV, tenantInfo.tenant, sessionId);
        if (!session) return null;
        const user = await getUser(c.env.DB, tenantInfo.tenant, session.userId);
        return user ? session.userId : null;
    }

    function pending202(c: any, id: string, code: string) {
        c.header('Location', `${endpoint}/v1/aauth/pending/${id}`);
        c.header('Retry-After', '5');
        c.header('Cache-Control', 'no-store');
        c.header('AAuth-Requirement', `requirement=interaction; url="${endpoint}/consent"; code="${code}"`);
        return c.json({ status: 'pending' }, 202);
    }

    // ------------------------------------------------------------------ //
    // Discovery

    // Discovery reads provision the tenant's signing key on first hit, so
    // domains claimed before AAuth shipped (or any idle pool) never advertise
    // an empty JWKS. Sandbox tenants must exist first: the sandbox id is an
    // attacker-chosen path segment, and without the row check any GET could
    // insert ps_keys rows for made-up ids.
    async function eagerMintAllowed(db: D1Database): Promise<boolean> {
        if (!tenantInfo.sandbox) return true;
        const row = await db.prepare('SELECT 1 FROM sandboxes WHERE id = ?').bind(tenantInfo.tenant).first();
        return !!row;
    }

    app.get('/.well-known/aauth-person.json', async (c) => {
        const jwks = await ensureTenantJwks(
            c.env.DB,
            c.env,
            tenantInfo.tenant,
            await eagerMintAllowed(c.env.DB)
        );
        return c.json(
            {
                issuer: tenantIss,
                token_endpoint: `${endpoint}/v1/aauth/token`,
                mission_endpoint: `${endpoint}/v1/aauth/mission`,
                permission_endpoint: `${endpoint}/v1/aauth/permission`,
                audit_endpoint: `${endpoint}/v1/aauth/audit`,
                interaction_endpoint: `${endpoint}/v1/aauth/interaction`,
                jwks_uri: `${endpoint}/v1/aauth/jwks.json`,
                keys: jwks.keys,
                signature_algorithms_supported: ['ed25519'],
            },
            200,
            { 'Cache-Control': 'no-cache' }
        );
    });

    app.get('/v1/aauth/jwks.json', async (c) => {
        const jwks = await ensureTenantJwks(
            c.env.DB,
            c.env,
            tenantInfo.tenant,
            await eagerMintAllowed(c.env.DB)
        );
        return c.json(jwks, 200, { 'Cache-Control': 'no-cache' });
    });

    // ------------------------------------------------------------------ //
    // Token endpoint

    app.post('/v1/aauth/token', async (c) => {
        const { agent } = await authenticateAgent(c);
        const body = (await c.req.json().catch(() => null)) as {
            resource_token?: string;
            justification?: string;
        } | null;
        if (!body || typeof body.resource_token !== 'string' || body.resource_token.length > MAX_TOKEN_LEN) {
            throw new AAuthError('invalid_request', 'resource_token is required');
        }
        const justification =
            typeof body.justification === 'string' ? body.justification.slice(0, MAX_TEXT_LEN) : undefined;

        const rt = await verifyResourceToken(c.env.KV, body.resource_token, {
            iss: agent.iss,
            sub: agent.sub,
            jkt: agent.jkt,
        });

        // Mission context: header ref must match the resource token's echo.
        const headerRef = parseMissionHeader(c.req.header('AAuth-Mission') ?? undefined);
        if (headerRef && rt.mission && (headerRef.s256 !== rt.mission.s256 || headerRef.approver !== rt.mission.approver)) {
            throw new AAuthError('invalid_request', 'AAuth-Mission header does not match the resource token mission');
        }
        const ref = headerRef ?? rt.mission ?? null;

        if (ref) {
            const row = await requireActiveMission(
                c.env.DB,
                tenantInfo.tenant,
                ref,
                { iss: agent.iss, sub: agent.sub },
                tenantIss
            );
            await logMission(c.env.DB, tenantInfo.tenant, row.id, 'token_request', {
                resource: rt.resource,
                scope: rt.scope,
                aud: rt.aud,
            });

            // Budget path: entries match the resource token ISS (never aud).
            const budget = budgetEntryFor(row.mission_json!, rt.resource);
            if (budget) {
                const key = await getSigningKey(c.env.DB, c.env, tenantInfo.tenant);
                if (rt.aud === tenantIss) {
                    // Three-party: we mint the identityless budgeted token.
                    const minted = await mintAuthToken({
                        key,
                        iss: tenantIss,
                        aud: rt.resource,
                        cnfJwk: agent.cnfJwk,
                        scope: rt.scope,
                        identity: { kind: 'budgeted', agent: agentId(agent), mission: ref, budget },
                    });
                    return c.json({ auth_token: minted.token, expires_in: minted.expiresIn });
                }
                // Four-party: relay to the AS named by aud with our attestation.
                const relayed = await relayBudgetTokenRequest({
                    key,
                    tenantIss,
                    asUrl: rt.aud,
                    resourceToken: rt.token,
                    agentToken: agent.token,
                    resource: rt.resource,
                    mission: ref,
                    agentJkt: agent.jkt,
                    budget,
                });
                await logMission(c.env.DB, tenantInfo.tenant, row.id, 'federation', {
                    as: rt.aud,
                    resource: rt.resource,
                    funded: relayed.funded,
                });
                return c.json(relayed);
            }
            // Mission-bound but no budget entry for this resource: fall through
            // to the base (identity) path, which still requires consent.
        }

        // Base path: the resource token must be addressed to this PS.
        if (rt.aud !== tenantIss) {
            throw new AAuthError('invalid_request', 'resource token is not addressed to this Person Server');
        }

        const grant = await findGrant(c.env.DB, tenantInfo.tenant, agent.iss, agent.sub, rt.resource);
        if (grant && scopeCovered(rt.scope, grant.scope)) {
            await touchGrant(c.env.DB, grant.id);
            const key = await getSigningKey(c.env.DB, c.env, tenantInfo.tenant);
            const minted = await mintAuthToken({
                key,
                iss: tenantIss,
                aud: rt.resource,
                cnfJwk: agent.cnfJwk,
                scope: rt.scope,
                identity: { kind: 'base', sub: grant.user_id },
            });
            return c.json({ auth_token: minted.token, expires_in: minted.expiresIn });
        }

        const { id, code } = await createPending(c.env.KV, tenantInfo.tenant, {
            kind: 'token',
            agent: { iss: agent.iss, sub: agent.sub, jwk: agent.cnfJwk },
            payload: { resource: rt.resource, scope: rt.scope, justification },
        });
        return pending202(c, id, code);
    });

    // ------------------------------------------------------------------ //
    // Missions (proposal is D1-backed: consent can take days)

    app.post('/v1/aauth/mission', async (c) => {
        const { agent } = await authenticateAgent(c);
        const proposal = validateProposal(await c.req.json().catch(() => null));
        const { id, code } = await proposeMission(
            c.env.DB,
            tenantInfo.tenant,
            { iss: agent.iss, sub: agent.sub, jwk: agent.cnfJwk },
            proposal
        );
        return pending202(c, id, code);
    });

    app.get('/v1/aauth/mission/:s256', async (c) => {
        const { agent } = await authenticateAgent(c);
        const row = await getMissionByS256(c.env.DB, tenantInfo.tenant, c.req.param('s256'));
        if (!row || row.agent_iss !== agent.iss || row.agent_sub !== agent.sub) {
            throw new AAuthError('mission_expired', 'no such mission', 404);
        }
        const status = await effectiveStatus(c.env.DB, row);
        return c.json(
            { status, s256: row.s256, mission: row.mission_json ? JSON.parse(row.mission_json) : null },
            200,
            { 'Cache-Control': 'no-store' }
        );
    });

    // ------------------------------------------------------------------ //
    // Permission / audit / interaction (governance; mission-bound)

    app.post('/v1/aauth/permission', async (c) => {
        const { agent } = await authenticateAgent(c);
        const body = (await c.req.json().catch(() => null)) as {
            action?: string;
            description?: string;
            parameters?: Record<string, unknown>;
            mission?: MissionRef;
        } | null;
        if (!body || typeof body.action !== 'string' || !body.action) {
            throw new AAuthError('invalid_request', 'action is required');
        }
        if (!body.mission) throw new AAuthError('invalid_request', 'mission is required');
        const row = await requireActiveMission(
            c.env.DB,
            tenantInfo.tenant,
            body.mission,
            { iss: agent.iss, sub: agent.sub },
            tenantIss
        );

        const mission = JSON.parse(row.mission_json!) as { approved_tools?: string[] };
        if (mission.approved_tools?.includes(body.action)) {
            await logMission(c.env.DB, tenantInfo.tenant, row.id, 'permission', {
                action: body.action,
                parameters: body.parameters,
                result: 'granted',
                auto: true,
            });
            return c.json({ permission: 'granted' });
        }

        await logMission(c.env.DB, tenantInfo.tenant, row.id, 'permission', {
            action: body.action,
            description: body.description?.slice(0, MAX_TEXT_LEN),
            parameters: body.parameters,
            result: 'pending',
        });
        const { id, code } = await createPending(c.env.KV, tenantInfo.tenant, {
            kind: 'permission',
            agent: { iss: agent.iss, sub: agent.sub, jwk: agent.cnfJwk },
            payload: {
                action: body.action,
                description: body.description?.slice(0, MAX_TEXT_LEN),
                parameters: body.parameters,
                missionId: row.id,
            },
        });
        return pending202(c, id, code);
    });

    app.post('/v1/aauth/audit', async (c) => {
        const { agent } = await authenticateAgent(c);
        const body = (await c.req.json().catch(() => null)) as {
            mission?: MissionRef;
            action?: string;
            description?: string;
            parameters?: Record<string, unknown>;
            result?: Record<string, unknown>;
        } | null;
        if (!body?.mission) throw new AAuthError('invalid_request', 'mission is required');
        if (typeof body.action !== 'string' || !body.action) {
            throw new AAuthError('invalid_request', 'action is required');
        }
        const row = await requireActiveMission(
            c.env.DB,
            tenantInfo.tenant,
            body.mission,
            { iss: agent.iss, sub: agent.sub },
            tenantIss
        );
        await logMission(c.env.DB, tenantInfo.tenant, row.id, 'audit', {
            action: body.action,
            description: body.description?.slice(0, MAX_TEXT_LEN),
            parameters: body.parameters,
            result: body.result,
        });
        return c.body(null, 201);
    });

    app.post('/v1/aauth/interaction', async (c) => {
        const { agent } = await authenticateAgent(c);
        const body = (await c.req.json().catch(() => null)) as {
            type?: string;
            mission?: MissionRef;
            summary?: string;
            question?: string;
        } | null;
        const type = body?.type;
        if (type !== 'question' && type !== 'completion' && type !== 'forward') {
            throw new AAuthError('invalid_request', 'type must be question, completion or forward');
        }
        let missionId: string | undefined;
        if (body?.mission) {
            const row = await requireActiveMission(
                c.env.DB,
                tenantInfo.tenant,
                body.mission,
                { iss: agent.iss, sub: agent.sub },
                tenantIss
            );
            missionId = row.id;
        } else if (type === 'completion') {
            throw new AAuthError('invalid_request', 'completion requires a mission');
        }
        if (missionId) {
            await logMission(c.env.DB, tenantInfo.tenant, missionId, 'interaction', {
                type,
                summary: body?.summary?.slice(0, MAX_TEXT_LEN),
                question: body?.question?.slice(0, MAX_TEXT_LEN),
            });
        }
        const { id, code } = await createPending(c.env.KV, tenantInfo.tenant, {
            kind: 'interaction',
            agent: { iss: agent.iss, sub: agent.sub, jwk: agent.cnfJwk },
            payload: {
                type,
                summary: body?.summary?.slice(0, MAX_TEXT_LEN),
                question: body?.question?.slice(0, MAX_TEXT_LEN),
                missionId,
            },
        });
        return pending202(c, id, code);
    });

    // ------------------------------------------------------------------ //
    // Pending: agent polls / answers clarifications / cancels

    /** Latest clarification chat state for a mission: pending question for the agent? */
    async function missionClarification(c: any, row: MissionRow): Promise<string | null> {
        const log = await missionLog(c.env.DB, tenantInfo.tenant, row.id, 20);
        const chats = log.filter((l) => l.kind === 'clarification');
        const last = chats[chats.length - 1];
        return last && last.entry.from === 'user' ? String(last.entry.text ?? '') : null;
    }

    app.get('/v1/aauth/pending/:id', async (c) => {
        const id = c.req.param('id');
        c.header('Cache-Control', 'no-store');

        // Mission pendings live in D1.
        const row = await getMissionById(c.env.DB, tenantInfo.tenant, id);
        if (row) {
            const status = await effectiveStatus(c.env.DB, row);
            if (status === 'proposed') {
                const question = await missionClarification(c, row);
                if (question) {
                    c.header('AAuth-Requirement', 'requirement=clarification');
                    return c.json({ status: 'pending', clarification: question, timeout: 120 }, 202);
                }
                c.header('Retry-After', '5');
                return c.json({ status: 'pending' }, 202);
            }
            if (status === 'active') {
                const ref = missionRefOf(tenantIss, row);
                c.header('AAuth-Mission', missionHeader(ref));
                return c.json({ status: 'active', s256: row.s256, mission: JSON.parse(row.mission_json!) });
            }
            if (status === 'declined') return c.json({ error: 'access_denied', error_description: 'the person declined' }, 403);
            return c.json({ error: 'mission_expired', error_description: 'the proposal expired' }, 404);
        }

        const pending = await getPending(c.env.KV, tenantInfo.tenant, id);
        if (!pending) return c.json({ error: 'not_found', error_description: 'unknown or expired pending' }, 404);
        if (pending.st === 'pending') {
            const last = pending.chat[pending.chat.length - 1];
            if (last && last.from === 'user') {
                c.header('AAuth-Requirement', 'requirement=clarification');
                return c.json({ status: 'pending', clarification: last.text, timeout: 120 }, 202);
            }
            c.header('Retry-After', '5');
            return c.json({ status: 'pending' }, 202);
        }
        if (pending.st === 'denied') {
            await deletePending(c.env.KV, tenantInfo.tenant, id);
            return c.json(pending.result ?? { error: 'access_denied', error_description: 'the person declined' }, 403);
        }
        // approved: one-shot pickup
        await deletePending(c.env.KV, tenantInfo.tenant, id);
        return c.json(pending.result ?? { status: 'approved' });
    });

    app.post('/v1/aauth/pending/:id', async (c) => {
        const { agent } = await authenticateAgent(c);
        const id = c.req.param('id');
        const body = (await c.req.json().catch(() => null)) as { clarification_response?: string } | null;
        const response = body?.clarification_response;
        if (typeof response !== 'string' || !response.trim()) {
            throw new AAuthError('invalid_request', 'clarification_response is required');
        }

        const row = await getMissionById(c.env.DB, tenantInfo.tenant, id);
        if (row) {
            if (row.agent_iss !== agent.iss || row.agent_sub !== agent.sub) {
                throw new AAuthError('invalid_request', 'pending belongs to a different agent', 403);
            }
            await logMission(c.env.DB, tenantInfo.tenant, row.id, 'clarification', {
                from: 'agent',
                text: response.slice(0, MAX_TEXT_LEN),
            });
            return c.json({ status: 'pending' }, 202);
        }

        const pending = await getPending(c.env.KV, tenantInfo.tenant, id);
        if (!pending) throw new AAuthError('not_found', 'unknown or expired pending', 404);
        if (pending.agent.iss !== agent.iss || pending.agent.sub !== agent.sub) {
            throw new AAuthError('invalid_request', 'pending belongs to a different agent', 403);
        }
        pending.chat.push({ from: 'agent', text: response.slice(0, MAX_TEXT_LEN), at: Date.now() });
        await putPending(c.env.KV, tenantInfo.tenant, id, pending);
        return c.json({ status: 'pending' }, 202);
    });

    app.delete('/v1/aauth/pending/:id', async (c) => {
        const { agent } = await authenticateAgent(c);
        const id = c.req.param('id');

        const row = await getMissionById(c.env.DB, tenantInfo.tenant, id);
        if (row) {
            if (row.agent_iss !== agent.iss || row.agent_sub !== agent.sub) {
                throw new AAuthError('invalid_request', 'pending belongs to a different agent', 403);
            }
            if (row.status === 'proposed') {
                await c.env.DB
                    .prepare("UPDATE aauth_missions SET status = 'expired', code_hash = NULL, closed_at = ? WHERE id = ? AND status = 'proposed'")
                    .bind(Date.now(), row.id)
                    .run();
            }
            return c.json({ success: true });
        }

        const pending = await getPending(c.env.KV, tenantInfo.tenant, id);
        if (pending && (pending.agent.iss !== agent.iss || pending.agent.sub !== agent.sub)) {
            throw new AAuthError('invalid_request', 'pending belongs to a different agent', 403);
        }
        await deletePending(c.env.KV, tenantInfo.tenant, id);
        return c.json({ success: true });
    });

    // ------------------------------------------------------------------ //
    // Consent (session-gated; backs the /consent surface)

    /** Resolve a consent code to a mission row or a KV pending. */
    async function resolveCode(
        c: any,
        code: string
    ): Promise<{ mission?: MissionRow; pendingId?: string; pending?: PendingRecord }> {
        const mission = await getMissionByCode(c.env.DB, tenantInfo.tenant, code);
        if (mission) {
            if ((await effectiveStatus(c.env.DB, mission)) !== 'proposed') {
                throw new AAuthError('not_found', 'this request is no longer awaiting consent', 404);
            }
            return { mission };
        }
        const pendingId = await getPendingIdByCode(c.env.KV, tenantInfo.tenant, code);
        if (pendingId) {
            const pending = await getPending(c.env.KV, tenantInfo.tenant, pendingId);
            if (pending && pending.st === 'pending') return { pendingId, pending };
        }
        throw new AAuthError('not_found', 'unknown or expired code', 404);
    }

    function requireIntendedApprover(row: MissionRow, userId: string) {
        if (row.approver_hint && row.approver_hint !== userId) {
            throw new AAuthError('not_intended_approver', 'this proposal names a different approver', 403);
        }
    }

    app.get('/v1/aauth/consent', async (c) => {
        const userId = await sessionUser(c);
        if (!userId) return c.json({ error: 'not_authenticated' }, 401);
        const code = (c.req.query('code') || '').trim();
        if (!code) throw new AAuthError('invalid_request', 'code is required');

        const resolved = await resolveCode(c, code);
        c.header('Cache-Control', 'no-store');
        if (resolved.mission) {
            const row = resolved.mission;
            requireIntendedApprover(row, userId);
            const log = await missionLog(c.env.DB, tenantInfo.tenant, row.id, 40);
            return c.json({
                kind: 'mission',
                agent: { iss: row.agent_iss, sub: row.agent_sub },
                proposal: JSON.parse(row.proposal_json),
                created_at: row.created_at,
                expires_at: row.expires_at,
                chat: log
                    .filter((l) => l.kind === 'clarification')
                    .map((l) => ({ from: l.entry.from, text: l.entry.text, at: l.at })),
            });
        }
        const pending = resolved.pending!;
        return c.json({
            kind: pending.kind,
            agent: { iss: pending.agent.iss, sub: pending.agent.sub },
            payload: pending.payload,
            chat: pending.chat,
            created_at: pending.createdAt,
        });
    });

    app.post('/v1/aauth/consent', async (c) => {
        const userId = await sessionUser(c);
        if (!userId) return c.json({ error: 'not_authenticated' }, 401);
        const body = (await c.req.json().catch(() => null)) as {
            code?: string;
            decision?: 'approve' | 'deny';
            remember?: boolean;
            answer?: string;
            attenuation?: { budgets?: BudgetAttenuation; omit?: string[] };
        } | null;
        const code = (body?.code || '').trim();
        if (!code) throw new AAuthError('invalid_request', 'code is required');

        const resolved = await resolveCode(c, code);

        // A chat message (question to the agent) — code is NOT consumed.
        if (typeof body?.answer === 'string' && body.answer.trim() && !body.decision) {
            const text = body.answer.slice(0, MAX_TEXT_LEN);
            if (resolved.mission) {
                requireIntendedApprover(resolved.mission, userId);
                await logMission(c.env.DB, tenantInfo.tenant, resolved.mission.id, 'clarification', {
                    from: 'user',
                    text,
                });
            } else {
                const pending = resolved.pending!;
                pending.chat.push({ from: 'user', text, at: Date.now() });
                await putPending(c.env.KV, tenantInfo.tenant, resolved.pendingId!, pending);
            }
            return c.json({ ok: true, status: 'pending' });
        }

        if (body?.decision !== 'approve' && body?.decision !== 'deny') {
            throw new AAuthError('invalid_request', 'decision must be approve or deny');
        }

        // Mission proposal
        if (resolved.mission) {
            const row = resolved.mission;
            requireIntendedApprover(row, userId);
            if (body.decision === 'deny') {
                await declineMission(c.env.DB, row, userId);
                await logMission(c.env.DB, tenantInfo.tenant, row.id, 'approval', { result: 'declined' });
                return c.json({ ok: true, status: 'declined' });
            }
            const { s256 } = await approveMission(
                c.env.DB,
                tenantInfo.tenant,
                row,
                userId,
                tenantIss,
                body.attenuation?.budgets,
                body.attenuation?.omit
            );
            await logMission(c.env.DB, tenantInfo.tenant, row.id, 'approval', { result: 'approved', s256 });
            return c.json({ ok: true, status: 'active', s256 });
        }

        // KV pendings (token / permission / interaction)
        const pending = resolved.pending!;
        const pendingId = resolved.pendingId!;
        await consumeCode(c.env.KV, tenantInfo.tenant, code);

        if (body.decision === 'deny') {
            pending.st = 'denied';
            if (pending.kind === 'permission') pending.result = { permission: 'denied' };
            await putPending(c.env.KV, tenantInfo.tenant, pendingId, pending);
            return c.json({ ok: true, status: 'denied' });
        }

        if (pending.kind === 'token') {
            const resource = String(pending.payload.resource);
            const scope = pending.payload.scope as string | undefined;
            const key = await getSigningKey(c.env.DB, c.env, tenantInfo.tenant);
            const minted = await mintAuthToken({
                key,
                iss: tenantIss,
                aud: resource,
                cnfJwk: pending.agent.jwk as any,
                scope,
                identity: { kind: 'base', sub: userId },
            });
            pending.st = 'approved';
            pending.result = { auth_token: minted.token, expires_in: minted.expiresIn };
            await putPending(c.env.KV, tenantInfo.tenant, pendingId, pending);
            if (body.remember) {
                await upsertGrant(
                    c.env.DB,
                    tenantInfo.tenant,
                    userId,
                    pending.agent.iss,
                    pending.agent.sub,
                    resource,
                    normalizeScope(scope)
                );
            }
            return c.json({ ok: true, status: 'approved' });
        }

        // Mission-bound pendings: the mission was active at creation time, but
        // the person may have revoked it (or it completed/expired) while this
        // sat awaiting consent — re-check liveness before granting anything.
        const missionStillActive = async (missionId: string | undefined): Promise<boolean> => {
            if (!missionId) return true; // not mission-bound
            const m = await getMissionById(c.env.DB, tenantInfo.tenant, missionId);
            return !!m && (await effectiveStatus(c.env.DB, m)) === 'active';
        };

        if (pending.kind === 'permission') {
            const missionId = pending.payload.missionId as string | undefined;
            if (!(await missionStillActive(missionId))) {
                pending.st = 'denied';
                pending.result = { permission: 'denied', reason: 'the mission is no longer active' };
                await putPending(c.env.KV, tenantInfo.tenant, pendingId, pending);
                return c.json({ ok: true, status: 'denied', error: 'mission_closed' });
            }
            pending.st = 'approved';
            pending.result = { permission: 'granted' };
            await putPending(c.env.KV, tenantInfo.tenant, pendingId, pending);
            if (missionId) {
                await logMission(c.env.DB, tenantInfo.tenant, missionId, 'permission', {
                    action: pending.payload.action,
                    result: 'granted',
                });
            }
            return c.json({ ok: true, status: 'approved' });
        }

        // interaction
        const type = pending.payload.type as string;
        const missionId = pending.payload.missionId as string | undefined;
        if (missionId && !(await missionStillActive(missionId))) {
            pending.st = 'denied';
            pending.result = { error: 'mission_closed', error_description: 'the mission is no longer active' };
            await putPending(c.env.KV, tenantInfo.tenant, pendingId, pending);
            return c.json({ ok: true, status: 'denied', error: 'mission_closed' });
        }
        if (type === 'completion' && missionId) {
            await closeMission(c.env.DB, missionId, 'completed');
            await logMission(c.env.DB, tenantInfo.tenant, missionId, 'completion', {
                summary: pending.payload.summary,
            });
        }
        pending.st = 'approved';
        pending.result =
            type === 'question'
                ? { response: (body.answer ?? '').slice(0, MAX_TEXT_LEN) }
                : { accepted: true };
        await putPending(c.env.KV, tenantInfo.tenant, pendingId, pending);
        return c.json({ ok: true, status: 'approved' });
    });

    // ------------------------------------------------------------------ //
    // Self-service: grants + missions (session-gated)

    app.get('/v1/aauth/grants', async (c) => {
        const userId = await sessionUser(c);
        if (!userId) return c.json({ error: 'not_authenticated' }, 401);
        const grants = await listGrants(c.env.DB, tenantInfo.tenant, userId);
        return c.json({
            grants: grants.map((g) => ({
                id: g.id,
                agent: { iss: g.agent_iss, sub: g.agent_sub },
                resource: g.resource,
                scope: g.scope,
                created_at: g.created_at,
                last_used_at: g.last_used_at,
                expires_at: g.expires_at,
            })),
        });
    });

    app.delete('/v1/aauth/grants/:id', async (c) => {
        const userId = await sessionUser(c);
        if (!userId) return c.json({ error: 'not_authenticated' }, 401);
        const ok = await revokeGrant(c.env.DB, tenantInfo.tenant, userId, c.req.param('id'));
        if (!ok) return c.json({ error: 'not_found' }, 404);
        return c.json({ success: true });
    });

    app.get('/v1/aauth/missions', async (c) => {
        const userId = await sessionUser(c);
        if (!userId) return c.json({ error: 'not_authenticated' }, 401);
        const { results } = await c.env.DB
            .prepare(
                'SELECT * FROM aauth_missions WHERE tenant = ? AND (user_id = ? OR approver_hint = ?) ORDER BY created_at DESC LIMIT 100'
            )
            .bind(tenantInfo.tenant, userId, userId)
            .all();
        const missions = [];
        for (const row of (results || []) as MissionRow[]) {
            const status = await effectiveStatus(c.env.DB, row);
            missions.push({
                id: row.id,
                s256: row.s256,
                status,
                agent: { iss: row.agent_iss, sub: row.agent_sub },
                proposal: JSON.parse(row.proposal_json),
                mission: row.mission_json ? JSON.parse(row.mission_json) : null,
                created_at: row.created_at,
                approved_at: row.approved_at,
                log: await missionLog(c.env.DB, tenantInfo.tenant, row.id, 10),
            });
        }
        return c.json({ missions });
    });

    app.post('/v1/aauth/missions/:id/revoke', async (c) => {
        const userId = await sessionUser(c);
        if (!userId) return c.json({ error: 'not_authenticated' }, 401);
        const row = await getMissionById(c.env.DB, tenantInfo.tenant, c.req.param('id'));
        if (!row || row.user_id !== userId) return c.json({ error: 'not_found' }, 404);
        if (row.status !== 'active') return c.json({ error: 'invalid_request', error_description: 'mission is not active' }, 400);
        await closeMission(c.env.DB, row.id, 'revoked');
        await logMission(c.env.DB, tenantInfo.tenant, row.id, 'revocation', {});
        return c.json({ success: true });
    });

    return app;
}
