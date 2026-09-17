// Missions: scoped authorization contexts for agent governance, with the
// AAuth-Budget extension (entries a consenting person may only NARROW) and a
// D1-backed proposal window measured in days — consent is asynchronous and the
// approver is often not the proposer (third-party approval; freeweight R3).
//
// draft-01 leaves the proposal body and mission canonicalization open; the
// shapes here are our concrete interpretation, pinned by the seam contract:
// s256 = sha256 over the EXACT approved-mission bytes as serialized/stored
// here (no JCS — we hash what we store, byte-for-byte).

import { AAuthError, sha256B64u } from './encoding';
import type { BudgetEntry, MissionRef } from './jwt';
import { generateCode } from './pending';

const DEFAULT_PROPOSAL_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_PROPOSAL_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_TEXT = 16 * 1024;

export type MissionStatus = 'proposed' | 'active' | 'completed' | 'declined' | 'revoked' | 'expired';

export type MissionProposal = {
    description: string;
    approved_tools?: string[];
    resources?: Array<{ resource: string; scope?: string }>;
    budgets?: BudgetEntry[];
    /** Intended approver (tenant-scoped user UUID). Absent → code-holder approves. */
    approver?: string;
    /** Proposal window in seconds (default 7d, max 30d). */
    expires_in?: number;
};

export type ApprovedMission = {
    description: string;
    approved_tools?: string[];
    resources?: Array<{ resource: string; scope?: string }>;
    budgets?: BudgetEntry[];
    agent: { iss: string; sub: string };
    approver: string; // the PS tenant iss
    approved_at: number;
};

export type MissionRow = {
    id: string;
    s256: string | null;
    tenant: string;
    user_id: string | null;
    approver_hint: string | null;
    agent_iss: string;
    agent_sub: string;
    agent_jwk: string;
    proposal_json: string;
    mission_json: string | null;
    code_hash: string | null;
    status: MissionStatus;
    created_at: number;
    expires_at: number;
    approved_at: number | null;
    closed_at: number | null;
};

/** Attenuation submitted at consent: per-entry new amount / models subset. */
export type BudgetAttenuation = Array<{ resource: string; amount?: string; models?: string[] }>;

const DECIMAL_RE = /^(0|[1-9]\d*)(\.\d{1,6})?$/;
const CURRENCY_RE = /^[A-Z]{3}$/;

function isHttpsUrl(s: string): boolean {
    try {
        const u = new URL(s);
        return u.protocol === 'https:' || (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname.endsWith('.localhost')));
    } catch {
        return false;
    }
}

function amountValue(s: string): number {
    return parseFloat(s);
}

export function validateBudgets(budgets: unknown): BudgetEntry[] {
    if (!Array.isArray(budgets)) throw new AAuthError('invalid_request', 'budgets must be an array');
    const seen = new Set<string>();
    return budgets.map((raw) => {
        const e = raw as Partial<BudgetEntry>;
        if (typeof e.resource !== 'string' || !isHttpsUrl(e.resource)) {
            throw new AAuthError('invalid_request', 'budget entry resource must be an https URL');
        }
        if (seen.has(e.resource)) {
            throw new AAuthError('invalid_request', 'at most one budget entry per resource');
        }
        seen.add(e.resource);
        if (typeof e.amount !== 'string' || !DECIMAL_RE.test(e.amount) || amountValue(e.amount) <= 0) {
            throw new AAuthError('invalid_request', 'budget amount must be a positive decimal string');
        }
        if (typeof e.currency !== 'string' || !CURRENCY_RE.test(e.currency) || e.currency === 'XTS' || e.currency === 'XXX') {
            throw new AAuthError('invalid_request', 'budget currency must be an ISO 4217 code (not XTS/XXX)');
        }
        const entry: BudgetEntry = { resource: e.resource, amount: e.amount, currency: e.currency };
        if (e.models !== undefined) {
            if (
                !Array.isArray(e.models) ||
                e.models.length === 0 ||
                e.models.some((m) => typeof m !== 'string' || !m) ||
                new Set(e.models).size !== e.models.length
            ) {
                throw new AAuthError('invalid_request', 'models must be a non-empty array of unique strings');
            }
            entry.models = e.models;
        }
        return entry;
    });
}

export function validateProposal(raw: unknown): MissionProposal {
    const body = (raw ?? {}) as Record<string, unknown>;
    const mission = (body.mission ?? {}) as Record<string, unknown>;
    if (typeof mission.description !== 'string' || !mission.description.trim()) {
        throw new AAuthError('invalid_request', 'mission.description is required');
    }
    if (mission.description.length > MAX_TEXT) {
        throw new AAuthError('invalid_request', 'mission.description too long');
    }
    const out: MissionProposal = { description: mission.description };
    if (mission.approved_tools !== undefined) {
        if (!Array.isArray(mission.approved_tools) || mission.approved_tools.some((t) => typeof t !== 'string')) {
            throw new AAuthError('invalid_request', 'approved_tools must be an array of strings');
        }
        out.approved_tools = mission.approved_tools as string[];
    }
    if (mission.resources !== undefined) {
        if (!Array.isArray(mission.resources)) throw new AAuthError('invalid_request', 'resources must be an array');
        out.resources = (mission.resources as Array<Record<string, unknown>>).map((r) => {
            if (typeof r.resource !== 'string' || !isHttpsUrl(r.resource)) {
                throw new AAuthError('invalid_request', 'resources entries need an https resource URL');
            }
            return { resource: r.resource, scope: typeof r.scope === 'string' ? r.scope : undefined };
        });
    }
    if (mission.budgets !== undefined) out.budgets = validateBudgets(mission.budgets);
    if (mission.approver !== undefined) {
        if (typeof mission.approver !== 'string' || !mission.approver) {
            throw new AAuthError('invalid_request', 'approver must be a user id string');
        }
        out.approver = mission.approver;
    }
    if (mission.expires_in !== undefined) {
        const s = Number(mission.expires_in);
        if (!Number.isFinite(s) || s <= 0 || s * 1000 > MAX_PROPOSAL_TTL_MS) {
            throw new AAuthError('invalid_request', 'expires_in must be positive and at most 30 days');
        }
        out.expires_in = s;
    }
    return out;
}

/**
 * Apply consent-time attenuation to proposed budgets. Narrowing only (seam
 * §3 / TPX-A): entries may be omitted, amounts may only decrease, currency is
 * fixed, models may only shrink — and may be ADDED when the proposal had none.
 * `attenuation` entries are matched by exact resource; entries of the proposal
 * absent from `attenuation` are granted as proposed, unless `omit` lists them.
 */
export function applyAttenuation(
    proposed: BudgetEntry[],
    attenuation: BudgetAttenuation | undefined,
    omit: string[] | undefined
): BudgetEntry[] {
    const byResource = new Map((attenuation ?? []).map((a) => [a.resource, a]));
    for (const a of byResource.keys()) {
        if (!proposed.some((p) => p.resource === a)) {
            throw new AAuthError('invalid_request', 'attenuation may not add budget entries');
        }
    }
    const omitted = new Set(omit ?? []);
    const granted: BudgetEntry[] = [];
    for (const p of proposed) {
        if (omitted.has(p.resource)) continue;
        const a = byResource.get(p.resource);
        const entry: BudgetEntry = { resource: p.resource, amount: p.amount, currency: p.currency };
        if (p.models) entry.models = p.models;
        if (a) {
            if (a.amount !== undefined) {
                if (!DECIMAL_RE.test(a.amount) || amountValue(a.amount) <= 0) {
                    throw new AAuthError('invalid_request', 'attenuated amount must be a positive decimal string');
                }
                if (amountValue(a.amount) > amountValue(p.amount)) {
                    throw new AAuthError('invalid_request', 'attenuated amount may not exceed the proposed amount');
                }
                entry.amount = a.amount;
            }
            if (a.models !== undefined) {
                if (!Array.isArray(a.models) || a.models.length === 0 || new Set(a.models).size !== a.models.length) {
                    throw new AAuthError('invalid_request', 'attenuated models must be a non-empty unique array');
                }
                if (p.models && !a.models.every((m) => p.models!.includes(m))) {
                    throw new AAuthError('invalid_request', 'attenuated models must be a subset of the proposed models');
                }
                entry.models = a.models;
            }
        }
        granted.push(entry);
    }
    return granted;
}

export async function proposeMission(
    db: D1Database,
    tenant: string,
    agent: { iss: string; sub: string; jwk: unknown },
    proposal: MissionProposal
): Promise<{ id: string; code: string; expiresAt: number }> {
    const id = crypto.randomUUID();
    const code = generateCode();
    const codeHash = await sha256B64u(code.toUpperCase());
    const now = Date.now();
    const expiresAt = now + (proposal.expires_in ? proposal.expires_in * 1000 : DEFAULT_PROPOSAL_TTL_MS);
    await db
        .prepare(
            `INSERT INTO aauth_missions (id, tenant, approver_hint, agent_iss, agent_sub, agent_jwk, proposal_json, code_hash, status, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?)`
        )
        .bind(id, tenant, proposal.approver ?? null, agent.iss, agent.sub, JSON.stringify(agent.jwk), JSON.stringify(proposal), codeHash, now, expiresAt)
        .run();
    return { id, code, expiresAt };
}

export async function getMissionById(db: D1Database, tenant: string, id: string): Promise<MissionRow | null> {
    return (await db
        .prepare('SELECT * FROM aauth_missions WHERE tenant = ? AND id = ?')
        .bind(tenant, id)
        .first()) as MissionRow | null;
}

export async function getMissionByS256(db: D1Database, tenant: string, s256: string): Promise<MissionRow | null> {
    return (await db
        .prepare('SELECT * FROM aauth_missions WHERE tenant = ? AND s256 = ?')
        .bind(tenant, s256)
        .first()) as MissionRow | null;
}

export async function getMissionByCode(db: D1Database, tenant: string, code: string): Promise<MissionRow | null> {
    const codeHash = await sha256B64u(code.toUpperCase());
    return (await db
        .prepare('SELECT * FROM aauth_missions WHERE tenant = ? AND code_hash = ?')
        .bind(tenant, codeHash)
        .first()) as MissionRow | null;
}

/** Lazily expire an overdue proposal; returns the (possibly updated) status. */
export async function effectiveStatus(db: D1Database, row: MissionRow): Promise<MissionStatus> {
    if (row.status === 'proposed' && row.expires_at < Date.now()) {
        await db
            .prepare("UPDATE aauth_missions SET status = 'expired', code_hash = NULL, closed_at = ? WHERE id = ? AND status = 'proposed'")
            .bind(Date.now(), row.id)
            .run();
        return 'expired';
    }
    return row.status;
}

/**
 * Approve: build the canonical approved blob, serialize ONCE, hash those exact
 * bytes. The consent code is cleared (single-use).
 */
export async function approveMission(
    db: D1Database,
    tenant: string,
    row: MissionRow,
    userId: string,
    tenantIss: string,
    attenuation: BudgetAttenuation | undefined,
    omit: string[] | undefined
): Promise<{ s256: string; mission: ApprovedMission; missionJson: string }> {
    const proposal = JSON.parse(row.proposal_json) as MissionProposal;
    const mission: ApprovedMission = {
        description: proposal.description,
        agent: { iss: row.agent_iss, sub: row.agent_sub },
        approver: tenantIss,
        approved_at: Date.now(),
    };
    if (proposal.approved_tools) mission.approved_tools = proposal.approved_tools;
    if (proposal.resources) mission.resources = proposal.resources;
    if (proposal.budgets) {
        const granted = applyAttenuation(proposal.budgets, attenuation, omit);
        if (granted.length > 0) mission.budgets = granted;
    }
    const missionJson = JSON.stringify(mission);
    const s256 = await sha256B64u(missionJson);
    await db
        .prepare(
            "UPDATE aauth_missions SET s256 = ?, mission_json = ?, user_id = ?, status = 'active', approved_at = ?, code_hash = NULL WHERE id = ? AND status = 'proposed'"
        )
        .bind(s256, missionJson, userId, Date.now(), row.id)
        .run();
    return { s256, mission, missionJson };
}

export async function declineMission(db: D1Database, row: MissionRow, userId: string): Promise<void> {
    await db
        .prepare("UPDATE aauth_missions SET status = 'declined', user_id = ?, code_hash = NULL, closed_at = ? WHERE id = ? AND status = 'proposed'")
        .bind(userId, Date.now(), row.id)
        .run();
}

export async function closeMission(db: D1Database, id: string, status: 'completed' | 'revoked'): Promise<void> {
    await db
        .prepare("UPDATE aauth_missions SET status = ?, closed_at = ? WHERE id = ? AND status = 'active'")
        .bind(status, Date.now(), id)
        .run();
}

/**
 * Resolve a mission ref presented by an agent and require it active. Distinct
 * lifecycle errors (seam §7) so a harness learns promptly why access stopped.
 */
export async function requireActiveMission(
    db: D1Database,
    tenant: string,
    ref: MissionRef,
    agent: { iss: string; sub: string },
    tenantIss: string
): Promise<MissionRow> {
    if (ref.approver !== tenantIss) {
        throw new AAuthError('invalid_request', 'mission approver is not this Person Server', 403);
    }
    const row = await getMissionByS256(db, tenant, ref.s256);
    if (!row) throw new AAuthError('mission_expired', 'no mission with that s256', 404);
    if (row.agent_iss !== agent.iss || row.agent_sub !== agent.sub) {
        throw new AAuthError('invalid_request', 'mission belongs to a different agent', 403);
    }
    const status = await effectiveStatus(db, row);
    if (status === 'active') return row;
    if (status === 'revoked') throw new AAuthError('mission_revoked', 'the approver revoked this mission', 403);
    if (status === 'completed') throw new AAuthError('mission_completed', 'this mission is complete', 403);
    throw new AAuthError('mission_expired', 'this mission is no longer active', 403);
}

/** The granted budget entry whose resource matches — matched by resource token `iss` (seam §3). */
export function budgetEntryFor(missionJson: string, resource: string): BudgetEntry | null {
    const mission = JSON.parse(missionJson) as ApprovedMission;
    return mission.budgets?.find((b) => b.resource === resource) ?? null;
}

export async function logMission(
    db: D1Database,
    tenant: string,
    missionId: string,
    kind: string,
    entry: Record<string, unknown>
): Promise<void> {
    await db
        .prepare('INSERT INTO aauth_mission_log (tenant, mission_id, at, kind, entry_json) VALUES (?, ?, ?, ?, ?)')
        .bind(tenant, missionId, Date.now(), kind, JSON.stringify(entry))
        .run();
}

export async function missionLog(
    db: D1Database,
    tenant: string,
    missionId: string,
    limit = 100
): Promise<Array<{ at: number; kind: string; entry: Record<string, unknown> }>> {
    const { results } = await db
        .prepare('SELECT at, kind, entry_json FROM aauth_mission_log WHERE tenant = ? AND mission_id = ? ORDER BY id DESC LIMIT ?')
        .bind(tenant, missionId, limit)
        .all();
    return ((results || []) as Array<{ at: number; kind: string; entry_json: string }>)
        .map((r) => ({ at: r.at, kind: r.kind, entry: JSON.parse(r.entry_json) }))
        .reverse();
}

/** Mark overdue proposals expired (called from the provisioner cron). */
export async function expireSweep(db: D1Database): Promise<number> {
    const res = await db
        .prepare("UPDATE aauth_missions SET status = 'expired', code_hash = NULL, closed_at = ? WHERE status = 'proposed' AND expires_at < ?")
        .bind(Date.now(), Date.now())
        .run();
    return res.meta?.changes ?? 0;
}
