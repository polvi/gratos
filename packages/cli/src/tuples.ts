// `authgravity tuples import <file>` — bulk relationship import.
//
// Migration day: adopters always have existing data to load, but the write
// endpoint caps a batch at 100 atomic updates. This chunks a file of updates
// into ≤100-update batches (each its own transaction) with a --dry-run preview.

import { readFileSync } from 'node:fs';
import type { RelUpdate } from '@authgravity/server';
import { parseArgs, flagStr, flagBool } from './args';

const WRITE_CHUNK = 100; // server MAX_UPDATES
const OPS = new Set(['touch', 'create', 'delete']);

export const TUPLES_USAGE = `authgravity tuples import <file> [options]

  Bulk-import relationship updates from a JSON file. The file is either an array
  of updates or an object { "updates": [...] }, each update:
    { "op": "touch"|"create"|"delete", "object": "type:id", "relation": "...", "subject": "type:id[#rel]" }

Options:
  --endpoint <url>   Tenant auth endpoint (or env PUBLIC_AUTH_ENDPOINT)
  --token <agk_...>  Service token (or env AUTHGRAVITY_SERVICE_TOKEN)
  --dry-run          Validate and preview the import plan without writing
  -h, --help         Show this help
`;

/** Validate + normalize the file contents into a flat RelUpdate[]. Pure. */
export function normalizeUpdates(parsed: unknown): RelUpdate[] {
    const arr = Array.isArray(parsed)
        ? parsed
        : parsed && typeof parsed === 'object' && Array.isArray((parsed as any).updates)
          ? (parsed as any).updates
          : null;
    if (!arr) {
        throw new Error('file must be an array of updates or { "updates": [...] }');
    }
    return arr.map((u: any, i: number): RelUpdate => {
        if (!u || typeof u !== 'object') throw new Error(`updates[${i}] is not an object`);
        if (!OPS.has(u.op)) throw new Error(`updates[${i}].op must be touch|create|delete`);
        for (const f of ['object', 'relation', 'subject'] as const) {
            if (typeof u[f] !== 'string' || !u[f]) throw new Error(`updates[${i}].${f} must be a non-empty string`);
        }
        return { op: u.op, object: u.object, relation: u.relation, subject: u.subject };
    });
}

export function chunk<T>(arr: T[], size: number): T[][] {
    const out: T[][] = [];
    for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
    return out;
}

/** Per-op counts for the dry-run preview. Pure. */
export function planSummary(updates: RelUpdate[]): { total: number; chunks: number; byOp: Record<string, number> } {
    const byOp: Record<string, number> = {};
    for (const u of updates) byOp[u.op] = (byOp[u.op] ?? 0) + 1;
    return { total: updates.length, chunks: chunk(updates, WRITE_CHUNK).length, byOp };
}

export async function runTuplesImport(args: string[]) {
    const { positionals, flags } = parseArgs(args);
    if (flagBool(flags, 'help', 'h')) {
        console.log(TUPLES_USAGE);
        return;
    }
    const file = positionals[0];
    if (!file) {
        console.error('Missing <file>.\n');
        console.error(TUPLES_USAGE);
        process.exit(1);
    }
    const endpoint = flagStr(flags, 'endpoint') || process.env.PUBLIC_AUTH_ENDPOINT;
    if (!endpoint) {
        console.error('No endpoint: pass --endpoint or set PUBLIC_AUTH_ENDPOINT.');
        process.exit(1);
    }
    const token = flagStr(flags, 'token') || process.env.AUTHGRAVITY_SERVICE_TOKEN;

    let updates: RelUpdate[];
    try {
        updates = normalizeUpdates(JSON.parse(readFileSync(file, 'utf8')));
    } catch (e) {
        console.error(`Failed to read ${file}: ${(e as Error).message}`);
        process.exit(1);
    }

    const plan = planSummary(updates);
    const opsLine = Object.entries(plan.byOp)
        .map(([op, n]) => `${n} ${op}`)
        .join(', ');
    console.log(`${plan.total} updates (${opsLine}) → ${plan.chunks} chunk(s) of ≤${WRITE_CHUNK}`);

    if (flagBool(flags, 'dry-run')) {
        console.log('Dry run — nothing written.');
        return;
    }
    if (!token) {
        console.error('No service token: pass --token or set AUTHGRAVITY_SERVICE_TOKEN.');
        process.exit(1);
    }

    let written = 0;
    let deleted = 0;
    const batches = chunk(updates, WRITE_CHUNK);
    for (let i = 0; i < batches.length; i++) {
        const res = await fetch(`${endpoint}/v1/authz/relationships`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ updates: batches[i] }),
        });
        if (!res.ok) {
            console.error(`\nChunk ${i + 1}/${batches.length} failed (${res.status}): ${await res.text()}`);
            console.error(`Imported ${written} written / ${deleted} deleted before the failure.`);
            process.exit(1);
        }
        const data = (await res.json()) as { written?: number; deleted?: number };
        written += data.written ?? 0;
        deleted += data.deleted ?? 0;
        process.stdout.write(`\r  chunk ${i + 1}/${batches.length}`);
    }
    console.log(`\n✔ Imported: ${written} written, ${deleted} deleted.`);
}
