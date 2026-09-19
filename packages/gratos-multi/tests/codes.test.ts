import { describe, expect, test } from 'bun:test';
import { Database } from 'bun:sqlite';
import { readFileSync } from 'node:fs';
import {
    generateCode,
    startTicket as start,
    mintCode as mint,
    verifyCode as verify,
    MAX_MINTS,
    MAX_TRIES,
    USER_MINTS_PER_HOUR,
} from '../src/codes';

// Just enough of D1 over bun:sqlite to run the real SQL (RETURNING included).
function fakeD1() {
    const sqlite = new Database(':memory:');
    sqlite.exec(readFileSync(new URL('../migrations/0009_code_tickets.sql', import.meta.url), 'utf8'));
    const stmt = (sql: string, args: any[] = []) => ({
        bind: (...a: any[]) => stmt(sql, a),
        first: async () => (sqlite.query(sql).get(...args) as any) ?? null,
        run: async () => ({ meta: { changes: sqlite.query(sql).run(...args).changes } }),
        all: async () => ({ results: sqlite.query(sql).all(...args) }),
    });
    return {
        sqlite,
        db: {
            prepare: (sql: string) => stmt(sql),
            batch: async (stmts: any[]) => Promise.all(stmts.map((s) => s.run())),
        } as any,
    };
}

function fakeKv() {
    const store = new Map<string, string>();
    return {
        get: async (k: string) => store.get(k) ?? null,
        put: async (k: string, v: string) => void store.set(k, v),
    } as any;
}

// One pool per test: D1 for tickets, KV for the per-user soft cap.
function pool() {
    const { db, sqlite } = fakeD1();
    const kv = fakeKv();
    return {
        sqlite,
        startTicket: (tenant: string, now?: number) => start(db, tenant, now),
        mintCode: (tenant: string, ticket: string, userId: string, now?: number) => mint(db, kv, tenant, ticket, userId, now),
        verifyCode: (tenant: string, ticket: string, verifier: string, code: string, now?: number) =>
            verify(db, tenant, ticket, verifier, code, now),
    };
}

const wrong = (code: string) => String((Number(code) + 1) % 1_000_000).padStart(6, '0');

describe('generateCode', () => {
    test('always six digits', () => {
        for (let i = 0; i < 1000; i++) expect(generateCode()).toMatch(/^\d{6}$/);
    });
});

describe('code ceremony', () => {
    test('start → mint → verify signs in exactly once', async () => {
        const p = pool();
        const { ticket, verifier } = await p.startTicket('t');
        const minted = await p.mintCode('t', ticket, 'u1');
        if ('error' in minted) throw new Error(minted.error);
        expect(await p.verifyCode('t', ticket, verifier, minted.code)).toEqual({ userId: 'u1' });
        expect(await p.verifyCode('t', ticket, verifier, minted.code)).toMatchObject({ status: 400 });
    });

    test('a leaked code is useless without the starting browser\u2019s verifier (and spends no try)', async () => {
        const p = pool();
        const { ticket, verifier } = await p.startTicket('t');
        const minted = (await p.mintCode('t', ticket, 'u1')) as { code: string };
        for (let i = 0; i < MAX_TRIES + 2; i++) {
            expect(await p.verifyCode('t', ticket, 'attacker-verifier', minted.code)).toMatchObject({ status: 400 });
        }
        expect(await p.verifyCode('t', ticket, verifier, minted.code)).toEqual({ userId: 'u1' });
    });

    test('tickets are tenant-scoped', async () => {
        const p = pool();
        const { ticket, verifier } = await p.startTicket('a.com');
        expect(await p.mintCode('b.com', ticket, 'u1')).toMatchObject({ status: 404 });
        const minted = (await p.mintCode('a.com', ticket, 'u1')) as { code: string };
        expect(await p.verifyCode('b.com', ticket, verifier, minted.code)).toMatchObject({ status: 400 });
    });

    test('verify before any code was minted fails', async () => {
        const p = pool();
        const { ticket, verifier } = await p.startTicket('t');
        expect(await p.verifyCode('t', ticket, verifier, '123456')).toMatchObject({ status: 400 });
    });

    test(`the ticket burns after ${MAX_TRIES} wrong codes`, async () => {
        const p = pool();
        const { ticket, verifier } = await p.startTicket('t');
        const { code } = (await p.mintCode('t', ticket, 'u1')) as { code: string };
        for (let i = 0; i < MAX_TRIES; i++) await p.verifyCode('t', ticket, verifier, wrong(code));
        expect(await p.verifyCode('t', ticket, verifier, code)).toMatchObject({ status: 400 });
    });

    test('parallel guesses cannot exceed the attempt budget, and one code yields one session', async () => {
        const p = pool();
        const { ticket, verifier } = await p.startTicket('t');
        const { code } = (await p.mintCode('t', ticket, 'u1')) as { code: string };
        const guesses = Array.from({ length: 50 }, (_, i) => (i === 49 ? code : wrong(code)));
        const results = await Promise.all(guesses.map((g) => p.verifyCode('t', ticket, verifier, g)));
        // The right code came last: every attempt slot was spent before it.
        expect(results.filter((r) => 'userId' in r)).toHaveLength(0);

        const t2 = await p.startTicket('t');
        const c2 = (await p.mintCode('t', t2.ticket, 'u1')) as { code: string };
        const wins = await Promise.all(Array.from({ length: 5 }, () => p.verifyCode('t', t2.ticket, t2.verifier, c2.code)));
        expect(wins.filter((r) => 'userId' in r)).toHaveLength(1);
    });

    test('a resend replaces the code and resets tries, up to the mint cap', async () => {
        const p = pool();
        const { ticket, verifier } = await p.startTicket('t');
        const first = (await p.mintCode('t', ticket, 'u1')) as { code: string };
        for (let i = 0; i < MAX_TRIES - 1; i++) await p.verifyCode('t', ticket, verifier, wrong(first.code));
        let latest = first;
        for (let i = 1; i < MAX_MINTS; i++) latest = (await p.mintCode('t', ticket, 'u1')) as { code: string };
        expect(await p.mintCode('t', ticket, 'u1')).toMatchObject({ status: 429 });
        if (latest.code !== first.code) {
            expect(await p.verifyCode('t', ticket, verifier, first.code)).toMatchObject({ status: 400 });
        }
        expect(await p.verifyCode('t', ticket, verifier, latest.code)).toEqual({ userId: 'u1' });
    });

    test('a ticket is bound to the first user a code was minted for', async () => {
        const p = pool();
        const { ticket } = await p.startTicket('t');
        await p.mintCode('t', ticket, 'u1');
        expect(await p.mintCode('t', ticket, 'u2')).toMatchObject({ status: 400 });
    });

    test(`per-user cap of ${USER_MINTS_PER_HOUR} codes an hour across tickets`, async () => {
        const p = pool();
        for (let i = 0; i < USER_MINTS_PER_HOUR; i++) {
            const { ticket } = await p.startTicket('t');
            expect(await p.mintCode('t', ticket, 'u1')).toHaveProperty('code');
        }
        const { ticket } = await p.startTicket('t');
        expect(await p.mintCode('t', ticket, 'u1')).toMatchObject({ status: 429 });
    });

    test('expired tickets refuse both mint and verify', async () => {
        const p = pool();
        const t0 = 1_000_000;
        const { ticket, verifier } = await p.startTicket('t', t0);
        const { code } = (await p.mintCode('t', ticket, 'u1', t0)) as { code: string };
        const later = t0 + 601_000;
        expect(await p.verifyCode('t', ticket, verifier, code, later)).toMatchObject({ status: 400 });
        expect(await p.mintCode('t', ticket, 'u1', later)).toMatchObject({ status: 404 });
    });

    test('only hashes are stored', async () => {
        const p = pool();
        const { ticket, verifier } = await p.startTicket('t');
        const { code } = (await p.mintCode('t', ticket, 'u1')) as { code: string };
        const raw = JSON.stringify(p.sqlite.query('SELECT * FROM code_tickets').all());
        expect(raw).not.toContain(verifier);
        expect(raw).not.toContain(`"${code}"`);
    });
});
