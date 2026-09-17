// Tenant signing keys: KEK wrap/unwrap roundtrip, dev-KEK fallback, kek_id
// mismatch (secret set/rotated) retiring and regenerating, JWKS shape. Backed
// by a tiny in-memory stand-in for the ps_keys table.

import { describe, test, expect } from 'bun:test';

import { ensureTenantJwks, getSigningKey, getTenantJwks } from '../src/aauth/pskeys';

type Row = {
    kid: string;
    tenant: string;
    public_jwk: string;
    private_wrapped: string;
    kek_id: string;
    created_at: number;
    retired_at: number | null;
};

/** Just enough D1 for pskeys.ts' four statements. */
function fakeDb(): { db: D1Database; rows: Row[] } {
    const rows: Row[] = [];
    const active = (tenant: string) =>
        rows
            .filter((r) => r.tenant === tenant && r.retired_at === null)
            .sort((a, b) => a.created_at - b.created_at || a.kid.localeCompare(b.kid));
    const db = {
        prepare(sql: string) {
            return {
                bind(...args: unknown[]) {
                    return {
                        async all() {
                            if (sql.includes('retired_at IS NULL OR retired_at >')) {
                                const [tenant, cutoff] = args as [string, number];
                                return {
                                    results: rows.filter(
                                        (r) => r.tenant === tenant && (r.retired_at === null || r.retired_at > cutoff)
                                    ),
                                };
                            }
                            return { results: active(args[0] as string) };
                        },
                        async first() {
                            return active(args[0] as string)[0] ?? null;
                        },
                        async run() {
                            if (sql.startsWith('INSERT OR IGNORE')) {
                                const [kid, tenant, public_jwk, private_wrapped, kek_id, created_at] = args as [
                                    string, string, string, string, string, number,
                                ];
                                // Mirrors 0006: kid PK + one active row per tenant.
                                if (!rows.some((r) => r.kid === kid) && active(tenant).length === 0) {
                                    rows.push({ kid, tenant, public_jwk, private_wrapped, kek_id, created_at, retired_at: null });
                                }
                            } else if (sql.startsWith('UPDATE ps_keys SET retired_at')) {
                                const [retiredAt, kid] = args as [number, string];
                                const row = rows.find((r) => r.kid === kid);
                                if (row) row.retired_at = retiredAt;
                            }
                            return { meta: { changes: 1 } };
                        },
                    };
                },
            };
        },
    };
    return { db: db as unknown as D1Database, rows };
}

describe('pskeys', () => {
    test('generates on first use, then unwraps the SAME key (dev KEK fallback)', async () => {
        const { db, rows } = fakeDb();
        const a = await getSigningKey(db, {}, 'example.com');
        expect(rows).toHaveLength(1);
        expect(rows[0].kek_id).toBe('dev');
        // Wrapped blob must not contain the raw private key material in the clear:
        // unwrapping must require the KEK (roundtrip proves decrypt works).
        const b = await getSigningKey(db, {}, 'example.com');
        expect(rows).toHaveLength(1);
        expect(b.kid).toBe(a.kid);
        expect(b.publicJwk).toEqual(a.publicJwk);
        // The unwrapped key signs; the stored public half verifies.
        const data = new TextEncoder().encode('probe');
        const sig = await crypto.subtle.sign({ name: 'Ed25519' }, b.privateKey, data as BufferSource);
        const pub = await crypto.subtle.importKey(
            'jwk', { kty: 'OKP', crv: 'Ed25519', x: a.publicJwk.x }, { name: 'Ed25519' }, false, ['verify']
        );
        expect(await crypto.subtle.verify({ name: 'Ed25519' }, pub, sig, data as BufferSource)).toBe(true);
    });

    test('tenants are isolated', async () => {
        const { db } = fakeDb();
        const a = await getSigningKey(db, {}, 'a.com');
        const b = await getSigningKey(db, {}, 'b.com');
        expect(a.kid).not.toBe(b.kid);
    });

    test('setting PS_KEK retires dev-wrapped keys and regenerates', async () => {
        const { db, rows } = fakeDb();
        const devKey = await getSigningKey(db, {}, 'example.com');
        const prodKey = await getSigningKey(db, { PS_KEK: 'super-secret-value' }, 'example.com');
        expect(prodKey.kid).not.toBe(devKey.kid);
        expect(rows.find((r) => r.kid === devKey.kid)!.retired_at).not.toBeNull();
        expect(rows.find((r) => r.kid === prodKey.kid)!.kek_id).not.toBe('dev');
        // Same secret → same key again.
        const again = await getSigningKey(db, { PS_KEK: 'super-secret-value' }, 'example.com');
        expect(again.kid).toBe(prodKey.kid);
    });

    test('JWKS includes active and recently-retired public keys with kid/alg/use', async () => {
        const { db } = fakeDb();
        const devKey = await getSigningKey(db, {}, 'example.com');
        await getSigningKey(db, { PS_KEK: 's' }, 'example.com'); // retires devKey
        const jwks = await getTenantJwks(db, 'example.com');
        expect(jwks.keys).toHaveLength(2); // retired one still within the serving window
        for (const k of jwks.keys) {
            expect(k.kid).toBeDefined();
            expect(k.alg).toBe('EdDSA');
            expect(k.use).toBe('sig');
            expect((k as any).d).toBeUndefined(); // never a private member
        }
        expect(jwks.keys.some((k) => k.kid === devKey.kid)).toBe(true);
    });

    test('ensureTenantJwks provisions a key on first discovery read', async () => {
        const { db, rows } = fakeDb();
        const jwks = await ensureTenantJwks(db, {}, 'example.com', true);
        expect(jwks.keys).toHaveLength(1);
        expect(rows).toHaveLength(1);
        // Subsequent reads serve the same key without minting another.
        const again = await ensureTenantJwks(db, {}, 'example.com', true);
        expect(again.keys).toHaveLength(1);
        expect(again.keys[0].kid).toBe(jwks.keys[0].kid);
        expect(rows).toHaveLength(1);
        // The minted key is the one getSigningKey signs with.
        const signer = await getSigningKey(db, {}, 'example.com');
        expect(signer.kid).toBe(jwks.keys[0].kid);
    });

    test('ensureTenantJwks does NOT mint when disallowed (nonexistent sandbox)', async () => {
        const { db, rows } = fakeDb();
        const jwks = await ensureTenantJwks(db, {}, 'sandbox.authgravity.org/made-up', false);
        expect(jwks.keys).toHaveLength(0);
        expect(rows).toHaveLength(0);
    });
});
