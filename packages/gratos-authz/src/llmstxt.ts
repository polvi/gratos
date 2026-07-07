// Per-tenant /llms.txt: a copy-paste-able integration guide for AI agents,
// rendered from the tenant's LIVE schema. Served unauthenticated on the
// tenant's own auth host (the schema is structure, like API docs — the
// relationship data itself stays session-gated).

import { PermissionExpr, StoredSchema, SubjectTypeRef } from './schema';

/** Render a permission expression compactly: "viewer | editor | parent->view". */
export function fmtExpr(expr: PermissionExpr): string {
    if ('rel' in expr) return expr.rel;
    if ('arrow' in expr) return `${expr.arrow.via}->${expr.arrow.permission}`;
    if ('union' in expr) return expr.union.map(wrap).join(' | ');
    if ('intersection' in expr) return expr.intersection.map(wrap).join(' & ');
    return `${wrap(expr.exclusion.base)} minus ${wrap(expr.exclusion.subtract)}`;
}

function wrap(expr: PermissionExpr): string {
    const s = fmtExpr(expr);
    return 'rel' in expr || 'arrow' in expr ? s : `(${s})`;
}

function fmtSubjects(subjects: SubjectTypeRef[]): string {
    return subjects.map((s) => (s.relation ? `${s.type}#${s.relation}` : s.type)).join(', ');
}

export function buildTenantLlmsTxt(
    tenant: string,
    stored: StoredSchema | null,
    mode: 'open-sandbox' | 'managed'
): string {
    const defs = stored?.doc.definitions ?? {};
    const typeNames = Object.keys(defs);

    // Pick a realistic example from the live schema for the curl samples.
    let exampleObject = 'document:readme';
    let examplePermission = 'view';
    let exampleRelation = 'viewer';
    for (const [typeName, def] of Object.entries(defs)) {
        const perms = Object.keys(def.permissions ?? {});
        const rels = Object.keys(def.relations ?? {});
        if (perms.length && rels.length) {
            exampleObject = `${typeName}:example-id`;
            examplePermission = perms[0];
            exampleRelation = rels[0];
            break;
        }
    }

    const lines: string[] = [];
    lines.push(`# Authorization for ${tenant}`);
    lines.push('');
    lines.push(
        `> Relationship-based access control (Zanzibar-style) for ${tenant}, served on this host by AuthGravity. Subjects are the AuthGravity user UUIDs of this tenant's passkey users — the same \`user_id\` returned by \`GET /v1/whoami\` on this host. Passkey login/registration for this host is documented at https://authgravity.org/llms.txt.`
    );
    lines.push('');

    lines.push('## The schema');
    lines.push('');
    if (!stored || typeNames.length === 0) {
        lines.push(
            'No schema is defined yet. ' +
                (mode === 'open-sandbox'
                    ? 'This is an open sandbox: define one with `PUT /v1/authz/schema` (any authenticated user).'
                    : "The tenant owner defines it from the AuthGravity dashboard's Authorization panel.")
        );
        lines.push('');
    } else {
        lines.push(
            `Schema version ${stored.version}. Objects are written \`type:id\`; subjects are \`user:<uuid>\` or subject sets like \`group:eng#member\`.`
        );
        lines.push('');
        for (const [typeName, def] of Object.entries(defs)) {
            lines.push(`### ${typeName}`);
            const rels = Object.entries(def.relations ?? {});
            if (rels.length) {
                lines.push('Relations (facts you write as tuples):');
                for (const [name, rel] of rels) {
                    lines.push(`- \`${typeName}:<id>#${name}\` — allowed subjects: ${fmtSubjects(rel.subjects)}`);
                }
            }
            const perms = Object.entries(def.permissions ?? {});
            if (perms.length) {
                lines.push('Permissions (questions you check):');
                for (const [name, expr] of perms) {
                    lines.push(`- \`${name}\` = ${fmtExpr(expr)}`);
                }
            }
            lines.push('');
        }
    }

    lines.push('## Integration (HTTP API on this host)');
    lines.push('');
    lines.push(
        'Every call needs the end user\'s session: send the first-party `session_id` cookie, or forward its value as `Authorization: Bearer <session_id>` from your backend (read it from the incoming Cookie header, same as the `/v1/whoami` pattern).'
    );
    lines.push('');
    lines.push('Check a permission (the call your app makes on every gated action). With a session, omit the subject or pass `"self"` — one round trip both authenticates and authorizes, and returns the user id:');
    lines.push('');
    lines.push('```');
    lines.push(`curl -X POST <this host>/v1/authz/check \\`);
    lines.push(`  -H "Authorization: Bearer $SESSION_ID" -H 'Content-Type: application/json' \\`);
    lines.push(`  -d '{ "object": "${exampleObject}", "permission": "${examplePermission}" }'`);
    lines.push(`# -> { "allowed": true | false, "user_id": "<the session user's uuid>" }`);
    lines.push('```');
    lines.push('');
    lines.push(
        'Batch (list pages): `{"items": [{"object": "...", "permission": "..."}, ...]}` (max 50) -> `{"results": [{"allowed": ...}, ...], "user_id": "..."}` — items are evaluated concurrently and keep their order; a malformed item reports `{"allowed": false, "error": "..."}` in place. An explicit `"subject": "user:<uuid>"` is allowed anywhere and REQUIRED when calling with a service token (tokens have no session user).'
    );
    lines.push('');
    lines.push('Do not cache allowed/denied results across requests — per-request checks are what make revocation instant, and they are point lookups.');
    lines.push('');
    lines.push('Other endpoints:');
    lines.push('');
    lines.push('- `GET /v1/authz/status` -> `{user_id, mode, can_manage, schema_version}`');
    lines.push('- `GET /v1/authz/schema` -> the schema JSON document');
    lines.push(
        '- `GET /v1/authz/relationships?object_type=...` (or `subject_type=...`; more filters: `object_id`, `relation`, `subject_id`; paging: `limit`, `cursor`)'
    );
    lines.push(
        `- \`POST /v1/authz/relationships\` \`{updates: [{op: "touch"|"create"|"delete", object, relation, subject}]}\` (max 100, atomic) — e.g. \`{"op": "touch", "object": "${exampleObject}", "relation": "${exampleRelation}", "subject": "user:<uuid>"}\``
    );
    lines.push('');

    lines.push('## Who can write');
    lines.push('');
    if (mode === 'open-sandbox') {
        lines.push(
            'This is an anonymous sandbox: any authenticated user of this pool may edit the schema and write relationships. Perfect for development — write tuples directly from your app while you build.'
        );
    } else {
        lines.push(
            "This tenant is owner-managed. The schema is administered by the tenant owner (AuthGravity dashboard). For relationship writes there are two paths:"
        );
        lines.push('');
        lines.push(
            '- **Your app backend** uses a **service token** — minted by the tenant owner in the dashboard\'s Authorization panel, kept as a server secret (e.g. env var `AUTHZ_SERVICE_TOKEN`), and sent as `Authorization: Bearer agk_...` to `POST /v1/authz/relationships` on this host. This is how the app records domain events: a new resource\'s owner, an invited user joining a group, a revoked share. Service tokens can check, read, and write relationships for this tenant only — they cannot change the schema.'
        );
        lines.push(
            "- **End-user sessions** can check permissions and read relationships, but their relationship writes get 403."
        );
        lines.push('');
        lines.push('Example — an invite-link flow:');
        lines.push('');
        lines.push('1. Your app validates its own invite token, then reads the new user\'s uuid from `GET /v1/whoami` (their session).');
        lines.push('2. Your backend writes the membership with the service token:');
        lines.push('');
        lines.push('```');
        lines.push(`curl -X POST <this host>/v1/authz/relationships \\`);
        lines.push(`  -H "Authorization: Bearer $AUTHZ_SERVICE_TOKEN" -H 'Content-Type: application/json' \\`);
        lines.push(
            `  -d '{ "updates": [{ "op": "touch", "object": "${exampleObject}", "relation": "${exampleRelation}", "subject": "user:<new-uuid>" }] }'`
        );
        lines.push('```');
    }
    lines.push('');

    lines.push('## Design guidance for your app');
    lines.push('');
    lines.push('- Gate every protected route/action with a `check` call — do not cache allow/deny decisions across requests.');
    lines.push('- Key your own database rows by the AuthGravity user UUID; use those same UUIDs as `user:<uuid>` subjects.');
    lines.push('- Object ids are your own identifiers (`[a-zA-Z0-9_@./=+-]`, no `:` or `#`).');
    lines.push('- A self-contained console for this tenant lives at `/authz` on this host.');
    lines.push('');

    if (stored && typeNames.length > 0) {
        lines.push('## Schema JSON (current)');
        lines.push('');
        lines.push('```json');
        lines.push(JSON.stringify(stored.doc, null, 2));
        lines.push('```');
        lines.push('');
    }

    return lines.join('\n');
}
