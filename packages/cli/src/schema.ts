// `authgravity schema types` — TypeScript codegen from a tenant's live schema.
// Fetches GET /v1/authz/schema and runs @authgravity/server's schemaToTypes so
// check() calls are compile-time-verified against the deployed schema version.

import { writeFileSync } from 'node:fs';
import { schemaToTypes } from '@authgravity/server';
import { parseArgs, flagStr, flagBool } from './args';

export const SCHEMA_USAGE = `authgravity schema types [options]

  Generate TypeScript types from a tenant's live authorization schema.

Options:
  --endpoint <url>   Tenant auth endpoint (or env PUBLIC_AUTH_ENDPOINT)
  --token <agk_...>  Service token (or env AUTHGRAVITY_SERVICE_TOKEN)
  --tenant <name>    Tenant name to stamp in the file header (optional)
  --out <file>       Write to a file (default: stdout)
  -h, --help         Show this help
`;

export async function runSchemaTypes(args: string[]) {
    const { flags } = parseArgs(args);
    if (flagBool(flags, 'help', 'h')) {
        console.log(SCHEMA_USAGE);
        return;
    }
    const endpoint = flagStr(flags, 'endpoint') || process.env.PUBLIC_AUTH_ENDPOINT;
    if (!endpoint) {
        console.error('No endpoint: pass --endpoint or set PUBLIC_AUTH_ENDPOINT.');
        process.exit(1);
    }
    const token = flagStr(flags, 'token') || process.env.AUTHGRAVITY_SERVICE_TOKEN;

    const res = await fetch(`${endpoint}/v1/authz/schema`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (res.status === 404) {
        console.error('No schema is defined for this tenant yet.');
        process.exit(1);
    }
    if (!res.ok) {
        console.error(`Failed to fetch schema (${res.status}): ${await res.text()}`);
        process.exit(1);
    }
    const { schema, version, updated_at } = (await res.json()) as {
        schema: any;
        version: number;
        updated_at: number;
    };

    const ts = schemaToTypes(schema, {
        version,
        updatedAt: updated_at,
        tenant: flagStr(flags, 'tenant'),
    });

    const out = flagStr(flags, 'out');
    if (out) {
        writeFileSync(out, ts);
        console.error(`Wrote ${out} (schema version ${version}).`);
    } else {
        process.stdout.write(ts);
    }
}
