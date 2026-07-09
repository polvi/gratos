#!/usr/bin/env bun
import { listen } from './listen';
import { runSchemaTypes, SCHEMA_USAGE } from './schema';
import { runTuplesImport, TUPLES_USAGE } from './tuples';

const DEFAULT_PORT = 8787;
const DEFAULT_MINT_HOST = 'https://authgravity.authgravity.org';

const USAGE = `AuthGravity CLI

Usage:
  authgravity listen [options]        Run a local auth proxy for development.
                                      Mints an instant sandbox and bridges its
                                      session to a first-party localhost cookie,
                                      so your app uses the same cookie-based auth
                                      code in dev as in production.
  authgravity schema types [options]  Generate TypeScript types from a tenant's
                                      live authorization schema.
  authgravity tuples import <file>    Bulk-import relationship updates (chunked,
                                      with --dry-run).

Options (listen):
  -p, --port <port>        Port to listen on (default: ${DEFAULT_PORT})
      --endpoint <url>     Use an existing sandbox endpoint instead of minting
                           (e.g. https://sandbox.authgravity.org/<id>)
      --mint-host <url>    Host used to mint the sandbox
                           (default: ${DEFAULT_MINT_HOST})
  -h, --help               Show this help

Run "authgravity <command> --help" for command-specific options.
Docs: https://authgravity.org/llms.txt
`;

function parseFlags(args: string[]): Record<string, string> {
    const flags: Record<string, string> = {};
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg === '-h' || arg === '--help') flags.help = 'true';
        else if (arg === '-p' || arg === '--port') flags.port = args[++i];
        else if (arg === '--endpoint') flags.endpoint = args[++i];
        else if (arg === '--mint-host') flags.mintHost = args[++i];
        else {
            console.error(`Unknown option: ${arg}\n`);
            console.error(USAGE);
            process.exit(1);
        }
    }
    return flags;
}

/** `schema <sub>` — currently only `types`. */
async function runSchema(args: string[]) {
    const sub = args[0];
    if (sub === 'types') return runSchemaTypes(args.slice(1));
    if (sub === undefined || sub === '-h' || sub === '--help') {
        console.log(SCHEMA_USAGE);
        return;
    }
    console.error(`Unknown 'schema' subcommand: ${sub}\n`);
    console.error(SCHEMA_USAGE);
    process.exit(1);
}

/** `tuples <sub>` — currently only `import`. */
async function runTuples(args: string[]) {
    const sub = args[0];
    if (sub === 'import') return runTuplesImport(args.slice(1));
    if (sub === undefined || sub === '-h' || sub === '--help') {
        console.log(TUPLES_USAGE);
        return;
    }
    console.error(`Unknown 'tuples' subcommand: ${sub}\n`);
    console.error(TUPLES_USAGE);
    process.exit(1);
}

async function runListen(args: string[]) {
    const flags = parseFlags(args);
    if (flags.help) {
        console.log(USAGE);
        return;
    }

    const port = flags.port ? parseInt(flags.port, 10) : DEFAULT_PORT;
    if (Number.isNaN(port)) {
        console.error(`Invalid port: ${flags.port}`);
        process.exit(1);
    }

    const { endpoint, mintedId, proxyUrl } = await listen({
        endpoint: flags.endpoint,
        port,
        mintHost: flags.mintHost || DEFAULT_MINT_HOST,
    });

    console.log('AuthGravity CLI\n');
    if (mintedId) console.log(`✔ Minted sandbox ${mintedId}`);
    console.log(`  Sandbox endpoint: ${endpoint}`);
    console.log(`▶ Listening on ${proxyUrl}\n`);
    console.log('Point your app at the proxy:');
    console.log(`  PUBLIC_AUTH_ENDPOINT=${proxyUrl}\n`);
    console.log('Sessions will be set as a first-party session_id cookie on localhost.');
    console.log('Requests:');
}

const [, , command, ...rest] = process.argv;

switch (command) {
    case 'listen':
        await runListen(rest);
        break;
    case 'schema':
        await runSchema(rest);
        break;
    case 'tuples':
        await runTuples(rest);
        break;
    case undefined:
    case '-h':
    case '--help':
    case 'help':
        console.log(USAGE);
        break;
    default:
        console.error(`Unknown command: ${command}\n`);
        console.error(USAGE);
        process.exit(1);
}
