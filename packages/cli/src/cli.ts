#!/usr/bin/env bun
import { listen } from './listen';

const DEFAULT_PORT = 8787;
const DEFAULT_MINT_HOST = 'https://authgravity.authgravity.org';

const USAGE = `AuthGravity CLI

Usage:
  authgravity listen [options]   Run a local auth proxy for development.
                                 Mints an instant sandbox and bridges its
                                 session to a first-party localhost cookie,
                                 so your app uses the same cookie-based auth
                                 code in dev as in production.

Options (listen):
  -p, --port <port>        Port to listen on (default: ${DEFAULT_PORT})
      --endpoint <url>     Use an existing sandbox endpoint instead of minting
                           (e.g. https://sandbox.authgravity.org/<id>)
      --mint-host <url>    Host used to mint the sandbox
                           (default: ${DEFAULT_MINT_HOST})
  -h, --help               Show this help

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
