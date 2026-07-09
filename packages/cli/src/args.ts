// Generic argv parser for subcommands. Unlike the original listen-only parser,
// this accepts positionals (e.g. `tuples import <file>`) and treats `--flag`
// with no following value (or a following value that starts with `-`) as a
// boolean flag (e.g. `--dry-run`).

export interface ParsedArgs {
    positionals: string[];
    flags: Record<string, string | true>;
}

export function parseArgs(argv: string[]): ParsedArgs {
    const positionals: string[] = [];
    const flags: Record<string, string | true> = {};
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--') {
            positionals.push(...argv.slice(i + 1));
            break;
        }
        if (a.startsWith('--') || (a.startsWith('-') && a.length > 1)) {
            const key = a.startsWith('--') ? a.slice(2) : a.slice(1);
            const next = argv[i + 1];
            if (next !== undefined && !next.startsWith('-')) {
                flags[key] = next;
                i++;
            } else {
                flags[key] = true;
            }
        } else {
            positionals.push(a);
        }
    }
    return { positionals, flags };
}

/** Read a flag as a string, honoring short aliases; undefined if absent/boolean. */
export function flagStr(flags: Record<string, string | true>, ...names: string[]): string | undefined {
    for (const n of names) {
        const v = flags[n];
        if (typeof v === 'string') return v;
    }
    return undefined;
}

export function flagBool(flags: Record<string, string | true>, ...names: string[]): boolean {
    return names.some((n) => flags[n] !== undefined);
}
