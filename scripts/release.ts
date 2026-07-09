#!/usr/bin/env bun
// Project-wide npm release for the publishable packages. Order matters:
// @authgravity/server must publish before @authgravity/cli, because the CLI
// depends on it via `workspace:*` and `bun publish` rewrites that to server's
// just-bumped version. @authgravity/browser is independent.
//
// Each package's own `release` script does the work (build or typecheck →
// patch-bump its package.json → bun publish). This only sequences them and,
// because Bun's $ throws on a non-zero exit, stops on the first failure so a
// broken publish doesn't cascade into the packages that depend on it.
import { $ } from 'bun';

const STEPS: Array<{ name: string; dir: string }> = [
    { name: '@authgravity/server', dir: 'packages/server' },
    { name: '@authgravity/browser', dir: 'packages/browser' },
    { name: '@authgravity/cli', dir: 'packages/cli' },
];

const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;

for (let i = 0; i < STEPS.length; i++) {
    const { name, dir } = STEPS[i];
    console.log(`\n${bold(`▶ [${i + 1}/${STEPS.length}] Releasing ${name}`)} (${dir})`);
    // Use .cwd() rather than `bun --cwd <dir> run <script>`, which Bun
    // mis-parses into `run --help`.
    await $`bun run release`.cwd(dir);
}

console.log(`\n${green('✔ All packages released')}`);
console.log('Version bumps are in the working tree — commit them when ready.');
