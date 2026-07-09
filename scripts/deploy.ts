#!/usr/bin/env bun
// Project-wide production deploy. Order matters because of service bindings:
//   gratos-authz  ← called by multi (AUTHZ) and provisioner (AUTHZ)
//   gratos-multi   ← binds AUTHZ; called by provisioner (AUTH) and the dash (HTTP)
//   provisioner    ← binds AUTH + AUTHZ
//   gratos-dash    ← builds Astro, talks to multi over HTTP at runtime
// Deploy dependencies first so each worker's bindings resolve to a live target.
import { $ } from 'bun';

const STEPS: Array<{ name: string; dir: string }> = [
    { name: '@gratos/authz', dir: 'packages/gratos-authz' },
    { name: '@gratos/multi', dir: 'packages/gratos-multi' },
    { name: '@gratos/provisioner', dir: 'packages/provisioner' },
    { name: 'gratos-dash', dir: 'packages/gratos-dash' },
];

const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;

for (let i = 0; i < STEPS.length; i++) {
    const { name, dir } = STEPS[i];
    console.log(`\n${bold(`▶ [${i + 1}/${STEPS.length}] Deploying ${name}`)} (${dir})`);
    // Run each package's own `deploy` script from its directory. Use .cwd()
    // rather than `bun --cwd <dir> run …`, which Bun mis-parses into `run --help`.
    // Bun's $ throws on a non-zero exit, so a failed deploy aborts the rest.
    await $`bun run deploy`.cwd(dir);
}

console.log(`\n${green('✔ All workers deployed')}`);
