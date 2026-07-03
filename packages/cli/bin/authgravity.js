#!/usr/bin/env bun
// npm rejects .ts files as bin targets, so this JS shim is the published
// binary; bun (the shebang interpreter) runs the TypeScript directly.
import '../src/cli.ts';
