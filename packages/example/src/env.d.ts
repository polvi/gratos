/// <reference types="astro/client" />

declare namespace App {
    interface Locals {
        userId?: string;
        runtime: { env: import('./lib/authz').RuntimeEnv };
    }
}
