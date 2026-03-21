import { defineConfig } from 'astro/config';
import preact from '@astrojs/preact';
import cloudflare from '@astrojs/cloudflare';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
    site: 'https://authgravity.org',
    integrations: [preact(), sitemap()],
    adapter: cloudflare()
});
