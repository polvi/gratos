import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
    testDir: './tests',
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 1 : undefined,
    reporter: 'html',
    use: {
        baseURL: 'http://localhost:4321',
        trace: 'on-first-retry',
    },
    projects: [
        {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
        },
    ],
    webServer: [
        {
            command: 'cd ../worker-runtime && bun run dev',
            port: 8787,
            reuseExistingServer: true,
            stdout: 'pipe',
            stderr: 'pipe',
        },
        {
            command: 'cd ../demo && bun run dev',
            port: 4321,
            reuseExistingServer: true,
            stdout: 'pipe',
            stderr: 'pipe',
        }
    ],
});
