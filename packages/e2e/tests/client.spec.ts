
import { test, expect } from '@playwright/test';

test.describe('Client Management', () => {
    let authenticatorId: string;

    test.beforeEach(async ({ page }) => {
        // Connect to CDP session
        const client = await page.context().newCDPSession(page);
        await client.send('WebAuthn.enable');

        const result = await client.send('WebAuthn.addVirtualAuthenticator', {
            options: {
                protocol: 'ctap2',
                transport: 'internal',
                hasResidentKey: true,
                hasUserVerification: true,
            },
        });
        authenticatorId = result.authenticatorId;
        await client.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: true });
    });

    test('should allow creating a client with full URL', async ({ page }) => {
        // 1. Visit Demo
        await page.goto('/');

        // 2. Login or Register
        const usernameInput = page.getByPlaceholder('Username');
        const registerBtn = page.getByRole('button', { name: 'Register', exact: true });

        const username = `admin_${Date.now()}`;
        // Wait for hydration
        await page.waitForTimeout(1000);
        await usernameInput.click({ force: true });
        await usernameInput.pressSequentially(username, { delay: 50 });
        await registerBtn.click();
        await expect(page.getByText(`Welcome back, ${username}!`)).toBeVisible({ timeout: 10000 });

        // 3. Go to Admin
        await page.goto('/admin');
        await expect(page.getByText('Manage Clients')).toBeVisible();

        // 4. Create Client with Full URL
        const originInput = page.getByLabel('Client Origin (URL)');
        const cookieDomainInput = page.getByLabel('Cookie Domain');
        const addBtn = page.getByRole('button', { name: 'Add Client' });

        await originInput.fill('http://localhost:3000');
        await cookieDomainInput.fill('localhost');
        await addBtn.click();

        // 5. Verify Client in List
        await expect(page.getByText('http://localhost:3000')).toBeVisible();

        // 6. Verify Validation (Fail Case)
        await originInput.fill('http://example.com');
        await cookieDomainInput.fill('localhost'); // Mismatch
        await addBtn.click();
        
        await expect(page.getByText('Invalid cookie domain')).toBeVisible();
    });
});
