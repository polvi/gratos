import { test, expect } from '@playwright/test';

test.describe('Gratos Auth with Virtual Authenticator', () => {
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

    test('should register and login with passkey', async ({ page }) => {
        // 1. Visit Demo
        await page.goto('/');

        // Debug: Listen to console
        page.on('console', msg => console.log('PAGE LOG:', msg.text()));

        const usernameInput = page.getByPlaceholder('Enter username');
        const registerBtn = page.getByRole('button', { name: 'Register Passkey' });
        const loginBtn = page.getByRole('button', { name: 'Login with Passkey' });

        // 2. Register
        const username = `user_${Date.now()}`;
        await usernameInput.fill(username);
        await registerBtn.click();

        // Wait for ANY status message (success or error)
        try {
            // Check for success first
            await expect(page.getByText('Registration successful!')).toBeVisible({ timeout: 5000 });
        } catch (e) {
            // If failed, try to capture what IS visible
            const status = await page.locator('p').textContent().catch(() => 'No status text found');
            console.log('TEST FAILURE DEBUG: Status text is:', status);
            throw e; // Rethrow to fail test
        }

        // 3. Login
        await loginBtn.click();

        try {
            await expect(page.getByText(`Login successful! Welcome ${username}`)).toBeVisible({ timeout: 5000 });
        } catch (e) {
            const status = await page.locator('div > p').last().textContent().catch(() => 'No status text found');
            console.log('LOGIN FAILURE DEBUG: Status text is:', status);
            throw e;
        }
    });
});
