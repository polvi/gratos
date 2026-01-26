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

        const usernameInput = page.getByPlaceholder('Username');
        const registerBtn = page.getByRole('button', { name: 'Register', exact: true });

        // 2. Register
        const username = `user_${Date.now()}`;
        // Wait for hydration to settle
        await page.waitForTimeout(1000);
        await usernameInput.click();
        await usernameInput.pressSequentially(username, { delay: 50 });

        // Wait for state update
        await expect(usernameInput).toHaveValue(username);
        await expect(registerBtn).toBeEnabled();

        await registerBtn.click();

        // 3. Verify Registration (Auto-login)
        await expect(page.getByText(`Welcome back, ${username}!`)).toBeVisible({ timeout: 10000 });

        // 4. Logout
        const logoutBtn = page.getByRole('button', { name: 'Logout' });
        await logoutBtn.click();
        await expect(page.getByText('Welcome to the Gratos demo')).toBeVisible();

        // 5. Login
        const loginBtn = page.getByRole('button', { name: 'Login', exact: true });
        await loginBtn.click();
        await expect(page.getByText(`Welcome back, ${username}!`)).toBeVisible({ timeout: 10000 });
    });
});
