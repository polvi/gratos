
export const loginPage = (returnTo: string | null, clientId: string | null) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gratos Auth</title>
    <style>
        body { font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: white; }
        .card { display: none; }
        .error { color: red; margin-top: 1rem; text-align: center; }
        .loading { font-size: 1.2rem; color: #5f6368; }
    </style>
    <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
</head>
<body>
    <div class="loading" id="loadingMsg">Authenticating...</div>
    <div class="error" id="errorMsg"></div>

    <script>
        const { startAuthentication } = SimpleWebAuthnBrowser;
        const errorMsg = document.getElementById('errorMsg');
        const loadingMsg = document.getElementById('loadingMsg');
        
        const returnTo = ${returnTo ? `"${returnTo}"` : 'null'};
        const clientId = ${clientId ? `"${clientId}"` : 'null'};

        async function doLogin() {
            try {
                // 1. Get options
                const resp = await fetch('/login/options');
                if (!resp.ok) throw new Error('Failed to get login options');
                const opts = await resp.json();

                // 2. Start Auth
                let asseResp;
                try {
                    asseResp = await startAuthentication(opts);
                } catch (error) {
                    // StartAuth failed (e.g. user cancelled, or no credentials)
                    console.error(error);
                    loadingMsg.style.display = 'none';
                    errorMsg.innerText = 'Authentication cancelled or failed.';
                    return;
                }

                // 3. Verify
                const verifyResp = await fetch('/login/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        response: asseResp,
                        challengeId: opts.challengeId,
                        clientId: clientId,
                        returnTo: returnTo
                    })
                });

                const verifyJson = await verifyResp.json();

                if (verifyJson.redirectUrl) {
                    window.location.href = verifyJson.redirectUrl;
                } else if (verifyJson.verified) {
                    if (returnTo) {
                        window.location.href = returnTo;
                    } else {
                        loadingMsg.innerText = 'Success!';
                    }
                } else {
                    loadingMsg.style.display = 'none';
                    errorMsg.innerText = verifyJson.error || 'Verification failed';
                }
            } catch (err) {
                console.error(err);
                loadingMsg.style.display = 'none';
                errorMsg.innerText = err.message || 'An error occurred';
            }
        }

        // Start automatically
        doLogin();
    </script>
</body>
</html>
`;


export const promptPage = (returnTo: string | null, clientId: string | null) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In</title>
    <style>
        body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, arial, sans-serif; overflow: hidden; background: transparent; }
        .btn {
            display: block;
            width: 100%;
            background-color: #1a73e8;
            color: white;
            text-align: center;
            padding: 12px 16px;
            border-radius: 8px;
            text-decoration: none;
            font-size: 15px;
            font-weight: 500;
            border: none;
            cursor: pointer;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        .btn:hover { background-color: #155db1; }
        .btn:active { background-color: #1260a0; }
        .error { color: #d93025; font-size: 13px; margin-top: 6px; text-align: center; }
        .link {
            font-size: 14px;
            color: #1a73e8;
            cursor: pointer;
            text-align: center;
            margin-top: 10px;
            background: none;
            border: none;
            text-decoration: none;
            display: block;
            width: 100%;
            padding: 8px 0;
            -webkit-tap-highlight-color: transparent;
        }
        .link:active { color: #155db1; }
    </style>
    <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
</head>
<body>
    <button id="signinBtn" class="btn">Sign in</button>
    <button id="createAccountLink" class="link">Create account</button>
    <div id="errorMsg" class="error"></div>

    <script>
        const { startAuthentication } = SimpleWebAuthnBrowser;
        const signinBtn = document.getElementById('signinBtn');
        const createAccountLink = document.getElementById('createAccountLink');
        const errorMsg = document.getElementById('errorMsg');

        const returnTo = ${returnTo ? `"${returnTo}"` : 'null'};
        const clientId = ${clientId ? `"${clientId}"` : 'null'};

        // Notify parent of content height so iframe can resize
        if (window.parent && window.parent !== window) {
            window.parent.postMessage({ type: 'GRATOS_RESIZE', height: document.body.scrollHeight + 2 }, '*');
        }

        // "Create account" opens a popup via the parent frame
        createAccountLink.addEventListener('click', () => {
            if (window.parent && window.parent !== window) {
                window.parent.postMessage({ type: 'GRATOS_OPEN_REGISTER' }, '*');
            }
        });

        signinBtn.addEventListener('click', async () => {
            signinBtn.disabled = true;
            signinBtn.innerText = 'Signing in...';
            errorMsg.innerText = '';

            try {
                const resp = await fetch('/login/options');
                if (!resp.ok) throw new Error('Failed to init login');
                const opts = await resp.json();

                let asseResp;
                try {
                    asseResp = await startAuthentication(opts);
                } catch (e) {
                     signinBtn.disabled = false;
                     signinBtn.innerText = 'Sign in';
                     return;
                }

                const verifyResp = await fetch('/login/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        response: asseResp,
                        challengeId: opts.challengeId,
                        clientId: clientId,
                        returnTo: returnTo
                    })
                });

                const verifyJson = await verifyResp.json();

                if (verifyJson.redirectUrl) {
                    window.location.href = verifyJson.redirectUrl;
                } else {
                     errorMsg.innerText = verifyJson.error || 'Login failed';
                     signinBtn.disabled = false;
                     signinBtn.innerText = 'Sign in';
                }
            } catch (err) {
                console.error(err);
                errorMsg.innerText = 'Authentication failed';
                signinBtn.disabled = false;
                signinBtn.innerText = 'Sign in';
            }
        });
    </script>
</body>
</html>
`;


export const registerPage = (returnTo: string | null, clientId: string | null) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Create Account - Let's Ident</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
            margin: 0;
            padding: 0;
            background-color: #f8f9fa;
        }
        .card {
            background: white;
            width: 100%;
            min-height: 100vh;
            padding: 32px 24px;
            padding-top: max(32px, env(safe-area-inset-top, 0px));
            padding-bottom: max(32px, env(safe-area-inset-bottom, 0px));
        }
        @media (min-width: 480px) {
            body { align-items: center; padding: 24px; }
            .card {
                max-width: 400px;
                min-height: auto;
                border-radius: 12px;
                box-shadow: 0 1px 6px rgba(0,0,0,0.12);
                padding: 32px;
            }
        }
        h1 { font-size: 22px; margin: 0 0 6px; color: #202124; font-weight: 700; }
        .tagline { font-size: 15px; color: #5f6368; margin: 0 0 20px; line-height: 1.5; }
        input {
            display: block;
            width: 100%;
            padding: 14px 16px;
            border: 1px solid #dadce0;
            border-radius: 8px;
            font-size: 16px;
            margin-bottom: 12px;
            -webkit-appearance: none;
        }
        input:focus { outline: none; border-color: #1a73e8; box-shadow: 0 0 0 2px rgba(26,115,232,0.2); }
        .btn {
            display: block;
            width: 100%;
            background-color: #1a73e8;
            color: white;
            text-align: center;
            padding: 14px 16px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 500;
            border: none;
            cursor: pointer;
            -webkit-tap-highlight-color: transparent;
        }
        .btn:hover { background-color: #155db1; }
        .btn:active { background-color: #1260a0; }
        .btn:disabled { background-color: #94bfff; cursor: default; }
        .error { color: #d93025; font-size: 14px; margin-top: 12px; text-align: center; }
        .success { color: #1e8e3e; font-size: 14px; margin-top: 12px; text-align: center; }
        .features { list-style: none; padding: 0; margin: 0 0 24px; }
        .features li { font-size: 14px; color: #3c4043; padding: 6px 0; padding-left: 24px; position: relative; line-height: 1.4; }
        .features li::before { content: "\\2713"; position: absolute; left: 0; color: #1a73e8; font-weight: bold; }
        .privacy-note { font-size: 13px; color: #80868b; margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; line-height: 1.6; }
    </style>
    <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
</head>
<body>
    <div class="card">
        <h1>Let's Ident</h1>
        <p class="tagline">Free, privacy-preserving authentication.<br>No passwords. No tracking.</p>
        <ul class="features">
            <li>Passwordless sign-in with passkeys</li>
            <li>No personal data stored on the server</li>
            <li>Works across all your devices</li>
        </ul>
        <input type="text" id="usernameInput" placeholder="Choose a username" autocomplete="username" autofocus />
        <button id="registerBtn" class="btn">Create account</button>
        <div class="privacy-note">Your username stays on your device and is never sent to the server. It's only used to label your passkey so you can recognize it later.</div>
        <div id="errorMsg" class="error"></div>
        <div id="successMsg" class="success"></div>
    </div>

    <script>
        const { startRegistration } = SimpleWebAuthnBrowser;
        const registerBtn = document.getElementById('registerBtn');
        const usernameInput = document.getElementById('usernameInput');
        const errorMsg = document.getElementById('errorMsg');
        const successMsg = document.getElementById('successMsg');

        const returnTo = ${returnTo ? `"${returnTo}"` : 'null'};
        const clientId = ${clientId ? `"${clientId}"` : 'null'};

        registerBtn.addEventListener('click', async () => {
            const username = usernameInput.value.trim();
            if (!username) {
                errorMsg.innerText = 'Please enter a username';
                return;
            }

            registerBtn.disabled = true;
            registerBtn.innerText = 'Registering...';
            errorMsg.innerText = '';

            try {
                const resp = await fetch('/register/options');
                if (!resp.ok) throw new Error('Failed to init registration');
                const opts = await resp.json();
                const userId = opts.userId;

                opts.user.name = username;
                opts.user.displayName = username;

                let regResp;
                try {
                    regResp = await startRegistration({ optionsJSON: opts });
                } catch (e) {
                    console.error('startRegistration error:', e);
                    errorMsg.innerText = e.message || 'Registration cancelled';
                    registerBtn.disabled = false;
                    registerBtn.innerText = 'Create account';
                    return;
                }

                const verifyResp = await fetch('/register/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        userId: userId,
                        response: regResp,
                        clientId: clientId,
                        returnTo: returnTo
                    })
                });

                const verifyJson = await verifyResp.json();

                if (verifyJson.verified) {
                    // Notify opener (the parent page) and close popup
                    if (window.opener) {
                        window.opener.postMessage({ type: 'GRATOS_LOGIN_SUCCESS' }, '*');
                        window.close();
                    } else if (verifyJson.redirectUrl) {
                        window.location.href = verifyJson.redirectUrl;
                    } else {
                        successMsg.innerText = 'Account created! You can close this window.';
                    }
                } else {
                    errorMsg.innerText = verifyJson.error || 'Registration failed';
                    registerBtn.disabled = false;
                    registerBtn.innerText = 'Create account';
                }
            } catch (err) {
                console.error(err);
                errorMsg.innerText = 'Registration failed';
                registerBtn.disabled = false;
                registerBtn.innerText = 'Register';
            }
        });

        usernameInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') registerBtn.click();
        });
    </script>
</body>
</html>
`;

export const successPage = () => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Success</title>
</head>
<body>
    <script>
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ type: "GRATOS_LOGIN_SUCCESS" }, "*");
      }
    </script>
</body>
</html>
`;
