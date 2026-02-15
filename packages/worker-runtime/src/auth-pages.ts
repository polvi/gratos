
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
        body { margin: 0; font-family: Roboto, arial, sans-serif; overflow: hidden; background: transparent; }
        .btn {
            display: block;
            width: 100%;
            background-color: #1a73e8;
            color: white;
            text-align: center;
            padding: 8px 16px;
            border-radius: 4px;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            border: none;
            cursor: pointer;
            box-sizing: border-box;
        }
        .btn:hover { background-color: #155db1; }
        .error { color: red; font-size: 12px; margin-top: 4px; text-align: center; }
        .link { font-size: 12px; color: #1a73e8; cursor: pointer; text-align: center; margin-top: 6px; background: none; border: none; text-decoration: underline; display: block; width: 100%; }
        .link:hover { color: #155db1; }
        #registerView { display: none; }
        #registerView input {
            display: block;
            width: 100%;
            padding: 8px;
            border: 1px solid #dadce0;
            border-radius: 4px;
            font-size: 14px;
            margin-bottom: 8px;
            box-sizing: border-box;
        }
    </style>
    <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
</head>
<body>
    <div id="signinView">
        <button id="signinBtn" class="btn">Sign in</button>
        <button id="showRegisterLink" class="link">Create account</button>
    </div>
    <div id="registerView">
        <input type="text" id="usernameInput" placeholder="Username" autocomplete="username" />
        <button id="registerBtn" class="btn">Register</button>
        <button id="backToSigninLink" class="link">Back to sign in</button>
    </div>
    <div id="errorMsg" class="error"></div>

    <script>
        const { startAuthentication, startRegistration } = SimpleWebAuthnBrowser;
        const signinView = document.getElementById('signinView');
        const registerView = document.getElementById('registerView');
        const signinBtn = document.getElementById('signinBtn');
        const registerBtn = document.getElementById('registerBtn');
        const showRegisterLink = document.getElementById('showRegisterLink');
        const backToSigninLink = document.getElementById('backToSigninLink');
        const usernameInput = document.getElementById('usernameInput');
        const errorMsg = document.getElementById('errorMsg');

        const returnTo = ${returnTo ? `"${returnTo}"` : 'null'};
        const clientId = ${clientId ? `"${clientId}"` : 'null'};

        function notifyResize() {
            if (window.parent && window.parent !== window) {
                window.parent.postMessage({ type: 'GRATOS_RESIZE', height: document.body.scrollHeight }, '*');
            }
        }

        function showSignin() {
            signinView.style.display = 'block';
            registerView.style.display = 'none';
            errorMsg.innerText = '';
            notifyResize();
        }

        function showRegister() {
            signinView.style.display = 'none';
            registerView.style.display = 'block';
            errorMsg.innerText = '';
            usernameInput.value = '';
            notifyResize();
        }

        showRegisterLink.addEventListener('click', showRegister);
        backToSigninLink.addEventListener('click', showSignin);

        // --- Sign in flow ---
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

        // --- Registration flow ---
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

                // Overwrite display name client-side (server only stores UUID)
                opts.user.name = username;
                opts.user.displayName = username;

                let regResp;
                try {
                    regResp = await startRegistration(opts);
                } catch (e) {
                    registerBtn.disabled = false;
                    registerBtn.innerText = 'Register';
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

                if (verifyJson.redirectUrl) {
                    window.location.href = verifyJson.redirectUrl;
                } else if (verifyJson.verified) {
                    if (returnTo) {
                        window.location.href = returnTo;
                    } else {
                        registerBtn.innerText = 'Success!';
                    }
                } else {
                    errorMsg.innerText = verifyJson.error || 'Registration failed';
                    registerBtn.disabled = false;
                    registerBtn.innerText = 'Register';
                }
            } catch (err) {
                console.error(err);
                errorMsg.innerText = 'Registration failed';
                registerBtn.disabled = false;
                registerBtn.innerText = 'Register';
            }
        });

        // Initial resize notification
        notifyResize();
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
