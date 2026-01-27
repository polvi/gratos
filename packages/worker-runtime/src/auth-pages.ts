
export const loginPage = (returnTo: string | null) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Gratos Auth</title>
    <style>
        body { font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f2f5; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; width: 100%; max-width: 400px; }
        h1 { margin-bottom: 1.5rem; color: #1a73e8; }
        button { background-color: #1a73e8; color: white; border: none; padding: 10px 20px; border-radius: 4px; font-size: 16px; cursor: pointer; width: 100%; }
        button:hover { background-color: #1557b0; }
        .error { color: red; margin-top: 1rem; display: none; }
    </style>
    <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
</head>
<body>
    <div class="card">
        <h1>Gratos Auth</h1>
        <p>Sign in with your passkey</p>
        <button id="loginBtn">Sign In</button>
        <p class="error" id="errorMsg"></p>
    </div>

    <script>
        const { startAuthentication } = SimpleWebAuthnBrowser;
        const loginBtn = document.getElementById('loginBtn');
        const errorMsg = document.getElementById('errorMsg');
        
        const returnTo = ${returnTo ? `"${returnTo}"` : 'null'};

        loginBtn.addEventListener('click', async () => {
            errorMsg.style.display = 'none';
            try {
                // 1. Get options
                const resp = await fetch('/login/options');
                const opts = await resp.json();

                // 2. Start Auth
                let asseResp;
                try {
                    asseResp = await startAuthentication(opts);
                } catch (error) {
                    throw error;
                }

                // 3. Verify
                const verifyResp = await fetch('/login/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        response: asseResp,
                        challengeId: opts.challengeId
                    })
                });

                const verifyJson = await verifyResp.json();

                if (verifyJson.verified) {
                    if (returnTo) {
                        window.location.href = returnTo;
                    } else {
                        window.location.reload();
                    }
                } else {
                    errorMsg.innerText = verifyJson.error || 'Verification failed';
                    errorMsg.style.display = 'block';
                }
            } catch (err) {
                console.error(err);
                errorMsg.innerText = err.message || 'An error occurred';
                errorMsg.style.display = 'block';
            }
        });
    </script>
</body>
</html>
`;
