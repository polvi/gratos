
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

