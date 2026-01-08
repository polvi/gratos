import { h } from 'preact';
import { useState } from 'preact/hooks';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

interface AuthProps {
    apiBaseUrl: string;
}

export function Auth({ apiBaseUrl }: AuthProps) {
    const [username, setUsername] = useState('');
    const [status, setStatus] = useState<string>('');

    const handleRegister = async () => {
        try {
            setStatus('Starting registration...');
            // 1. Get options from server
            const resp = await fetch(`${apiBaseUrl}/register/options?username=${encodeURIComponent(username)}`);
            const options = await resp.json();

            // 2. Pass to browser authenticator
            const attResp = await startRegistration(options);

            // 3. Verify with server
            const verifyResp = await fetch(`${apiBaseUrl}/register/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    response: attResp,
                }),
            });

            const verificationJSON = await verifyResp.json();

            if (verificationJSON && verificationJSON.verified) {
                setStatus('Registration successful!');
            } else {
                setStatus(`Registration failed: ${JSON.stringify(verificationJSON)}`);
            }
        } catch (error) {
            console.error(error);
            setStatus(`Error: ${(error as Error).message}`);
        }
    };

    const handleLogin = async () => {
        try {
            setStatus('Starting login...');
            // 1. Get options from server
            const resp = await fetch(`${apiBaseUrl}/login/options`);
            const options = await resp.json();

            // 2. Pass to browser authenticator
            const asseResp = await startAuthentication(options);

            // 3. Verify
            const verifyResp = await fetch(`${apiBaseUrl}/login/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    challengeId: options.challengeId,
                    response: asseResp,
                }),
            });

            const verifyJSON = await verifyResp.json();

            if (verifyJSON && verifyJSON.verified) {
                setStatus(`Login successful! Welcome ${verifyJSON.user?.username || 'User'}`);
            } else {
                setStatus(`Login failed: ${JSON.stringify(verifyJSON)}`);
            }
        } catch (error) {
            console.error(error);
            setStatus(`Error: ${(error as Error).message}`);
        }
    };

    return (
        <div style={{ padding: '20px', border: '1px solid #ccc', borderRadius: '8px' }}>
            <h3>Gratos Auth</h3>
            <div style={{ marginBottom: '10px' }}>
                <input
                    type="text"
                    value={username}
                    onInput={(e) => setUsername((e.target as HTMLInputElement).value)}
                    placeholder="Enter username"
                />
            </div>
            <div style={{ gap: '10px', display: 'flex' }}>
                <button onClick={handleRegister}>Register Passkey</button>
                <button onClick={handleLogin}>Login with Passkey</button>
            </div>
            {status && <p style={{ marginTop: '10px' }}>{status}</p>}
        </div>
    );
}
