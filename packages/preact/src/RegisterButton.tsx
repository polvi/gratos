import { h } from 'preact';
import { useState } from 'preact/hooks';
import { startRegistration } from '@simplewebauthn/browser';
import { useAuth } from './AuthContext';

export function RegisterButton() {
    const { login, apiBaseUrl } = useAuth();
    const [username, setUsername] = useState('');
    const [status, setStatus] = useState('');

    const handleRegister = async () => {
        if (!username) {
            setStatus('Please enter a username');
            return;
        }
        try {
            setStatus('Registering...');
            const resp = await fetch(`${apiBaseUrl}/register/options?username=${encodeURIComponent(username)}`);
            const options = await resp.json();

            const attResp = await startRegistration(options);

            const verifyResp = await fetch(`${apiBaseUrl}/register/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    response: attResp,
                }),
                credentials: 'include', // technically not needed for register but consistency
            });

            const verificationJSON = await verifyResp.json();

            if (verificationJSON && verificationJSON.verified) {
                setStatus('Success!');
                login(verificationJSON.user);
                setTimeout(() => setStatus(''), 2000);
            } else {
                setStatus('Failed');
            }
        } catch (error: any) {
            console.error(error);
            setStatus(error.message || String(error));
        }
    };

    return (
        <div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <input
                    type="text"
                    placeholder="Username"
                    value={username}
                    onInput={(e) => {
                        setUsername((e.target as HTMLInputElement).value);
                        if (status === 'Please enter a username') setStatus('');
                    }}
                />
                <button onClick={handleRegister} disabled={status === 'Registering...'}>
                    {status || 'Register'}
                </button>
            </div>
            {!window.isSecureContext && (
                <div style={{ color: 'red', fontSize: '0.8em', marginTop: '4px' }}>
                    ⚠️ Not Secure Context. WebAuthn requires HTTPS or localhost.
                </div>
            )}
        </div>
    );
}
