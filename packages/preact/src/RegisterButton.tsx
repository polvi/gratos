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
            // No username sent to server
            const resp = await fetch(`${apiBaseUrl}/register/options`);
            const options = await resp.json();

            // We get userId from the server to pass back for verification
            const userId = options.userId;

            // CLIENT-SIDE OVERWRITE: Put the real username here so the Authenticator (TouchID/FaceID) 
            // shows the correct label to the user. The server never sees this string.
            options.user.name = username;
            options.user.displayName = username;

            const attResp = await startRegistration({ optionsJSON: options });

            const verifyResp = await fetch(`${apiBaseUrl}/register/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    userId,
                    response: attResp,
                }),
                credentials: 'include',
            });

            const verificationJSON = await verifyResp.json();

            if (verificationJSON && verificationJSON.verified) {
                setStatus('Success!');
                // Server doesn't return username anymore, so we merge it in
                login({ ...verificationJSON.user, username: '' });

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
        <div style={{ position: 'relative' }}>
            <style>{`
                .register-input-group {
                    display: flex;
                    gap: 8px;
                    align-items: center;
                }
                .register-input {
                    padding: 8px 12px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    font-size: 16px; /* Avoid iOS zoom */
                }
                .register-btn {
                    padding: 8px 16px;
                    height: 40px;
                    cursor: pointer;
                    background: #18181b;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    font-size: 14px;
                    font-weight: 500;
                }
                .register-btn:disabled {
                    background: #a1a1aa;
                    cursor: not-allowed;
                }
                @media (max-width: 600px) {
                    .register-input-group {
                        flex-direction: column;
                        width: 100%;
                        align-items: stretch;
                    }
                    .register-input {
                        width: 100%;
                        height: 44px; /* Touch target */
                        box-sizing: border-box;
                    }
                    .register-btn {
                        width: 100%;
                        height: 48px; /* Larger touch target */
                        font-size: 16px;
                    }
                }
            `}</style>
            <div className="register-input-group">
                <input
                    type="text"
                    className="register-input"
                    placeholder="Username"
                    value={username}
                    onInput={(e) => {
                        setUsername((e.target as HTMLInputElement).value);
                        if (status === 'Please enter a username') setStatus('');
                    }}
                />
                <button
                    className="register-btn"
                    onClick={handleRegister}
                    disabled={status === 'Registering...'}
                >
                    {status || 'Register'}
                </button>
            </div>
            {!window.isSecureContext && (
                <div style={{ color: '#ef4444', fontSize: '0.75rem', marginTop: '6px', textAlign: 'center', background: '#fee2e2', padding: '4px', borderRadius: '4px' }}>
                    ⚠️ Not Secure Context. HTTPS required.
                </div>
            )}
        </div>
    );
}
