import { h } from 'preact';
import { useState } from 'preact/hooks';
import { startAuthentication } from '@simplewebauthn/browser';
import { useAuth } from './AuthContext';

export function LoginButton() {
    const { login, apiBaseUrl } = useAuth();
    const [status, setStatus] = useState('');

    const handleLogin = async () => {
        try {
            setStatus('Login...');
            const resp = await fetch(`${apiBaseUrl}/login/options`);
            const options = await resp.json();

            const asseResp = await startAuthentication(options);

            const verifyResp = await fetch(`${apiBaseUrl}/login/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    challengeId: options.challengeId,
                    response: asseResp,
                }),
                credentials: 'include',
            });

            const verifyJSON = await verifyResp.json();

            if (verifyJSON && verifyJSON.verified) {
                setStatus('');
                login(verifyJSON.user);
            } else {
                setStatus('Failed');
                console.error(verifyJSON);
            }
        } catch (error: any) {
            console.error(error);
            setStatus(error.message || String(error));
        }
    };

    return (
        <>
            <style>{`
                .login-btn {
                    padding: 8px 16px;
                    height: 40px;
                    cursor: pointer;
                    background: transparent;
                    color: #18181b;
                    border: 1px solid #e4e4e7;
                    border-radius: 4px;
                    font-size: 14px;
                    font-weight: 500;
                    background: white;
                }
                .login-btn:hover {
                    background: #f4f4f5;
                }
                @media (max-width: 600px) {
                    .login-btn {
                        width: 100%;
                        height: 48px;
                        font-size: 16px;
                    }
                }
            `}</style>
            <button className="login-btn" onClick={handleLogin} disabled={!!status}>
                {status || 'Login'}
            </button>
        </>
    );
}
