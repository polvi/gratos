import { h } from 'preact';
import { useState } from 'preact/hooks';
import { AuthProvider, useAuth } from '@gratos/preact';
import { startAuthentication } from '@simplewebauthn/browser';

function NavButtonInner({ currentPath }: { currentPath: string }) {
    const { isAuthenticated, login, logout, apiBaseUrl, isLoading } = useAuth();
    const [status, setStatus] = useState('');

    if (isLoading) {
        // Placeholder to prevent layout shift during initial auth check
        return <div style={{ width: '66px', height: '32px' }} />;
    }

    if (isAuthenticated) {
        return (
            <button
                class="nav-button"
                onClick={async () => {
                    await logout();
                    window.location.href = '/';
                }}
            >
                Log Out
            </button>
        );
    }

    const handleLogin = async () => {
        try {
            setStatus('Logging in...');
            const resp = await fetch(`${apiBaseUrl}/login/options`);
            const options = await resp.json();

            const asseResp = await startAuthentication({ optionsJSON: options });

            const verifyResp = await fetch(`${apiBaseUrl}/login/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
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
                window.location.href = '/domains';
            } else {
                setStatus('');
            }
        } catch {
            setStatus('');
        }
    };

    return (
        <button
            class="nav-button"
            onClick={handleLogin}
            disabled={!!status}
        >
            {status || 'Log In'}
        </button>
    );
}

export function NavButton({ apiBaseUrl, currentPath }: { apiBaseUrl: string, currentPath: string }) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <NavButtonInner currentPath={currentPath} />
        </AuthProvider>
    );
}
