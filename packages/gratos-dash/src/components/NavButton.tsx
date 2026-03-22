import { h } from 'preact';
import { useState } from 'preact/hooks';
import { AuthProvider, useAuth } from '@gratos/preact';
import { startAuthentication } from '@simplewebauthn/browser';

function NavButtonInner({ currentPath, provisionerBaseUrl }: { currentPath: string; provisionerBaseUrl: string }) {
    const { isAuthenticated, login, logout, apiBaseUrl, isLoading } = useAuth();
    const [status, setStatus] = useState('');

    const routeAfterLogin = async () => {
        try {
            const res = await fetch(`${provisionerBaseUrl}/domains`, {
                credentials: 'include',
            });
            if (res.ok) {
                const data = await res.json();
                const hasDomains = (data.claimed?.length > 0) || (data.pending?.length > 0);
                window.location.href = hasDomains ? '/domains' : '/signup';
                return;
            }
        } catch { /* fall through */ }
        window.location.href = '/signup';
    };

    if (isLoading) {
        // Placeholder to prevent layout shift during initial auth check
        return <div style={{ width: '66px', height: '32px' }} />;
    }

    if (isAuthenticated) {
        if (currentPath === '/domains') {
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
        return (
            <a href="/domains" class="nav-button">
                Dashboard
            </a>
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
                await routeAfterLogin();
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

export function NavButton({ apiBaseUrl, currentPath, provisionerBaseUrl }: { apiBaseUrl: string; currentPath: string; provisionerBaseUrl: string }) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <NavButtonInner currentPath={currentPath} provisionerBaseUrl={provisionerBaseUrl} />
        </AuthProvider>
    );
}
