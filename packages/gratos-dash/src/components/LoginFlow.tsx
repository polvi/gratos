import { h, Fragment } from 'preact';
import { useEffect } from 'preact/hooks';
import { AuthProvider, useAuth, LoginButton, RegisterButton } from '@gratos/preact';

function LoginInner({ provisionerBaseUrl }: { provisionerBaseUrl: string }) {
    const { isAuthenticated } = useAuth();

    // After auth, check if user has domains → route accordingly
    useEffect(() => {
        if (!isAuthenticated) return;

        (async () => {
            try {
                const res = await fetch(`${provisionerBaseUrl}/domains`, {
                    credentials: 'include',
                });
                if (res.ok) {
                    const data = await res.json();
                    const hasDomains = (data.claimed?.length > 0) || (data.pending?.length > 0);
                    window.location.href = hasDomains ? '/domains' : '/signup';
                } else {
                    // Auth might have failed on provisioner side, just go to signup
                    window.location.href = '/signup';
                }
            } catch {
                window.location.href = '/signup';
            }
        })();
    }, [isAuthenticated, provisionerBaseUrl]);

    return (
        <div style={{ width: '100%', margin: '2rem 0', textAlign: 'left' }}>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '0.75rem' }}>
                Welcome
            </h1>
            <p style={{ color: '#52525b', marginBottom: '2rem', lineHeight: 1.6 }}>
                Sign in or create an account with a passkey.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <LoginButton />
                <div style={{ textAlign: 'center', color: '#a1a1aa', fontSize: '0.875rem' }}>
                    or
                </div>
                <RegisterButton />
            </div>
        </div>
    );
}

export function LoginFlow({ apiBaseUrl, provisionerBaseUrl }: {
    apiBaseUrl: string;
    provisionerBaseUrl: string;
}) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <LoginInner provisionerBaseUrl={provisionerBaseUrl} />
        </AuthProvider>
    );
}
