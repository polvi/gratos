import { h, Fragment } from 'preact';
import { useEffect } from 'preact/hooks';
import { AuthProvider, useAuth, LoginButton, RegisterButton } from './auth';

function LoginInner() {
    const { isAuthenticated } = useAuth();

    // Signed in (fresh ceremony or existing session) → dashboard
    useEffect(() => {
        if (!isAuthenticated) return;
        window.location.href = '/domains';
    }, [isAuthenticated]);

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

export function LoginFlow({ apiBaseUrl }: { apiBaseUrl: string }) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <LoginInner />
        </AuthProvider>
    );
}
