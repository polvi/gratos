import { h, Fragment } from 'preact';
import { useEffect } from 'preact/hooks';
import { AuthProvider, useAuth, LoginButton, RegisterButton } from '@gratos/preact';

function LoginInner() {
    const { isAuthenticated } = useAuth();

    // Auto-advance to domains page if already authenticated 
    // or when authentication completes successfully
    useEffect(() => {
        if (isAuthenticated) {
            window.location.href = '/domains';
        }
    }, [isAuthenticated]);

    return (
        <div style={{ width: '100%', margin: '2rem 0', textAlign: 'left' }}>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '0.75rem' }}>
                Welcome Back
            </h1>
            <p style={{ color: '#52525b', marginBottom: '2rem', lineHeight: 1.6 }}>
                Sign in to manage your domains and passkey configuration.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <LoginButton />
                <div style={{ textAlign: 'center', color: '#a1a1aa', fontSize: '0.875rem' }}>
                    or
                </div>
                <RegisterButton />
            </div>
            <p style={{ marginTop: '2rem', fontSize: '0.875rem', color: '#71717a' }}>
                Don't have a domain configured? <a href="/signup" style={{ color: '#18181b', textDecoration: 'underline' }}>Sign up instead</a>.
            </p>
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
