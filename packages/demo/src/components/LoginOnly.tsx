import { h } from 'preact';
import { useEffect } from 'preact/hooks';
import { AuthProvider, LoginButton, useAuth } from '@gratos/preact';

function LoginContent() {
    const { isAuthenticated, user, logout } = useAuth();

    useEffect(() => {
        if (isAuthenticated) {
            const params = new URLSearchParams(window.location.search);
            const returnTo = params.get('return_to');
            if (returnTo) {
                window.location.href = returnTo;
            }
        }
    }, [isAuthenticated]);

    if (isAuthenticated) {
        // If we are about to redirect, maybe show a "Redirecting..." message?
        // But for now, user might see "You are logged in" briefly.
        return (
            <div style={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'center',
                height: '100vh',
                fontFamily: 'system-ui, sans-serif',
                gap: '1rem'
            }}>
                <div style={{ fontSize: '1.2rem', color: '#18181b' }}>
                    You are logged in.
                    {new URLSearchParams(window.location.search).get('return_to') && (
                        <div style={{ fontSize: '0.9rem', color: '#71717a', marginTop: '0.5rem' }}>
                            Redirecting back to application...
                        </div>
                    )}
                </div>
                <button
                    onClick={() => {
                        logout();
                        // State update will cause re-render to show LoginButton, acting as a "redirect"
                    }}
                    style={{
                        padding: '0.6rem 1.2rem',
                        fontSize: '1rem',
                        background: '#f4f4f5',
                        border: '1px solid #e4e4e7',
                        borderRadius: '0.375rem',
                        cursor: 'pointer',
                        color: '#18181b'
                    }}
                    onMouseOver={(e: any) => (e.currentTarget.style.background = '#e4e4e7')}
                    onMouseOut={(e: any) => (e.currentTarget.style.background = '#f4f4f5')}
                >
                    Logout
                </button>
            </div>
        );
    }

    return (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
            <LoginButton />
        </div>
    );
}

export function LoginOnly({ apiBaseUrl }: { apiBaseUrl: string }) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <LoginContent />
        </AuthProvider>
    );
}
