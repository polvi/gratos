import { h } from 'preact';
import { useEffect, useRef } from 'preact/hooks';
import { AuthProvider, useAuth, LoginButton, RegisterButton } from './auth';

function HomeAuthInner() {
    const { isAuthenticated, isLoading } = useAuth();
    const wasAuthed = useRef<boolean | null>(null);

    // Send freshly signed-in users to the dashboard, but leave visitors who
    // already had a session on the homepage (they get a Dashboard link).
    useEffect(() => {
        if (isLoading) return;
        if (wasAuthed.current === null) {
            wasAuthed.current = isAuthenticated;
            return;
        }
        if (isAuthenticated && !wasAuthed.current) {
            window.location.href = '/domains';
        }
    }, [isLoading, isAuthenticated]);

    if (isLoading) {
        return <div style={{ height: '120px' }} />;
    }

    return (
        <div style={{
            background: '#f9fafb',
            border: '1px solid #e4e4e7',
            borderRadius: '0.5rem',
            padding: '1.5rem',
            marginTop: '2rem',
            textAlign: 'left',
        }}>
            <div style={{
                color: '#71717a',
                fontWeight: 600,
                fontSize: '0.7rem',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: '1rem',
            }}>
                Try it out
            </div>
            {isAuthenticated ? (
                <a
                    href="/domains"
                    style={{
                        display: 'inline-block',
                        padding: '0.5rem 1.25rem',
                        background: '#18181b',
                        color: '#fff',
                        textDecoration: 'none',
                        borderRadius: '0.375rem',
                        fontSize: '0.875rem',
                        fontWeight: 600,
                    }}
                >
                    Go to Dashboard
                </a>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxWidth: '28rem' }}>
                    <RegisterButton />
                    <div style={{ textAlign: 'center', color: '#a1a1aa', fontSize: '0.875rem' }}>
                        or
                    </div>
                    <LoginButton />
                </div>
            )}
        </div>
    );
}

export function HomeAuth({ apiBaseUrl }: { apiBaseUrl: string }) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <HomeAuthInner />
        </AuthProvider>
    );
}
