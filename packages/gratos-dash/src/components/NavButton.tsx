import { h } from 'preact';
import { AuthProvider, useAuth } from '@gratos/preact';

function NavButtonInner({ currentPath }: { currentPath: string }) {
    const { isAuthenticated, logout, isLoading } = useAuth();

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

    return (
        <a
            href="/login"
            class={`nav-button ${currentPath === '/login' || currentPath === '/login/' ? 'active' : ''}`}
        >
            Log In
        </a>
    );
}

export function NavButton({ apiBaseUrl, currentPath }: { apiBaseUrl: string, currentPath: string }) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <NavButtonInner currentPath={currentPath} />
        </AuthProvider>
    );
}
