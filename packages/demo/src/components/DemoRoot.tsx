import { h } from 'preact';
import { AuthProvider, useAuth, LoginButton, LogoutButton, RegisterButton, UserProfile } from '@gratos/preact';

function Header() {
    const { isAuthenticated } = useAuth();

    return (
        <header style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '1rem 2rem',
            background: '#fff',
            borderBottom: '1px solid #e4e4e7'
        }}>
            <div style={{ fontWeight: 800, fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontSize: '1.5rem' }}>🏨</span> Gratos Hotel
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                {isAuthenticated ? (
                    <>
                        <UserProfile />
                        <LogoutButton />
                    </>
                ) : (
                    <>
                        <LoginButton />
                        <RegisterButton />
                    </>
                )}
            </div>
        </header>
    );
}

function Hero() {
    const { user, isAuthenticated } = useAuth();

    return (
        <main style={{ maxWidth: '800px', margin: '4rem auto', padding: '0 2rem', textAlign: 'center' }}>
            <h1 style={{ fontSize: '3rem', marginBottom: '1rem', color: '#18181b' }}>
                Welcome {isAuthenticated && user ? `back, ${user.username}!` : 'to Gratos Hotel'}
            </h1>
            <p style={{ fontSize: '1.25rem', color: '#52525b', lineHeight: 1.6 }}>
                Experience the future of authentication. Secure, passwordless, and seamless.
                {isAuthenticated ? ' You are currently logged in and can access your dashboard.' : ' Sign in to manage your reservation.'}
            </p>

            <div style={{ marginTop: '3rem', padding: '2rem', background: '#f4f4f5', borderRadius: '1rem' }}>
                <h3 style={{ margin: '0 0 1rem 0' }}>Why Passkeys?</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '2rem', textAlign: 'left' }}>
                    <div>
                        <strong>🔒 Secure</strong>
                        <p style={{ margin: '0.5rem 0 0 0', color: '#71717a' }}>Phishing-resistant by design.</p>
                    </div>
                    <div>
                        <strong>⚡ Fast</strong>
                        <p style={{ margin: '0.5rem 0 0 0', color: '#71717a' }}>No more typing complex passwords.</p>
                    </div>
                    <div>
                        <strong>😊 Easy</strong>
                        <p style={{ margin: '0.5rem 0 0 0', color: '#71717a' }}>Use your fingerprint or FaceID.</p>
                    </div>
                </div>
            </div>
        </main>
    );
}

export function DemoRoot({ apiBaseUrl }: { apiBaseUrl: string }) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <div style={{ minHeight: '100vh', background: '#fafafa', fontFamily: 'system-ui, sans-serif' }}>
                <Header />
                <Hero />
            </div>
        </AuthProvider>
    );
}
