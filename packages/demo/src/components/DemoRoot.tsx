import { h } from 'preact';
import { AuthProvider, useAuth, LoginButton, LogoutButton, RegisterButton, UserProfile } from '@gratos/preact';

function Header() {
    const { isAuthenticated } = useAuth();

    return (
        <>
            <style>{`
                .header-container {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 1rem 2rem;
                    background: #fff;
                    border-bottom: 1px solid #e4e4e7;
                }
                .logo-text {
                    font-weight: 800;
                    font-size: 1.25rem;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }
                .auth-actions {
                    display: flex;
                    align-items: center;
                    gap: 1rem;
                }
                @media (max-width: 600px) {
                    .header-container {
                        flex-direction: column;
                        gap: 1rem;
                        padding: 1rem;
                    }
                    .auth-actions {
                        width: 100%;
                        justify-content: center;
                        flex-wrap: wrap;
                    }
                }
            `}</style>
            <header className="header-container">
                <div className="logo-text">
                    Gratos Demo
                </div>
                <div className="auth-actions">
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
        </>
    );
}

function Hero() {
    const { user, isAuthenticated } = useAuth();

    return (
        <>
            <style>{`
                .hero-container {
                    max-width: 800px;
                    margin: 4rem auto;
                    padding: 0 2rem;
                    text-align: center;
                }
                .hero-title {
                    font-size: 3rem;
                    margin-bottom: 1rem;
                    color: #18181b;
                }
                .hero-subtitle {
                    font-size: 1.25rem;
                    color: #52525b;
                    line-height: 1.6;
                }
                .features-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 2rem;
                    text-align: left;
                }
                @media (max-width: 600px) {
                    .hero-container {
                        margin: 2rem auto;
                        padding: 0 1rem;
                    }
                    .hero-title {
                        font-size: 2rem;
                    }
                    .hero-subtitle {
                        font-size: 1rem;
                    }
                    .features-grid {
                        grid-template-columns: 1fr;
                        gap: 1rem;
                    }
                }
            `}</style>
            <main className="hero-container">
                <h1 className="hero-title">
                    Welcome {isAuthenticated && user ? (user.username ? `back, ${user.username}!` : 'back!') : 'to the Gratos demo'}
                </h1>
                <p className="hero-subtitle">
                    Experience the future of authentication. Secure, passwordless, and seamless.
                    {isAuthenticated ? ' You are currently logged in and can access your dashboard.' : ' Sign in to manage your reservation.'}
                </p>

                <div style={{ marginTop: '3rem', padding: '2rem', background: '#f4f4f5', borderRadius: '1rem' }}>
                    <h3 style={{ margin: '0 0 1rem 0' }}>Why Passkeys?</h3>
                    <div className="features-grid">
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
        </>
    );
}

import { LoginPrompt } from './LoginPrompt';

export function DemoRoot({ apiBaseUrl, loginBaseUrl, clientId, returnTo }: { apiBaseUrl: string; loginBaseUrl: string; clientId?: string; returnTo?: string }) {
    const loginUrl = `${loginBaseUrl}/login?client_id=${clientId}&return_to=${encodeURIComponent(returnTo || (typeof window !== 'undefined' ? window.location.origin : ''))}`;

    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>

            <div style={{ minHeight: '100vh', background: '#fafafa', fontFamily: 'system-ui, sans-serif' }}>
                <Header />
                <Hero />
                {clientId && <LoginPrompt loginUrl={loginUrl} apiBaseUrl={apiBaseUrl} />}

            </div>
        </AuthProvider>
    );
}


