import { h, createContext } from 'preact';
import { useContext, useState, useEffect } from 'preact/hooks';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

interface User {
    id: string;
    username: string;
}

interface AuthContextType {
    user: User | null;
    isLoading: boolean;
    isAuthenticated: boolean;
    login: (user: User) => void;
    logout: () => Promise<void>;
    apiBaseUrl: string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
    children: any;
    apiBaseUrl: string;
}

export function AuthProvider({ children, apiBaseUrl }: AuthProviderProps) {
    const [user, setUser] = useState<User | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        if (!apiBaseUrl) return;

        const checkAuth = async () => {
            try {
                const res = await fetch(`${apiBaseUrl}/v1/whoami`, {
                    credentials: 'include',
                });
                if (res.ok) {
                    const data = await res.json();

                    setUser({ id: data.user_id, username: '' });
                }
            } catch (err) {
                console.error('Failed to check auth', err);
            } finally {
                setIsLoading(false);
            }
        };

        checkAuth();
    }, [apiBaseUrl]);

    const login = (userData: User) => {
        const finalUser = { ...userData };

        // Username is no longer persisted or passed
        finalUser.username = '';
        setUser(finalUser);
    };

    const logout = async () => {
        setUser(null);
        // also call server logout
        if (apiBaseUrl) {
            try {
                await fetch(`${apiBaseUrl}/v1/logout`, { method: 'POST', credentials: 'include' });
            } catch (error) {
                console.error('Failed to log out on server:', error);
            }
        }
    };

    if (!apiBaseUrl) {
        return (
            <div style={{
                padding: '2rem',
                color: '#ef4444',
                fontFamily: 'system-ui, sans-serif',
                textAlign: 'center',
                fontWeight: '500'
            }}>
                Configuration Error: auth server is undefined.
            </div>
        );
    }

    return (
        <AuthContext.Provider value={{ user, isLoading, isAuthenticated: !!user, login, logout, apiBaseUrl }}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}

export function RegisterButton() {
    const { login, apiBaseUrl } = useAuth();
    const [status, setStatus] = useState('');

    const handleRegister = async () => {
        try {
            setStatus('Registering...');
            // No username: the passkey label defaults to "Me" (set server-side
            // in the options; the server never stores it).
            const resp = await fetch(`${apiBaseUrl}/v1/register/options`);
            const options = await resp.json();

            const attResp = await startRegistration({ optionsJSON: options });

            const verifyResp = await fetch(`${apiBaseUrl}/v1/register/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(attResp),
                credentials: 'include',
            });

            const verificationJSON = await verifyResp.json();

            if (verificationJSON && verificationJSON.verified) {
                setStatus('Success!');
                // Server doesn't return username anymore, so we merge it in
                login({ ...verificationJSON.user, username: '' });

                setTimeout(() => setStatus(''), 2000);
            } else {
                setStatus('Failed');
            }
        } catch (error: any) {
            console.error(error);
            setStatus(error.message || String(error));
        }
    };

    return (
        <div style={{ position: 'relative' }}>
            <style>{`
                .register-btn {
                    width: 100%;
                    padding: 8px 16px;
                    height: 40px;
                    cursor: pointer;
                    background: #18181b;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    font-size: 14px;
                    font-weight: 500;
                }
                .register-btn:disabled {
                    background: #a1a1aa;
                    cursor: not-allowed;
                }
                @media (max-width: 600px) {
                    .register-btn {
                        height: 48px; /* Larger touch target */
                        font-size: 16px;
                    }
                }
            `}</style>
            <button
                className="register-btn"
                onClick={handleRegister}
                disabled={status === 'Registering...'}
            >
                {status || 'Create Account'}
            </button>
            {!window.isSecureContext && (
                <div style={{ color: '#ef4444', fontSize: '0.75rem', marginTop: '6px', textAlign: 'center', background: '#fee2e2', padding: '4px', borderRadius: '4px' }}>
                    ⚠️ Not Secure Context. HTTPS required.
                </div>
            )}
        </div>
    );
}

export function LoginButton() {
    const { login, apiBaseUrl } = useAuth();
    const [status, setStatus] = useState('');

    const handleLogin = async () => {
        try {
            setStatus('Login...');
            const resp = await fetch(`${apiBaseUrl}/v1/login/options`);
            const options = await resp.json();

            const asseResp = await startAuthentication({ optionsJSON: options });

            const verifyResp = await fetch(`${apiBaseUrl}/v1/login/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(asseResp),
                credentials: 'include',
            });

            const verifyJSON = await verifyResp.json();

            if (verifyJSON && verifyJSON.verified) {
                setStatus('');
                login(verifyJSON.user);
            } else {
                setStatus('Failed');
                console.error(verifyJSON);
            }
        } catch (error: any) {
            console.error(error);
            setStatus(error.message || String(error));
        }
    };

    return (
        <>
            <style>{`
                .login-btn {
                    padding: 8px 16px;
                    height: 40px;
                    cursor: pointer;
                    background: transparent;
                    color: #18181b;
                    border: 1px solid #e4e4e7;
                    border-radius: 4px;
                    font-size: 14px;
                    font-weight: 500;
                    background: white;
                }
                .login-btn:hover {
                    background: #f4f4f5;
                }
                @media (max-width: 600px) {
                    .login-btn {
                        width: 100%;
                        height: 48px;
                        font-size: 16px;
                    }
                }
            `}</style>
            <button className="login-btn" onClick={handleLogin} disabled={!!status}>
                {status || 'Login'}
            </button>
        </>
    );
}
