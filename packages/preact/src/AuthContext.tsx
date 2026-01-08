import { createContext } from 'preact';
import { useContext, useState, useEffect } from 'preact/hooks';

interface User {
    id: string;
    username: string;
}

interface AuthContextType {
    user: User | null;
    isLoading: boolean;
    isAuthenticated: boolean;
    login: (user: User) => void;
    logout: () => void;
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
        const checkAuth = async () => {
            try {
                const res = await fetch(`${apiBaseUrl}/whoami`, {
                    credentials: 'include',
                });
                if (res.ok) {
                    const data = await res.json();
                    setUser(data.user);
                }
            } catch (err) {
                console.error('Failed to check auth', err);
            } finally {
                setIsLoading(false);
            }
        };

        checkAuth();
    }, [apiBaseUrl]);

    const login = (userData: User) => setUser(userData);
    const logout = () => {
        setUser(null);
        // also call server logout
        fetch(`${apiBaseUrl}/logout`, { method: 'POST', credentials: 'include' }).catch(console.error);
    };

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
