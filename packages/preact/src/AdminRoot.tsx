import { AuthProvider } from './AuthContext';
import { Admin } from './Admin';
import { LoginButton } from './LoginButton';
import { LogoutButton } from './LogoutButton';
import { useAuth } from './AuthContext';

function AdminHeader() {
    const { isAuthenticated } = useAuth();
    return (
         <div style={{ display: 'flex', justifyContent: 'space-between', padding: '1rem 2rem', borderBottom: '1px solid #eee', background: 'white' }}>
            <div style={{ fontWeight: 'bold' }}>Gratos Admin</div>
            <div>
                {isAuthenticated ? <LogoutButton /> : <LoginButton />}
            </div>
         </div>
    );
}

export function AdminRoot({ apiBaseUrl }: { apiBaseUrl: string }) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <div style={{ minHeight: '100vh', background: '#fafafa', fontFamily: 'system-ui, sans-serif' }}>
                <AdminHeader />
                <Admin />
            </div>
        </AuthProvider>
    );
}
