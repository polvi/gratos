import { h } from 'preact';
import { useAuth } from './AuthContext';

export function LogoutButton() {
    const { logout } = useAuth();
    return <button onClick={logout}>Logout</button>;
}
