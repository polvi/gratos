import { h } from 'preact';
import { useAuth } from './AuthContext';

export function UserProfile() {
    const { user, isAuthenticated } = useAuth();

    if (!isAuthenticated || !user || !user.username) return null;

    return (
        <span style={{ fontWeight: 'bold' }}>
            {user.username}
        </span>
    );
}
