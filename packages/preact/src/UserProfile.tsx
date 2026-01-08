import { h } from 'preact';
import { useAuth } from './AuthContext';

export function UserProfile() {
    const { user, isAuthenticated } = useAuth();

    if (!isAuthenticated || !user) return null;

    return (
        <span style={{ fontWeight: 'bold' }}>
            {user.username}
        </span>
    );
}
