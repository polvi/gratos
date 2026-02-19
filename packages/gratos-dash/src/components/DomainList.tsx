import { h } from 'preact';
import { useState, useEffect, useCallback } from 'preact/hooks';
import { AuthProvider, useAuth, LoginButton, RegisterButton } from '@gratos/preact';

type Domain = {
    id: string;
    domain: string;
    status: 'pending' | 'active';
    created_at?: number;
    claimed_at?: number;
};

function DomainListInner({ provisionerBaseUrl }: { provisionerBaseUrl: string }) {
    const { isAuthenticated } = useAuth();
    const [domains, setDomains] = useState<Domain[]>([]);
    const [loading, setLoading] = useState(true);
    const [deleting, setDeleting] = useState<string | null>(null);
    const [error, setError] = useState('');

    const fetchDomains = useCallback(async () => {
        try {
            const res = await fetch(`${provisionerBaseUrl}/domains`, {
                credentials: 'include',
            });
            if (!res.ok) {
                if (res.status === 401) return;
                setError('Failed to load domains');
                return;
            }
            const data = await res.json();
            const all: Domain[] = [
                ...(data.claimed || []),
                ...(data.pending || []),
            ];
            setDomains(all);
        } catch {
            setError('Network error');
        } finally {
            setLoading(false);
        }
    }, [provisionerBaseUrl]);

    useEffect(() => {
        if (isAuthenticated) {
            fetchDomains();
        } else {
            setLoading(false);
        }
    }, [isAuthenticated, fetchDomains]);

    const handleDelete = async (d: Domain) => {
        if (!confirm(`Remove ${d.domain}? This cannot be undone.`)) return;

        setDeleting(d.id);
        setError('');
        try {
            const endpoint = d.status === 'active'
                ? `${provisionerBaseUrl}/domains/${d.id}`
                : `${provisionerBaseUrl}/claims/${d.id}`;
            const res = await fetch(endpoint, {
                method: 'DELETE',
                credentials: 'include',
            });
            if (!res.ok) {
                const data = await res.json();
                setError(data.error || 'Failed to remove domain');
                return;
            }
            setDomains(prev => prev.filter(x => x.id !== d.id));
        } catch {
            setError('Network error');
        } finally {
            setDeleting(null);
        }
    };

    if (!isAuthenticated) {
        return (
            <div style={{ maxWidth: '480px', margin: '3rem auto', padding: '0 1.5rem' }}>
                <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '0.5rem' }}>
                    Your Domains
                </h1>
                <p style={{ color: '#52525b', marginBottom: '2rem', lineHeight: 1.6 }}>
                    Sign in to manage your connected domains.
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <LoginButton />
                    <div style={{ textAlign: 'center', color: '#a1a1aa', fontSize: '0.875rem' }}>or</div>
                    <RegisterButton />
                </div>
            </div>
        );
    }

    if (loading) {
        return (
            <div style={{ maxWidth: '480px', margin: '3rem auto', padding: '0 1.5rem', textAlign: 'center' }}>
                <p style={{ color: '#71717a' }}>Loading...</p>
            </div>
        );
    }

    return (
        <div style={{ maxWidth: '480px', margin: '3rem auto', padding: '0 1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                <h1 style={{ fontSize: '1.75rem', fontWeight: 700 }}>Your Domains</h1>
                <a
                    href="/signup"
                    style={{
                        padding: '0.5rem 1rem',
                        background: '#18181b',
                        color: '#fff',
                        textDecoration: 'none',
                        borderRadius: '0.375rem',
                        fontSize: '0.875rem',
                        fontWeight: 600,
                    }}
                >
                    Add Domain
                </a>
            </div>

            {error && (
                <p style={{ color: '#ef4444', fontSize: '0.875rem', marginBottom: '1rem' }}>{error}</p>
            )}

            {domains.length === 0 ? (
                <div style={{
                    border: '1px dashed #d4d4d8',
                    borderRadius: '0.5rem',
                    padding: '2rem',
                    textAlign: 'center',
                }}>
                    <p style={{ color: '#71717a', marginBottom: '1rem' }}>No domains connected yet.</p>
                    <a href="/signup" style={{ color: '#18181b', fontWeight: 600 }}>Add your first domain</a>
                </div>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {domains.map(d => (
                        <div
                            key={d.id}
                            style={{
                                background: '#fff',
                                border: '1px solid #e4e4e7',
                                borderRadius: '0.5rem',
                                padding: '1rem 1.25rem',
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                gap: '1rem',
                            }}
                        >
                            <div style={{ minWidth: 0 }}>
                                <div style={{
                                    fontWeight: 600,
                                    fontSize: '0.95rem',
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                }}>
                                    {d.domain}
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
                                    <span style={{
                                        display: 'inline-block',
                                        width: '0.5rem',
                                        height: '0.5rem',
                                        borderRadius: '50%',
                                        background: d.status === 'active' ? '#22c55e' : '#f59e0b',
                                    }} />
                                    <span style={{ fontSize: '0.75rem', color: '#71717a' }}>
                                        {d.status === 'active' ? 'Active' : 'Pending'}
                                    </span>
                                </div>
                            </div>
                            <button
                                onClick={() => handleDelete(d)}
                                disabled={deleting === d.id}
                                style={{
                                    padding: '0.375rem 0.75rem',
                                    background: 'none',
                                    border: '1px solid #fca5a5',
                                    borderRadius: '0.375rem',
                                    color: '#dc2626',
                                    fontSize: '0.8rem',
                                    cursor: deleting === d.id ? 'not-allowed' : 'pointer',
                                    opacity: deleting === d.id ? 0.5 : 1,
                                    flexShrink: 0,
                                }}
                            >
                                {deleting === d.id ? 'Removing...' : 'Remove'}
                            </button>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

export function DomainList({ apiBaseUrl, provisionerBaseUrl }: {
    apiBaseUrl: string;
    provisionerBaseUrl: string;
}) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <DomainListInner provisionerBaseUrl={provisionerBaseUrl} />
        </AuthProvider>
    );
}
