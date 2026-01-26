import { useState, useEffect } from 'preact/hooks';
import { useAuth } from './AuthContext';

interface Client {
    id: string;
    domain: string;
    domain_setting: string;
    created_at: number;
}

export function Admin() {
    const { apiBaseUrl, isAuthenticated, isLoading } = useAuth();
    const [clients, setClients] = useState<Client[]>([]);
    const [loadingClients, setLoadingClients] = useState(false);
    const [form, setForm] = useState({ domain: '', domain_setting: '' });
    const [error, setError] = useState('');

    useEffect(() => {
        if (isAuthenticated && apiBaseUrl) {
            fetchClients();
        }
    }, [isAuthenticated, apiBaseUrl]);

    async function fetchClients() {
        setLoadingClients(true);
        try {
            const res = await fetch(`${apiBaseUrl}/clients`, { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                setClients(data.clients);
            }
        } catch (e) {
            console.error('Failed to fetch clients', e);
        } finally {
            setLoadingClients(false);
        }
    }

    async function handleSubmit(e: any) {
        e.preventDefault();
        setError('');
        if (!form.domain || !form.domain_setting) {
            setError('Both fields are required');
            return;
        }

        try {
            const res = await fetch(`${apiBaseUrl}/clients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(form)
            });
            if (res.ok) {
                const newClient = await res.json();
                setClients([newClient, ...clients]);
                setForm({ domain: '', domain_setting: '' });
            } else {
                const err = await res.json();
                setError(err.error || 'Failed to create client');
            }
        } catch (e) {
            setError('Network error');
        }
    }

    async function deleteClient(id: string) {
        if (!confirm('Are you sure you want to delete this client?')) return;
        try {
            const res = await fetch(`${apiBaseUrl}/clients/${id}`, {
                method: 'DELETE',
                credentials: 'include'
            });
            if (res.ok) {
                setClients(clients.filter(c => c.id !== id));
            } else {
                alert('Failed to delete');
            }
        } catch (e) {
            alert('Error deleting client');
        }
    }

    if (isLoading) return <div>Loading...</div>;
    if (!isAuthenticated) return <div style={{ padding: '2rem' }}>Please login to access admin.</div>;

    return (
        <div style={{ padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
            <h1 style={{ fontSize: '1.5rem', marginBottom: '1rem', fontWeight: 'bold' }}>Admin: Manage Clients</h1>

            <div style={{ background: '#f9f9f9', padding: '1.5rem', borderRadius: '8px', marginBottom: '2rem' }}>
                <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>Add New Client</h2>
                {error && <div style={{ color: 'red', marginBottom: '0.5rem' }}>{error}</div>}
                <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1 }}>
                        <label style={{ display: 'block', marginBottom: '0.5rem' }}>Domain</label>
                        <input
                            type="text"
                            placeholder="id.example.com"
                            value={form.domain}
                            onInput={(e: any) => setForm({ ...form, domain: e.target.value })}
                            style={{ width: '100%', padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }}
                        />
                    </div>
                    <div style={{ flex: 1 }}>
                        <label style={{ display: 'block', marginBottom: '0.5rem' }}>Cookie Domain</label>
                        <input
                            type="text"
                            placeholder="example.com"
                            value={form.domain_setting}
                            onInput={(e: any) => setForm({ ...form, domain_setting: e.target.value })}
                            style={{ width: '100%', padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }}
                        />
                    </div>
                    <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                        <button type="submit" style={{ padding: '0.5rem 1rem', background: '#333', color: 'white', borderRadius: '4px', border: 'none', cursor: 'pointer' }}>
                            Add Client
                        </button>
                    </div>
                </form>
            </div>

            <div>
                <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>Existing Clients</h2>
                {loadingClients ? (
                    <div>Loading clients...</div>
                ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                            <tr style={{ background: '#eee', textAlign: 'left' }}>
                                <th style={{ padding: '0.5rem' }}>ID</th>
                                <th style={{ padding: '0.5rem' }}>Domain</th>
                                <th style={{ padding: '0.5rem' }}>Cookie Domain</th>
                                <th style={{ padding: '0.5rem' }}>Created At</th>
                                <th style={{ padding: '0.5rem' }}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {clients.length === 0 && (
                                <tr>
                                    <td colSpan={5} style={{ padding: '1rem', textAlign: 'center' }}>No clients found.</td>
                                </tr>
                            )}
                            {clients.map(client => (
                                <tr key={client.id} style={{ borderBottom: '1px solid #eee' }}>
                                    <td style={{ padding: '0.5rem', fontFamily: 'monospace', fontSize: '0.9rem' }}>{client.id}</td>
                                    <td style={{ padding: '0.5rem' }}>{client.domain}</td>
                                    <td style={{ padding: '0.5rem' }}>{client.domain_setting}</td>
                                    <td style={{ padding: '0.5rem', fontSize: '0.9rem' }}>{new Date(client.created_at).toLocaleString()}</td>
                                    <td style={{ padding: '0.5rem' }}>
                                        <button
                                            onClick={() => deleteClient(client.id)}
                                            style={{ padding: '0.25rem 0.5rem', background: '#ef4444', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                                        >
                                            Delete
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}
