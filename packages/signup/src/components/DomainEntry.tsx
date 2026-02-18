import { h } from 'preact';
import { useState } from 'preact/hooks';

export function DomainEntry({ provisionerBaseUrl, onClaimed }: {
    provisionerBaseUrl: string;
    onClaimed: (claimId: string, domain: string, cnameTarget: string) => void;
}) {
    const [domain, setDomain] = useState('');
    const [error, setError] = useState('');
    const [submitting, setSubmitting] = useState(false);

    const handleSubmit = async (e: Event) => {
        e.preventDefault();
        setError('');

        let trimmed = domain.trim().toLowerCase();
        if (!trimmed) {
            setError('Please enter a domain.');
            return;
        }

        // Strip letsident. prefix if user included it
        if (trimmed.startsWith('letsident.')) {
            trimmed = trimmed.slice('letsident.'.length);
        }

        const domainRegex = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
        if (!domainRegex.test(trimmed)) {
            setError('Enter a valid domain like example.com');
            return;
        }

        setSubmitting(true);
        try {
            const res = await fetch(`${provisionerBaseUrl}/claims`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: trimmed }),
            });

            const data = await res.json();

            if (!res.ok) {
                setError(data.error || 'Failed to create claim');
                return;
            }

            onClaimed(data.id, trimmed, data.cname_target);
        } catch (err) {
            setError('Network error. Please try again.');
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <form onSubmit={handleSubmit}>
            <label style={{ display: 'block', fontWeight: 600, marginBottom: '0.5rem' }}>
                Your domain
            </label>
            <p style={{ color: '#71717a', fontSize: '0.8rem', marginBottom: '0.5rem' }}>
                We'll create <strong>letsident.yourdomain.com</strong> as your auth endpoint.
            </p>
            <input
                type="text"
                placeholder="example.com"
                value={domain}
                onInput={(e) => setDomain((e.target as HTMLInputElement).value)}
                disabled={submitting}
                style={{
                    width: '100%',
                    padding: '0.625rem 0.75rem',
                    border: '1px solid #d4d4d8',
                    borderRadius: '0.375rem',
                    fontSize: '1rem',
                    marginBottom: '0.5rem',
                }}
            />
            {error && (
                <p style={{ color: '#ef4444', fontSize: '0.875rem', marginBottom: '0.5rem' }}>
                    {error}
                </p>
            )}
            <button
                type="submit"
                disabled={submitting}
                style={{
                    width: '100%',
                    padding: '0.625rem',
                    background: '#18181b',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '0.375rem',
                    fontSize: '1rem',
                    fontWeight: 600,
                    cursor: submitting ? 'not-allowed' : 'pointer',
                    opacity: submitting ? 0.6 : 1,
                    marginTop: '0.5rem',
                }}
            >
                {submitting ? 'Setting up...' : 'Claim Domain'}
            </button>
        </form>
    );
}
