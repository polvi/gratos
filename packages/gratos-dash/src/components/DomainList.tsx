import { h } from 'preact';
import { useState, useEffect, useCallback } from 'preact/hooks';
import { AuthProvider, useAuth } from '@gratos/preact';

const CNAME_NAME = 'authgravity';
const CNAME_TARGET = 'cname.authgravity.net';

type Domain = {
    id: string;
    domain: string;
    status: 'pending' | 'active';
    ssl_status?: string;
    created_at?: number;
    claimed_at?: number;
};

function CopyButton({ text }: { text: string }) {
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch { /* fallback */ }
    };

    return (
        <button
            onClick={handleCopy}
            title="Copy to clipboard"
            style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                padding: '0.125rem 0.25rem',
                fontSize: '0.75rem',
                flexShrink: 0,
                color: copied ? '#16a34a' : '#a1a1aa',
                verticalAlign: 'middle',
            }}
        >
            {copied ? (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
            ) : (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
            )}
        </button>
    );
}

function PendingDetails({ domain, provisionerBaseUrl, onClaimed }: {
    domain: Domain;
    provisionerBaseUrl: string;
    onClaimed: () => void;
}) {
    const [phase, setPhase] = useState<'waiting_for_dns' | 'dns_mismatch' | 'provisioning' | 'error'>('waiting_for_dns');
    const [dnsLookup, setDnsLookup] = useState(`${CNAME_NAME}.${domain.domain}`);
    const [dnsExpected, setDnsExpected] = useState(CNAME_TARGET);
    const [dnsActual, setDnsActual] = useState<string | null>(null);
    const [dnsFound, setDnsFound] = useState<Array<{ type: string; value: string }>>([]);
    const [error, setError] = useState('');

    const pollActivate = useCallback(async () => {
        try {
            const res = await fetch(`${provisionerBaseUrl}/claims/${domain.id}/activate`, {
                method: 'POST',
                credentials: 'include',
            });
            const data = await res.json();

            if (!res.ok) {
                setError(data.error || 'Activation failed');
                setPhase('error');
                return;
            }

            if (data.status === 'claimed') {
                onClaimed();
                return;
            }

            if (data.dns_lookup) setDnsLookup(data.dns_lookup);
            if (data.dns_expected) setDnsExpected(data.dns_expected);
            setDnsActual(data.dns_actual ?? null);
            setDnsFound(data.dns_found || []);

            if (data.status === 'dns_mismatch') {
                setPhase('dns_mismatch');
            } else if (data.status === 'waiting_for_dns') {
                setPhase('waiting_for_dns');
            } else if (data.status === 'provisioning') {
                setPhase('provisioning');
            }
        } catch {
            // Ignore transient poll errors
        }
    }, [domain.id, provisionerBaseUrl, onClaimed]);

    useEffect(() => {
        pollActivate();
        const interval = setInterval(pollActivate, 5000);
        return () => clearInterval(interval);
    }, [pollActivate]);

    const cardStyle = {
        background: '#f9fafb',
        border: '1px solid #e4e4e7',
        borderRadius: '0.375rem',
        padding: '0.75rem',
        marginBottom: '0.5rem',
    };

    const codeStyle = {
        background: '#f4f4f5',
        padding: '0.125rem 0.375rem',
        borderRadius: '0.25rem',
        fontFamily: 'monospace',
        fontSize: '0.75rem',
        wordBreak: 'break-all' as const,
    };

    const labelStyle = {
        color: '#71717a',
        fontWeight: 600 as const,
        fontSize: '0.7rem',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
        marginBottom: '0.125rem',
    };

    if (phase === 'error') {
        return (
            <div style={{ padding: '0.75rem 0' }}>
                <p style={{ color: '#ef4444', fontSize: '0.8rem' }}>{error}</p>
            </div>
        );
    }

    const isMismatch = phase === 'dns_mismatch';

    return (
        <div style={{ padding: '0.75rem 0 0' }}>
            <div style={{ fontSize: '0.8rem', color: '#52525b', marginBottom: '0.5rem' }}>
                {phase === 'waiting_for_dns' && (dnsFound.length > 0
                    ? `Found existing records for ${CNAME_NAME}.${domain.domain}, but no CNAME.`
                    : 'No DNS records found yet. Add the CNAME record below.')}
                {phase === 'dns_mismatch' && 'A CNAME record exists but points to the wrong target.'}
                {phase === 'provisioning' && `DNS verified. Setting up ${CNAME_NAME}.${domain.domain}...`}
            </div>

            {phase !== 'provisioning' && (
                <>
                    <div style={cardStyle}>
                        <div style={labelStyle}>Required CNAME</div>
                        <div style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>
                            <div style={{ marginBottom: '0.375rem' }}>
                                <span style={{ color: '#71717a', fontSize: '0.7rem' }}>Name: </span>
                                <span style={codeStyle}>{CNAME_NAME}</span>
                                <CopyButton text={CNAME_NAME || ''} />
                            </div>
                            <div>
                                <span style={{ color: '#71717a', fontSize: '0.7rem' }}>Target: </span>
                                <span style={codeStyle}>{dnsExpected}</span>
                                <CopyButton text={dnsExpected} />
                            </div>
                        </div>
                    </div>

                    <div style={{
                        ...cardStyle,
                        border: isMismatch ? '1px solid #fca5a5' : '1px solid #e4e4e7',
                        background: isMismatch ? '#fef2f2' : '#f9fafb',
                    }}>
                        <div style={labelStyle}>DNS Lookup</div>
                        <div style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>
                            <div style={{ marginBottom: '0.25rem' }}>
                                <span style={{ color: '#71717a', fontSize: '0.7rem' }}>Looking up: </span>
                                <span style={codeStyle}>{dnsLookup}</span>
                            </div>
                            <div>
                                <span style={{ color: '#71717a', fontSize: '0.7rem' }}>Resolves to: </span>
                                {dnsActual ? (
                                    <span style={{ ...codeStyle, background: isMismatch ? '#fee2e2' : '#f4f4f5' }}>
                                        CNAME {dnsActual}
                                    </span>
                                ) : dnsFound.length > 0 ? (
                                    <span>
                                        {dnsFound.map((r, i) => (
                                            <span key={i} style={{ ...codeStyle, background: '#fef9c3', marginRight: '0.25rem' }}>
                                                {r.type} {r.value}
                                            </span>
                                        ))}
                                    </span>
                                ) : (
                                    <span style={{ fontSize: '0.75rem', color: '#a1a1aa', fontStyle: 'italic' }}>
                                        No records found
                                    </span>
                                )}
                            </div>
                        </div>
                        {isMismatch && (
                            <p style={{ fontSize: '0.7rem', color: '#991b1b', marginTop: '0.5rem' }}>
                                Update the CNAME to match the required target above.
                            </p>
                        )}
                        {!isMismatch && dnsFound.length > 0 && (
                            <p style={{ fontSize: '0.7rem', color: '#854d0e', marginTop: '0.5rem' }}>
                                Found existing records but no CNAME. Remove these and add a CNAME instead.
                            </p>
                        )}
                    </div>
                </>
            )}

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{
                    padding: '0.2rem 0.5rem',
                    borderRadius: '9999px',
                    fontSize: '0.7rem',
                    fontWeight: 600,
                    background: phase === 'provisioning' ? '#dbeafe' : isMismatch ? '#fee2e2' : '#fef9c3',
                    color: phase === 'provisioning' ? '#1e40af' : isMismatch ? '#991b1b' : '#854d0e',
                }}>
                    {phase === 'waiting_for_dns' && 'No CNAME found'}
                    {phase === 'dns_mismatch' && 'Wrong target'}
                    {phase === 'provisioning' && 'Activating...'}
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ color: '#a1a1aa', fontSize: '0.7rem' }}>Auto-checking every 5s</span>
                    <button
                        onClick={() => pollActivate()}
                        style={{
                            padding: '0.25rem 0.5rem',
                            background: '#f4f4f5',
                            border: '1px solid #d4d4d8',
                            borderRadius: '0.375rem',
                            fontSize: '0.75rem',
                            cursor: 'pointer',
                        }}
                    >
                        Refresh
                    </button>
                </div>
            </div>
        </div>
    );
}

function ActiveDetails({ domain, provisionerBaseUrl }: { domain: Domain; provisionerBaseUrl: string }) {
    const endpoint = `${CNAME_NAME}.${domain.domain}`;
    const [sslStatus, setSslStatus] = useState<string>(domain.ssl_status || 'pending');

    useEffect(() => {
        if (sslStatus === 'active') return;

        const checkSsl = async () => {
            try {
                const res = await fetch(`${provisionerBaseUrl}/domains/${domain.id}/ssl`, {
                    credentials: 'include',
                });
                if (res.ok) {
                    const data = await res.json() as any;
                    setSslStatus(data.ssl_status || 'pending');
                }
            } catch {
                // Ignore transient errors
            }
        };

        checkSsl();
        const interval = setInterval(checkSsl, 5000);
        return () => clearInterval(interval);
    }, [domain.id, provisionerBaseUrl, sslStatus]);

    const sslReady = sslStatus === 'active';

    const cardStyle = {
        background: '#f9fafb',
        border: '1px solid #e4e4e7',
        borderRadius: '0.375rem',
        padding: '0.75rem',
        marginBottom: '0.5rem',
    };

    const codeStyle = {
        background: '#f4f4f5',
        padding: '0.125rem 0.375rem',
        borderRadius: '0.25rem',
        fontFamily: 'monospace',
        fontSize: '0.75rem',
        wordBreak: 'break-all' as const,
    };

    return (
        <div style={{ padding: '0.75rem 0 0' }}>
            {!sslReady && (
                <div style={{
                    background: '#fffbeb',
                    border: '1px solid #fde68a',
                    borderRadius: '0.375rem',
                    padding: '0.75rem',
                    marginBottom: '0.5rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                    <span style={{ color: '#92400e', fontSize: '0.8rem' }}>
                        SSL certificate provisioning — this usually takes a few minutes.
                    </span>
                </div>
            )}

            <div style={cardStyle}>
                <div style={{ color: '#71717a', fontWeight: 600, fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.25rem' }}>
                    Auth Endpoint
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                    <span style={codeStyle}>{endpoint}</span>
                    <CopyButton text={endpoint} />
                </div>
            </div>

            <div style={cardStyle}>
                <div style={{ color: '#71717a', fontWeight: 600, fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.25rem' }}>
                    API Base URL
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                    <span style={codeStyle}>https://{endpoint}</span>
                    <CopyButton text={`https://${endpoint}`} />
                </div>
            </div>

            <div style={cardStyle}>
                <div style={{ color: '#71717a', fontWeight: 600, fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>
                    Quick Start
                </div>
                <pre style={{
                    background: '#f4f4f5',
                    padding: '0.5rem',
                    borderRadius: '0.25rem',
                    fontSize: '0.7rem',
                    fontFamily: 'monospace',
                    overflowX: 'auto',
                    whiteSpace: 'pre',
                    lineHeight: 1.5,
                    margin: 0,
                }}>
                    <code>{`<AuthProvider apiBaseUrl="https://${endpoint}">
  <RegisterButton />
  <LoginButton />
</AuthProvider>`}</code>
                </pre>
            </div>

            <a
                href={`https://${endpoint}/demo`}
                target="_blank"
                rel="noopener"
                style={{
                    display: 'inline-block',
                    padding: '0.375rem 0.75rem',
                    background: sslReady ? '#f4f4f5' : '#e4e4e7',
                    border: '1px solid #d4d4d8',
                    borderRadius: '0.375rem',
                    fontSize: '0.75rem',
                    color: sslReady ? '#18181b' : '#a1a1aa',
                    textDecoration: 'none',
                    fontWeight: 500,
                    pointerEvents: sslReady ? 'auto' : 'none',
                }}
            >
                {sslReady ? 'Open Demo' : 'Waiting for SSL...'}
            </a>
        </div>
    );
}

function DomainListInner({ provisionerBaseUrl }: { provisionerBaseUrl: string }) {
    const { isAuthenticated } = useAuth();
    const [domains, setDomains] = useState<Domain[]>([]);
    const [loading, setLoading] = useState(true);
    const [deleting, setDeleting] = useState<string | null>(null);
    const [error, setError] = useState('');
    const [expandedId, setExpandedId] = useState<string | null>(null);

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
            if (expandedId === d.id) setExpandedId(null);
        } catch {
            setError('Network error');
        } finally {
            setDeleting(null);
        }
    };

    if (!isAuthenticated) {
        return null; // Handled by middleware redirect
    }

    if (loading) {
        return (
            <div style={{ margin: '2rem 0', textAlign: 'center' }}>
                <p style={{ color: '#71717a' }}>Loading...</p>
            </div>
        );
    }

    return (
        <div style={{ width: '100%', margin: '2rem 0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                <h1 style={{ fontSize: '1.75rem', fontWeight: 700 }}>Your Domains</h1>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
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
                            }}
                        >
                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                gap: '1rem',
                            }}>
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
                                <div style={{ display: 'flex', gap: '0.5rem', flexShrink: 0 }}>
                                    <button
                                        onClick={() => setExpandedId(expandedId === d.id ? null : d.id)}
                                        style={{
                                            padding: '0.375rem 0.75rem',
                                            background: expandedId === d.id ? '#18181b' : '#f4f4f5',
                                            border: '1px solid #d4d4d8',
                                            borderRadius: '0.375rem',
                                            color: expandedId === d.id ? '#fff' : '#18181b',
                                            fontSize: '0.8rem',
                                            cursor: 'pointer',
                                            fontWeight: 500,
                                        }}
                                    >
                                        {expandedId === d.id ? 'Hide Details' : 'Details'}
                                    </button>
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
                                        }}
                                    >
                                        {deleting === d.id ? 'Removing...' : 'Remove'}
                                    </button>
                                </div>
                            </div>

                            {expandedId === d.id && d.status === 'pending' && (
                                <PendingDetails
                                    domain={d}
                                    provisionerBaseUrl={provisionerBaseUrl}
                                    onClaimed={fetchDomains}
                                />
                            )}
                            {expandedId === d.id && d.status === 'active' && (
                                <ActiveDetails domain={d} provisionerBaseUrl={provisionerBaseUrl} />
                            )}
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
