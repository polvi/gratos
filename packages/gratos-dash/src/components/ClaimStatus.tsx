import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';

function CopyButton({ text }: { text: string }) {
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch {
            // fallback
        }
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

const CNAME_NAME = 'authgravity';
const CNAME_TARGET = 'cname.authgravity.net';

export function ClaimStatus({ domain, claimId, provisionerBaseUrl, onDone }: {
    domain: string;
    claimId: string;
    provisionerBaseUrl: string;
    onDone: () => void;
}) {
    const cnameName = CNAME_NAME;
    const cnameTarget = CNAME_TARGET;
    const [dcLoading, setDcLoading] = useState(true);
    const [dcSupported, setDcSupported] = useState(false);
    const [dcApplyUrl, setDcApplyUrl] = useState('');
    const [dcProvider, setDcProvider] = useState('');

    useEffect(() => {
        (async () => {
            try {
                const res = await fetch(`${provisionerBaseUrl}/claims/${claimId}/domain-connect`);
                if (res.ok) {
                    const data = await res.json() as any;
                    if (data.supported) {
                        setDcSupported(true);
                        setDcApplyUrl(data.apply_url);
                        setDcProvider(data.provider_name || 'your DNS provider');
                    }
                }
            } catch {
                // Domain Connect not available — fall through to manual
            } finally {
                setDcLoading(false);
            }
        })();
    }, [claimId, provisionerBaseUrl]);
    const cardStyle = {
        background: '#fff',
        border: '1px solid #e4e4e7',
        borderRadius: '0.5rem',
        padding: '1.5rem',
        marginBottom: '1.5rem',
    };

    const codeStyle = {
        background: '#f4f4f5',
        padding: '0.25rem 0.5rem',
        borderRadius: '0.25rem',
        fontFamily: 'monospace',
        fontSize: '0.8rem',
    };

    return (
        <div>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '0.5rem' }}>
                Configure DNS
            </h1>
            <p style={{ color: '#52525b', marginBottom: '1.5rem', lineHeight: 1.6 }}>
                Add a CNAME record to <strong>{domain}</strong> in your DNS provider.
            </p>

            {/* Domain Connect auto-setup */}
            {!dcLoading && dcSupported && (
                <div style={{
                    background: '#eff6ff',
                    border: '1px solid #bfdbfe',
                    borderRadius: '0.5rem',
                    padding: '1.25rem',
                    marginBottom: '1.5rem',
                }}>
                    <a
                        href={dcApplyUrl}
                        style={{
                            display: 'block',
                            width: '100%',
                            padding: '0.625rem',
                            background: '#2563eb',
                            color: '#fff',
                            border: 'none',
                            borderRadius: '0.375rem',
                            fontSize: '1rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            textAlign: 'center',
                            textDecoration: 'none',
                            boxSizing: 'border-box',
                        }}
                    >
                        Set up automatically with {dcProvider}
                    </a>
                    <p style={{ color: '#1e40af', fontSize: '0.8rem', marginTop: '0.75rem', textAlign: 'center' }}>
                        You'll be redirected to approve the DNS change, then sent back here.
                    </p>
                </div>
            )}

            {!dcLoading && dcSupported && (
                <p style={{ color: '#a1a1aa', fontSize: '0.8rem', marginBottom: '1rem', textAlign: 'center' }}>
                    Or configure manually
                </p>
            )}

            <div style={cardStyle}>
                <div style={{ fontSize: '0.875rem' }}>
                    <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
                        <span style={{ color: '#71717a', fontWeight: 600, minWidth: '3rem' }}>Type</span>
                        <span>CNAME</span>
                    </div>
                    <div style={{ marginBottom: '0.75rem' }}>
                        <div style={{ color: '#71717a', fontWeight: 600, marginBottom: '0.25rem' }}>Name</div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                            <span style={{ ...codeStyle, wordBreak: 'break-all' as const }}>{cnameName}</span>
                            <CopyButton text={cnameName} />
                        </div>
                    </div>
                    <div>
                        <div style={{ color: '#71717a', fontWeight: 600, marginBottom: '0.25rem' }}>Target</div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                            <span style={{ ...codeStyle, wordBreak: 'break-all' as const }}>{cnameTarget}</span>
                            <CopyButton text={cnameTarget} />
                        </div>
                    </div>
                </div>
            </div>

            <p style={{ color: '#52525b', fontSize: '0.875rem', marginBottom: '1.5rem', lineHeight: 1.6 }}>
                This creates <strong>{cnameName}.{domain}</strong> as your auth endpoint. Once you've added the record, click Done to continue.
            </p>

            <button
                onClick={onDone}
                style={{
                    width: '100%',
                    padding: '0.625rem',
                    background: '#18181b',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '0.375rem',
                    fontSize: '1rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                }}
            >
                Done
            </button>
        </div>
    );
}
