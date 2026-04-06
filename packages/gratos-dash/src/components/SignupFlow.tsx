import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import { AuthProvider } from '@gratos/preact';
import { DomainEntry } from './DomainEntry';
import { ClaimStatus } from './ClaimStatus';
import { InstallationPrompt } from './InstallationPrompt';

type Step = 'domain' | 'dns' | 'done';

const CNAME_NAME = 'authgravity';

function SignupInner({ provisionerBaseUrl }: { provisionerBaseUrl: string }) {
    const [step, setStep] = useState<Step>('domain');
    const [claimId, setClaimId] = useState<string | null>(null);
    const [domain, setDomain] = useState('');
    const [dcError, setDcError] = useState<string | null>(null);

    // Restore state after Domain Connect redirect
    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const dcClaimId = params.get('claim_id');
        const dcStatus = params.get('dc');
        if (dcClaimId && dcStatus) {
            // Clean URL immediately
            const url = new URL(window.location.href);
            url.searchParams.delete('claim_id');
            url.searchParams.delete('dc');
            url.searchParams.delete('error');
            window.history.replaceState({}, '', url.pathname);

            if (dcStatus === 'cancelled') {
                // User cancelled at the DNS provider — go back to DNS step
                (async () => {
                    try {
                        const res = await fetch(`${provisionerBaseUrl}/claims/${dcClaimId}`);
                        if (res.ok) {
                            const data = await res.json() as any;
                            if (data.status === 'pending') {
                                setClaimId(data.id);
                                setDomain(data.domain);
                                setDcError('Domain Connect was cancelled. You can try again or add the DNS record manually.');
                                setStep('dns');
                            }
                        }
                    } catch {
                        // Fall through to normal flow
                    }
                })();
            } else if (dcStatus === 'error') {
                (async () => {
                    try {
                        const res = await fetch(`${provisionerBaseUrl}/claims/${dcClaimId}`);
                        if (res.ok) {
                            const data = await res.json() as any;
                            if (data.status === 'pending') {
                                setClaimId(data.id);
                                setDomain(data.domain);
                                setDcError('Domain Connect encountered an error. You can try again or add the DNS record manually.');
                                setStep('dns');
                            }
                        }
                    } catch {
                        // Fall through to normal flow
                    }
                })();
            } else if (dcStatus === 'success') {
                // Domain Connect succeeded — fire activate and go straight to done
                (async () => {
                    try {
                        const res = await fetch(`${provisionerBaseUrl}/claims/${dcClaimId}`);
                        if (res.ok) {
                            const data = await res.json() as any;
                            if (data.status === 'pending') {
                                setClaimId(data.id);
                                setDomain(data.domain);
                                // Fire activate in background (skip DNS — DC already set it up)
                                fetch(`${provisionerBaseUrl}/claims/${dcClaimId}/activate`, {
                                    method: 'POST',
                                    credentials: 'include',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ skip_dns: true }),
                                }).catch(() => {});
                                setStep('done');
                            }
                        }
                    } catch {
                        // Fall through to normal flow
                    }
                })();
            }
        }
    }, [provisionerBaseUrl]);

    return (
        <div style={{ width: '100%', margin: '2rem 0' }}>
            {/* Step 1: EnterDomain — anon, DB only */}
            {step === 'domain' && (
                <>
                    <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '0.5rem' }}>
                        Set up your domain
                    </h1>
                    <p style={{ color: '#52525b', marginBottom: '2rem', lineHeight: 1.6 }}>
                        Enter the domain where you want passkey authentication.
                    </p>
                    <DomainEntry
                        provisionerBaseUrl={provisionerBaseUrl}
                        onClaimed={(id, dom) => {
                            setClaimId(id);
                            setDomain(dom);
                            setStep('dns');
                        }}
                        onReclaimed={(id, dom) => {
                            setClaimId(id);
                            setDomain(dom);
                            setStep('done');
                        }}
                    />
                </>
            )}

            {/* Step 2: Show CNAME instructions, "Done" button */}
            {step === 'dns' && dcError && (
                <div style={{
                    background: '#fef2f2',
                    border: '1px solid #fca5a5',
                    borderRadius: '0.5rem',
                    padding: '1rem',
                    marginBottom: '1rem',
                    color: '#991b1b',
                    fontSize: '0.875rem',
                }}>
                    {dcError}
                </div>
            )}
            {step === 'dns' && claimId && (
                <ClaimStatus
                    domain={domain}
                    claimId={claimId}
                    provisionerBaseUrl={provisionerBaseUrl}
                    onDone={() => {
                        setDcError(null);
                        // DNS validated — fire activate in background and go to done
                        fetch(`${provisionerBaseUrl}/claims/${claimId}/activate`, {
                            method: 'POST',
                            credentials: 'include',
                        }).catch(() => {});
                        setStep('done');
                    }}
                />
            )}

            {/* Step 3: Done */}
            {step === 'done' && claimId && (
                <DomainReady
                    domain={domain}
                    claimId={claimId}
                    provisionerBaseUrl={provisionerBaseUrl}
                />
            )}
        </div>
    );
}

function DomainReady({ domain, claimId, provisionerBaseUrl }: {
    domain: string;
    claimId: string;
    provisionerBaseUrl: string;
}) {
    const [sslStatus, setSslStatus] = useState<string | null>(null);

    useEffect(() => {
        if (sslStatus === 'active') return;

        const checkSsl = async () => {
            try {
                const res = await fetch(`${provisionerBaseUrl}/domains/${claimId}/ssl`, {
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
    }, [claimId, provisionerBaseUrl, sslStatus]);

    const sslReady = sslStatus === 'active';

    return (
        <div>
            <div style={{
                background: '#f0fdf4',
                border: '1px solid #bbf7d0',
                borderRadius: '0.5rem',
                padding: '1.5rem',
                marginBottom: '1.5rem',
            }}>
                <h2 style={{ color: '#166534', marginBottom: '0.5rem' }}>Domain Active</h2>
                <p style={{ color: '#15803d', fontSize: '0.875rem' }}>
                    <strong>{domain}</strong> is live with passkey authentication.
                </p>
            </div>

            {sslStatus !== null && !sslReady && (
                <div style={{
                    background: '#fffbeb',
                    border: '1px solid #fde68a',
                    borderRadius: '0.5rem',
                    padding: '1rem',
                    marginBottom: '1.5rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem',
                }}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                    <div>
                        <p style={{ color: '#92400e', fontSize: '0.875rem', fontWeight: 600 }}>
                            SSL certificate provisioning
                        </p>
                        <p style={{ color: '#a16207', fontSize: '0.8rem', marginTop: '0.125rem' }}>
                            Your domain is active but the SSL certificate is still being issued. This usually takes a few minutes.
                        </p>
                    </div>
                </div>
            )}

            <div style={{
                background: '#fff',
                border: '1px solid #e4e4e7',
                borderRadius: '0.5rem',
                padding: '1.5rem',
                marginBottom: '1rem',
            }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                    Try the demo
                </h3>
                <p style={{ color: '#52525b', fontSize: '0.875rem', lineHeight: 1.6, marginBottom: '0.75rem' }}>
                    See passkey auth in action on your domain:
                </p>
                <a
                    href={`https://${CNAME_NAME}.${domain}/demo`}
                    target="_blank"
                    rel="noopener"
                    style={{
                        display: 'inline-block',
                        padding: '0.5rem 1rem',
                        background: sslReady ? '#18181b' : '#a1a1aa',
                        color: '#fff',
                        textDecoration: 'none',
                        borderRadius: '0.375rem',
                        fontSize: '0.875rem',
                        fontWeight: 600,
                        pointerEvents: sslReady ? 'auto' : 'none',
                    }}
                >
                    {sslReady ? 'Open Demo' : 'Waiting for SSL...'}
                </a>
            </div>

            <InstallationPrompt domain={domain} />

            <div style={{ display: 'flex', gap: '0.75rem' }}>
                <a
                    href="/domains"
                    style={{
                        padding: '0.5rem 1rem',
                        background: '#f4f4f5',
                        border: '1px solid #d4d4d8',
                        borderRadius: '0.375rem',
                        fontSize: '0.875rem',
                        color: '#18181b',
                        textDecoration: 'none',
                        fontWeight: 600,
                    }}
                >
                    My Domains
                </a>
            </div>
        </div>
    );
}

export function SignupFlow({ apiBaseUrl, provisionerBaseUrl }: {
    apiBaseUrl: string;
    provisionerBaseUrl: string;
}) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <SignupInner provisionerBaseUrl={provisionerBaseUrl} />
        </AuthProvider>
    );
}
