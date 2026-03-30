import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import { AuthProvider } from '@gratos/preact';
import { DomainEntry } from './DomainEntry';
import { ClaimStatus } from './ClaimStatus';

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
            {step === 'done' && (
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
                                background: '#18181b',
                                color: '#fff',
                                textDecoration: 'none',
                                borderRadius: '0.375rem',
                                fontSize: '0.875rem',
                                fontWeight: 600,
                            }}
                        >
                            Open Demo
                        </a>
                    </div>

                    <div style={{
                        background: '#fff',
                        border: '1px solid #e4e4e7',
                        borderRadius: '0.5rem',
                        padding: '1.5rem',
                        marginBottom: '1rem',
                    }}>
                        <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>
                            Add to your app
                        </h3>
                        <p style={{ color: '#52525b', fontSize: '0.875rem', lineHeight: 1.6, marginBottom: '1rem' }}>
                            Install the Preact widget library and add passkey auth to your app.
                        </p>

                        <div style={{ marginBottom: '1rem' }}>
                            <div style={{ color: '#71717a', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>
                                Install
                            </div>
                            <pre style={{
                                background: '#f4f4f5',
                                padding: '0.75rem',
                                borderRadius: '0.375rem',
                                fontSize: '0.8rem',
                                fontFamily: 'monospace',
                                overflowX: 'auto',
                            }}>
                                <code>npm install @gratos/preact</code>
                            </pre>
                        </div>

                        <div>
                            <div style={{ color: '#71717a', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>
                                Usage
                            </div>
                            <pre style={{
                                background: '#f4f4f5',
                                padding: '0.75rem',
                                borderRadius: '0.375rem',
                                fontSize: '0.8rem',
                                fontFamily: 'monospace',
                                overflowX: 'auto',
                                whiteSpace: 'pre',
                                lineHeight: 1.5,
                            }}>
                                <code>{`import { AuthProvider, LoginButton,
  RegisterButton, LogoutButton,
  useAuth } from '@gratos/preact';

function App() {
  return (
    <AuthProvider
      apiBaseUrl="https://${CNAME_NAME}.${domain}"
    >
      <RegisterButton />
      <LoginButton />
      <LogoutButton />
    </AuthProvider>
  );
}`}</code>
                            </pre>
                        </div>
                    </div>

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
            )}
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
