import { h } from 'preact';
import { useState, useEffect, useCallback } from 'preact/hooks';
import { AuthProvider } from '@gratos/preact';
import { DomainEntry } from './DomainEntry';
import { ClaimStatus } from './ClaimStatus';

type Step = 'domain' | 'dns' | 'provisioning' | 'done';

const CNAME_NAME = 'authgravity';
const CNAME_TARGET = 'cname.authgravity.net';

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
                (async () => {
                    try {
                        const res = await fetch(`${provisionerBaseUrl}/claims/${dcClaimId}`);
                        if (res.ok) {
                            const data = await res.json() as any;
                            if (data.status === 'pending') {
                                setClaimId(data.id);
                                setDomain(data.domain);
                                setStep('provisioning');
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
                    onDone={() => { setDcError(null); setStep('provisioning'); }}
                />
            )}

            {/* Step 3: ProvisionCF + poll ValidateCF + ClaimDomain */}
            {step === 'provisioning' && claimId && (
                <ProvisionAndFinalize
                    claimId={claimId}
                    domain={domain}
                    provisionerBaseUrl={provisionerBaseUrl}
                    onDone={() => setStep('done')}
                />
            )}

            {/* Step 5: Done */}
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

function ProvisionAndFinalize({ claimId, domain, provisionerBaseUrl, onDone }: {
    claimId: string;
    domain: string;
    provisionerBaseUrl: string;
    onDone: () => void;
}) {
    const [phase, setPhase] = useState<'waiting_for_dns' | 'dns_mismatch' | 'provisioning' | 'error'>('waiting_for_dns');
    const [dnsLookup, setDnsLookup] = useState(`${CNAME_NAME}.${domain}`);
    const [dnsExpected, setDnsExpected] = useState(CNAME_TARGET);
    const [dnsActual, setDnsActual] = useState<string | null>(null);
    const [dnsFound, setDnsFound] = useState<Array<{ type: string; value: string }>>([]);
    const [error, setError] = useState('');

    // Poll /activate — drives the full state machine server-side
    const pollActivate = useCallback(async () => {
        try {
            const res = await fetch(`${provisionerBaseUrl}/claims/${claimId}/activate`, {
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
                onDone();
                return;
            }

            // Always update DNS diagnostic fields from response
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
    }, [claimId, provisionerBaseUrl, onDone]);

    // Start polling on mount
    useEffect(() => {
        pollActivate();
        const interval = setInterval(pollActivate, 5000);
        return () => clearInterval(interval);
    }, [pollActivate]);

    if (phase === 'error') {
        return (
            <div style={{ textAlign: 'center' as const }}>
                <p style={{ color: '#ef4444', marginBottom: '1rem' }}>{error}</p>
                <a href="/signup" style={{ color: '#18181b' }}>Start over</a>
            </div>
        );
    }

    const cardStyle = {
        background: '#fff',
        border: '1px solid #e4e4e7',
        borderRadius: '0.5rem',
        padding: '1.25rem',
        marginBottom: '1rem',
    };

    const codeStyle = {
        background: '#f4f4f5',
        padding: '0.25rem 0.5rem',
        borderRadius: '0.25rem',
        fontFamily: 'monospace',
        fontSize: '0.8rem',
        wordBreak: 'break-all' as const,
    };

    const labelStyle = {
        color: '#71717a',
        fontWeight: 600 as const,
        fontSize: '0.75rem',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
        marginBottom: '0.25rem',
    };

    const isMatch = phase === 'provisioning';
    const isMismatch = phase === 'dns_mismatch';

    return (
        <div>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '0.5rem' }}>
                {phase === 'waiting_for_dns' && 'Waiting for DNS'}
                {phase === 'dns_mismatch' && 'CNAME mismatch'}
                {phase === 'provisioning' && 'Activating domain'}
            </h1>
            <p style={{ color: '#52525b', marginBottom: '1.5rem', lineHeight: 1.6 }}>
                {phase === 'waiting_for_dns' && (dnsFound.length > 0
                    ? `Found existing records for ${CNAME_NAME}.${domain}, but no CNAME. See details below.`
                    : 'No DNS records found yet. Add the CNAME record below in your DNS provider.')}
                {phase === 'dns_mismatch' && 'A CNAME record exists but points to the wrong target. Update it to match.'}
                {phase === 'provisioning' && `DNS verified. Setting up ${CNAME_NAME}.${domain}...`}
            </p>

            {/* DNS diagnostic panel — always visible unless provisioning */}
            {phase !== 'provisioning' && (
                <>
                    {/* What we need */}
                    <div style={cardStyle}>
                        <div style={labelStyle}>Required CNAME</div>
                        <div style={{ fontSize: '0.875rem', marginTop: '0.5rem' }}>
                            <div style={{ marginBottom: '0.5rem' }}>
                                <div style={{ color: '#71717a', fontSize: '0.75rem', marginBottom: '0.125rem' }}>Name</div>
                                <span style={codeStyle}>{CNAME_NAME}</span>
                            </div>
                            <div>
                                <div style={{ color: '#71717a', fontSize: '0.75rem', marginBottom: '0.125rem' }}>Target</div>
                                <span style={codeStyle}>{dnsExpected}</span>
                            </div>
                        </div>
                    </div>

                    {/* What we see */}
                    <div style={{
                        ...cardStyle,
                        border: isMismatch ? '1px solid #fca5a5' : '1px solid #e4e4e7',
                        background: isMismatch ? '#fef2f2' : '#fff',
                    }}>
                        <div style={labelStyle}>DNS Lookup Result</div>
                        <div style={{ fontSize: '0.875rem', marginTop: '0.5rem' }}>
                            <div style={{ marginBottom: '0.5rem' }}>
                                <div style={{ color: '#71717a', fontSize: '0.75rem', marginBottom: '0.125rem' }}>Looking up</div>
                                <span style={codeStyle}>{dnsLookup}</span>
                            </div>
                            <div>
                                <div style={{ color: '#71717a', fontSize: '0.75rem', marginBottom: '0.125rem' }}>Resolves to</div>
                                {dnsActual ? (
                                    <span style={{
                                        ...codeStyle,
                                        background: isMismatch ? '#fee2e2' : '#f4f4f5',
                                    }}>
                                        CNAME {dnsActual}
                                    </span>
                                ) : dnsFound.length > 0 ? (
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                                        {dnsFound.map((r, i) => (
                                            <span key={i} style={{ ...codeStyle, background: '#fef9c3' }}>
                                                {r.type} {r.value}
                                            </span>
                                        ))}
                                    </div>
                                ) : (
                                    <span style={{ fontSize: '0.8rem', color: '#a1a1aa', fontStyle: 'italic' }}>
                                        No records found
                                    </span>
                                )}
                            </div>
                        </div>
                        {isMismatch && (
                            <p style={{ fontSize: '0.75rem', color: '#991b1b', marginTop: '0.75rem' }}>
                                This CNAME points to the wrong target. Update it to match the required target above.
                            </p>
                        )}
                        {!isMismatch && dnsFound.length > 0 && (
                            <p style={{ fontSize: '0.75rem', color: '#854d0e', marginTop: '0.75rem' }}>
                                Found existing records but no CNAME. You may need to remove these and add a CNAME record instead.
                            </p>
                        )}
                    </div>
                </>
            )}

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <span style={{
                    padding: '0.25rem 0.75rem',
                    borderRadius: '9999px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    background: isMatch ? '#dbeafe' : isMismatch ? '#fee2e2' : '#fef9c3',
                    color: isMatch ? '#1e40af' : isMismatch ? '#991b1b' : '#854d0e',
                }}>
                    {phase === 'waiting_for_dns' && 'No CNAME found'}
                    {phase === 'dns_mismatch' && 'Wrong target'}
                    {phase === 'provisioning' && 'Activating...'}
                </span>
                <button
                    onClick={() => pollActivate()}
                    style={{
                        padding: '0.375rem 0.75rem',
                        background: '#f4f4f5',
                        border: '1px solid #d4d4d8',
                        borderRadius: '0.375rem',
                        fontSize: '0.8rem',
                        cursor: 'pointer',
                    }}
                >
                    Refresh
                </button>
            </div>

            <p style={{ color: '#a1a1aa', fontSize: '0.75rem' }}>
                Auto-checking every 5 seconds.
            </p>
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
