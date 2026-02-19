import { h } from 'preact';
import { useState, useEffect, useCallback } from 'preact/hooks';
import { AuthProvider, useAuth, LoginButton, RegisterButton } from '@gratos/preact';
import { DomainEntry } from './DomainEntry';
import { ClaimStatus } from './ClaimStatus';

type Step = 'domain' | 'dns' | 'auth' | 'provisioning' | 'done';

function SignupInner({ provisionerBaseUrl }: { provisionerBaseUrl: string }) {
    const [step, setStep] = useState<Step>('domain');
    const [claimId, setClaimId] = useState<string | null>(null);
    const [domain, setDomain] = useState('');
    const [cnameName, setCnameName] = useState('');
    const [cnameTarget, setCnameTarget] = useState('');
    const { isAuthenticated } = useAuth();

    // When user authenticates on the auth step, auto-advance to provisioning
    useEffect(() => {
        if (step === 'auth' && isAuthenticated && claimId) {
            setStep('provisioning');
        }
    }, [step, isAuthenticated, claimId]);

    return (
        <div style={{ maxWidth: '480px', margin: '3rem auto', padding: '0 1.5rem' }}>
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
                        onClaimed={(id, dom, name, target) => {
                            setClaimId(id);
                            setDomain(dom);
                            setCnameName(name);
                            setCnameTarget(target);
                            setStep('dns');
                        }}
                    />
                </>
            )}

            {/* Step 2: Show CNAME instructions, "Done" button */}
            {step === 'dns' && (
                <ClaimStatus
                    domain={domain}
                    cnameName={cnameName}
                    cnameTarget={cnameTarget}
                    onDone={() => setStep('auth')}
                />
            )}

            {/* Step 3: Authenticate */}
            {step === 'auth' && !isAuthenticated && (
                <>
                    <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '0.5rem' }}>
                        Create your account
                    </h1>
                    <p style={{ color: '#52525b', marginBottom: '2rem', lineHeight: 1.6 }}>
                        Register or sign in to complete your domain claim.
                    </p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        <RegisterButton />
                        <div style={{ textAlign: 'center', color: '#a1a1aa', fontSize: '0.875rem' }}>
                            or
                        </div>
                        <LoginButton />
                    </div>
                </>
            )}

            {/* Step 4: ProvisionCF + poll ValidateCF + ClaimDomain */}
            {step === 'provisioning' && claimId && (
                <ProvisionAndFinalize
                    claimId={claimId}
                    domain={domain}
                    cnameName={cnameName}
                    cnameTarget={cnameTarget}
                    provisionerBaseUrl={provisionerBaseUrl}
                    onDone={() => setStep('done')}
                />
            )}

            {/* Step 5: Done */}
            {step === 'done' && (
                <div style={{
                    background: '#f0fdf4',
                    border: '1px solid #bbf7d0',
                    borderRadius: '0.5rem',
                    padding: '1.5rem',
                }}>
                    <h2 style={{ color: '#166534', marginBottom: '0.5rem' }}>Domain Active</h2>
                    <p style={{ color: '#15803d', fontSize: '0.875rem' }}>
                        <strong>{domain}</strong> is live with Gratos passkey authentication.
                    </p>
                </div>
            )}
        </div>
    );
}

function ProvisionAndFinalize({ claimId, domain, cnameName, cnameTarget, provisionerBaseUrl, onDone }: {
    claimId: string;
    domain: string;
    cnameName: string;
    cnameTarget: string;
    provisionerBaseUrl: string;
    onDone: () => void;
}) {
    const [phase, setPhase] = useState<'waiting_for_dns' | 'provisioning' | 'error'>('waiting_for_dns');
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

            if (data.status === 'waiting_for_dns') {
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
                {phase === 'waiting_for_dns' && 'Waiting for DNS'}
                {phase === 'provisioning' && 'Activating domain'}
            </h1>
            <p style={{ color: '#52525b', marginBottom: '1.5rem', lineHeight: 1.6 }}>
                {phase === 'waiting_for_dns' && `Checking for CNAME record on ${cnameName}.${domain}.`}
                {phase === 'provisioning' && `DNS verified. Setting up ${cnameName}.${domain}...`}
            </p>

            {phase === 'waiting_for_dns' && (
                <div style={cardStyle}>
                    <p style={{ fontSize: '0.875rem', color: '#52525b', marginBottom: '0.75rem' }}>
                        Ensure your CNAME record is set up:
                    </p>
                    <div style={{ fontSize: '0.875rem' }}>
                        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
                            <span style={{ color: '#71717a', fontWeight: 600, minWidth: '3rem' }}>Type</span>
                            <span>CNAME</span>
                        </div>
                        <div style={{ marginBottom: '0.75rem' }}>
                            <div style={{ color: '#71717a', fontWeight: 600, marginBottom: '0.25rem' }}>Name</div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                                <span style={{ ...codeStyle, wordBreak: 'break-all' as const }}>{cnameName}</span>
                            </div>
                        </div>
                        <div>
                            <div style={{ color: '#71717a', fontWeight: 600, marginBottom: '0.25rem' }}>Target</div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                                <span style={{ ...codeStyle, wordBreak: 'break-all' as const }}>{cnameTarget}</span>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <span style={{
                    padding: '0.25rem 0.75rem',
                    borderRadius: '9999px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    background: phase === 'provisioning' ? '#dbeafe' : '#fef9c3',
                    color: phase === 'provisioning' ? '#1e40af' : '#854d0e',
                }}>
                    {phase === 'waiting_for_dns' && 'Waiting for CNAME...'}
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
