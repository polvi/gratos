import { h } from 'preact';
import { useState, useEffect, useCallback } from 'preact/hooks';
import { AuthProvider, useAuth } from './auth';
import { InstallationPrompt } from './InstallationPrompt';

const CNAME_NAME = 'authgravity';
const CNAME_TARGET = 'cname.authgravity.net';

type Domain = {
    id: string;
    domain: string;
    status: 'pending' | 'active';
    activating?: boolean;
    ssl_status?: string;
    created_at?: number;
    claimed_at?: number;
    users?: number;
    sessions?: number;
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

const AUTHZ_STARTER = JSON.stringify(
    {
        definitions: {
            document: {
                relations: {
                    owner: { subjects: [{ type: 'user' }] },
                    viewer: { subjects: [{ type: 'user' }] },
                },
                permissions: {
                    view: { union: [{ rel: 'viewer' }, { rel: 'owner' }] },
                },
            },
        },
    },
    null,
    2
);

/**
 * Owner-facing authz management for one tenant (domain or owned sandbox),
 * via the on-behalf API on the root auth endpoint. The dash session cookie
 * flows to authgravity.authgravity.org, and the control plane authorizes us
 * because onboarding recorded this dash user as the tenant's owner.
 */
function agentPrompt(tenant: string): { url: string; prompt: string } {
    const isSandbox = tenant.includes('/');
    const url = isSandbox ? `https://${tenant}/llms.txt` : `https://authgravity.${tenant}/llms.txt`;
    const prompt =
        `Add authorization to my app using AuthGravity.\n\n` +
        `First fetch ${url} and read it fully — it documents this tenant's live authorization schema ` +
        `(object types, relations, permissions) and the exact HTTP API on that host.` +
        (isSandbox ? ` If I'm running \`authgravity listen\`, use http://localhost:8787/llms.txt instead.` : '') +
        `\n\nThen wire my app up to it: gate every protected route and action with POST /v1/authz/check ` +
        `using the signed-in user's session (forward the session_id cookie, or send its value as a Bearer token). ` +
        `Omit the subject so the session user is checked — the response returns both "allowed" and the user's ` +
        `"user_id" in one round trip. Use the batch form ({items: [...]}) for list pages. ` +
        `Where the app must write relationships at runtime (recording a new resource's owner, adding an invited ` +
        `user to a group), use the service token from the AUTHZ_SERVICE_TOKEN environment variable as the Bearer ` +
        `instead of a user session, as that document describes. ` +
        `Follow the integration and design guidance in that document exactly.`;
    return { url, prompt };
}

function AuthzPanel({ apiBaseUrl, tenant }: { apiBaseUrl: string; tenant: string }) {
    const base = `${apiBaseUrl}/v1/authz/tenants/${encodeURIComponent(tenant)}`;
    const [status, setStatus] = useState<{ schema_version: number | null } | null>(null);
    const [denied, setDenied] = useState(false);
    const [schemaText, setSchemaText] = useState('');
    const [rows, setRows] = useState<Array<{ object: string; relation: string; subject: string }>>([]);
    const [filterType, setFilterType] = useState('');
    const [form, setForm] = useState({ object: '', relation: '', subject: '' });
    const [msg, setMsg] = useState<{ error?: string; ok?: string } | null>(null);
    const [generating, setGenerating] = useState(false);
    const [aiDescription, setAiDescription] = useState('');
    const [tokens, setTokens] = useState<Array<{ id: string; name: string; created_at: number; last_used_at: number | null }>>([]);
    const [tokenName, setTokenName] = useState('');
    const [mintedToken, setMintedToken] = useState<{ name: string; token: string } | null>(null);

    useEffect(() => {
        (async () => {
            try {
                const res = await fetch(`${base}/status`, { credentials: 'include' });
                if (!res.ok) {
                    setDenied(true);
                    return;
                }
                setStatus(await res.json());
                const schemaRes = await fetch(`${base}/schema`, { credentials: 'include' });
                setSchemaText(
                    schemaRes.ok
                        ? JSON.stringify((await schemaRes.json()).schema, null, 2)
                        : AUTHZ_STARTER
                );
                const tokenRes = await fetch(`${base}/tokens`, { credentials: 'include' });
                if (tokenRes.ok) setTokens((await tokenRes.json()).tokens || []);
            } catch {
                setDenied(true);
            }
        })();
    }, [base]);

    const mintServiceToken = async () => {
        setMsg(null);
        const res = await fetch(`${base}/tokens`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ name: tokenName.trim() || 'default' }),
        });
        const data = await res.json();
        if (!res.ok) {
            setMsg({ error: data.error || 'Failed to mint token' });
            return;
        }
        setMintedToken({ name: data.name, token: data.token });
        setTokenName('');
        setTokens((prev) => [...prev, { id: data.id, name: data.name, created_at: data.created_at, last_used_at: null }]);
    };

    const revokeServiceToken = async (id: string) => {
        if (!confirm('Revoke this service token? Apps using it will immediately lose write access.')) return;
        setMsg(null);
        const res = await fetch(`${base}/tokens/${id}`, { method: 'DELETE', credentials: 'include' });
        if (res.ok) setTokens((prev) => prev.filter((t) => t.id !== id));
        else setMsg({ error: (await res.json()).error || 'Failed to revoke token' });
    };

    const saveSchema = async () => {
        setMsg(null);
        let doc;
        try {
            doc = JSON.parse(schemaText);
        } catch (e: any) {
            setMsg({ error: `Invalid JSON: ${e.message}` });
            return;
        }
        const res = await fetch(`${base}/schema`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(doc),
        });
        const data = await res.json();
        if (res.ok) {
            setMsg({ ok: `Saved as version ${data.version}` });
            setStatus((s) => (s ? { ...s, schema_version: data.version } : s));
        } else {
            setMsg({ error: (data.error || 'Save failed') + (data.details ? `\n${data.details.join('\n')}` : '') });
        }
    };

    const generateSchema = async () => {
        setMsg(null);
        setAiDescription('');
        setGenerating(true);
        try {
            const res = await fetch(`${base}/generate-schema`, {
                method: 'POST',
                credentials: 'include',
            });
            const data = await res.json();
            if (!res.ok) {
                setMsg({ error: (data.error || 'Generation failed') + (data.details ? `\n${data.details.join('\n')}` : '') });
                return;
            }
            setSchemaText(JSON.stringify(data.schema, null, 2));
            setAiDescription(data.description || '');
            setMsg({ ok: 'Draft generated — review below, then Save Schema to apply.' });
        } catch {
            setMsg({ error: 'Network error during generation' });
        } finally {
            setGenerating(false);
        }
    };

    const loadRows = async (type: string) => {
        setMsg(null);
        if (!type) {
            setRows([]);
            return;
        }
        const res = await fetch(`${base}/relationships?object_type=${encodeURIComponent(type)}`, {
            credentials: 'include',
        });
        const data = await res.json();
        if (res.ok) setRows(data.relationships);
        else setMsg({ error: data.error || 'Load failed' });
    };

    const writeRel = async (op: 'touch' | 'delete', object: string, relation: string, subject: string) => {
        setMsg(null);
        const res = await fetch(`${base}/relationships`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ updates: [{ op, object, relation, subject }] }),
        });
        const data = await res.json();
        if (!res.ok) {
            setMsg({ error: (data.error || 'Write failed') + (data.details ? `\n${data.details.join('\n')}` : '') });
            return;
        }
        await loadRows(filterType || object.split(':')[0]);
    };

    const codeStyle = {
        background: '#f4f4f5',
        padding: '0.125rem 0.375rem',
        borderRadius: '0.25rem',
        fontFamily: 'monospace',
        fontSize: '0.75rem',
        wordBreak: 'break-all' as const,
    };
    const inputStyle = {
        flex: 1,
        padding: '0.375rem 0.5rem',
        border: '1px solid #d4d4d8',
        borderRadius: '0.375rem',
        fontFamily: 'monospace',
        fontSize: '0.75rem',
    };
    const smallButton = {
        padding: '0.375rem 0.75rem',
        background: '#18181b',
        color: '#fff',
        border: 'none',
        borderRadius: '0.375rem',
        fontSize: '0.75rem',
        fontWeight: 600 as const,
        cursor: 'pointer',
    };

    if (denied) {
        return (
            <p style={{ color: '#71717a', fontSize: '0.8rem', padding: '0.5rem 0' }}>
                You don't manage this tenant's authorization.
            </p>
        );
    }
    if (!status) {
        return <p style={{ color: '#71717a', fontSize: '0.8rem', padding: '0.5rem 0' }}>Loading...</p>;
    }

    return (
        <div style={{ padding: '0.75rem 0 0' }}>
            <div style={{ fontSize: '0.75rem', color: '#71717a', marginBottom: '0.5rem' }}>
                {status.schema_version ? `Schema v${status.schema_version}` : 'No schema yet'} · API:{' '}
                <span style={codeStyle}>/v1/authz</span> on the tenant's auth endpoint
            </div>

            {aiDescription && (
                <div
                    style={{
                        background: '#eff6ff',
                        border: '1px solid #bfdbfe',
                        borderRadius: '0.375rem',
                        padding: '0.75rem',
                        marginBottom: '0.5rem',
                        fontSize: '0.8rem',
                        color: '#1e40af',
                        lineHeight: 1.5,
                        whiteSpace: 'pre-wrap',
                    }}
                >
                    {aiDescription}
                </div>
            )}

            <textarea
                value={schemaText}
                onInput={(e: any) => setSchemaText(e.target.value)}
                spellcheck={false}
                style={{
                    width: '100%',
                    minHeight: '12rem',
                    padding: '0.5rem',
                    border: '1px solid #d4d4d8',
                    borderRadius: '0.375rem',
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    marginBottom: '0.5rem',
                    boxSizing: 'border-box' as const,
                }}
            />
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <button onClick={saveSchema} style={smallButton}>
                    Save Schema
                </button>
                {!tenant.includes('/') && (
                    <button
                        onClick={generateSchema}
                        disabled={generating}
                        style={{
                            ...smallButton,
                            background: '#f4f4f5',
                            color: '#18181b',
                            border: '1px solid #d4d4d8',
                            cursor: generating ? 'not-allowed' : 'pointer',
                            opacity: generating ? 0.6 : 1,
                        }}
                    >
                        {generating ? 'Crawling site & generating…' : '✨ Generate with AI'}
                    </button>
                )}
            </div>

            <div style={{ marginTop: '1rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#18181b', marginBottom: '0.25rem' }}>
                    Integrate with an AI agent
                </div>
                <p style={{ fontSize: '0.75rem', color: '#71717a', marginBottom: '0.375rem', lineHeight: 1.5 }}>
                    This tenant's live schema and API are published at{' '}
                    <a href={agentPrompt(tenant).url} target="_blank" rel="noopener" style={{ color: '#2563eb' }}>
                        {agentPrompt(tenant).url}
                    </a>
                    . Paste this prompt into your coding agent:
                </p>
                <div
                    style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '0.25rem',
                        background: '#f9fafb',
                        border: '1px solid #e4e4e7',
                        borderRadius: '0.375rem',
                        padding: '0.5rem',
                        marginBottom: '1rem',
                    }}
                >
                    <div style={{ fontFamily: 'monospace', fontSize: '0.7rem', color: '#52525b', whiteSpace: 'pre-wrap', flex: 1 }}>
                        {agentPrompt(tenant).prompt}
                    </div>
                    <CopyButton text={agentPrompt(tenant).prompt} />
                </div>

                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#18181b', marginBottom: '0.25rem' }}>
                    Service tokens
                </div>
                <p style={{ fontSize: '0.75rem', color: '#71717a', marginBottom: '0.375rem', lineHeight: 1.5 }}>
                    Your app's backend uses a service token (<span style={codeStyle}>Authorization: Bearer agk_…</span>)
                    to write relationships at runtime — e.g. adding an invited user to a group, or recording a new
                    resource's owner. Tokens can check and write relationships for this tenant only; schema changes
                    stay here in the dashboard.
                </p>
                {mintedToken && (
                    <div
                        style={{
                            background: '#fffbeb',
                            border: '1px solid #fde68a',
                            borderRadius: '0.375rem',
                            padding: '0.5rem',
                            marginBottom: '0.5rem',
                            fontSize: '0.75rem',
                            color: '#92400e',
                        }}
                    >
                        Token <strong>{mintedToken.name}</strong> — copy it now, it won't be shown again:
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', marginTop: '0.25rem' }}>
                            <span style={{ ...codeStyle, flex: 1 }}>{mintedToken.token}</span>
                            <CopyButton text={mintedToken.token} />
                        </div>
                    </div>
                )}
                {tokens.length > 0 && (
                    <div style={{ marginBottom: '0.5rem' }}>
                        {tokens.map((t) => (
                            <div
                                key={t.id}
                                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.25rem 0', fontSize: '0.75rem' }}
                            >
                                <span style={{ fontWeight: 600 }}>{t.name}</span>
                                <span style={{ color: '#a1a1aa' }}>
                                    created {new Date(t.created_at).toLocaleDateString()}
                                    {t.last_used_at ? ` · last used ${new Date(t.last_used_at).toLocaleDateString()}` : ' · never used'}
                                </span>
                                <button
                                    onClick={() => revokeServiceToken(t.id)}
                                    style={{
                                        marginLeft: 'auto',
                                        padding: '0.125rem 0.5rem',
                                        background: 'none',
                                        border: '1px solid #fca5a5',
                                        borderRadius: '0.375rem',
                                        color: '#dc2626',
                                        fontSize: '0.7rem',
                                        cursor: 'pointer',
                                    }}
                                >
                                    Revoke
                                </button>
                            </div>
                        ))}
                    </div>
                )}
                <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
                    <input
                        placeholder="token name (e.g. production-backend)"
                        value={tokenName}
                        onInput={(e: any) => setTokenName(e.target.value)}
                        style={inputStyle}
                    />
                    <button onClick={mintServiceToken} style={smallButton}>
                        Mint Token
                    </button>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <input
                        placeholder="object type (e.g. document)"
                        value={filterType}
                        onInput={(e: any) => setFilterType(e.target.value)}
                        style={inputStyle}
                    />
                    <button onClick={() => loadRows(filterType)} style={{ ...smallButton, background: '#f4f4f5', color: '#18181b', border: '1px solid #d4d4d8' }}>
                        List Relationships
                    </button>
                </div>
                {rows.length > 0 && (
                    <div style={{ marginBottom: '0.5rem' }}>
                        {rows.map((r) => (
                            <div
                                key={`${r.object}#${r.relation}@${r.subject}`}
                                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.25rem 0', fontSize: '0.75rem' }}
                            >
                                <span style={codeStyle}>{r.object}</span>
                                <span style={{ color: '#71717a' }}>{r.relation}</span>
                                <span style={codeStyle}>{r.subject}</span>
                                <button
                                    onClick={() => writeRel('delete', r.object, r.relation, r.subject)}
                                    style={{
                                        marginLeft: 'auto',
                                        padding: '0.125rem 0.5rem',
                                        background: 'none',
                                        border: '1px solid #fca5a5',
                                        borderRadius: '0.375rem',
                                        color: '#dc2626',
                                        fontSize: '0.7rem',
                                        cursor: 'pointer',
                                    }}
                                >
                                    x
                                </button>
                            </div>
                        ))}
                    </div>
                )}
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <input
                        placeholder="document:readme"
                        value={form.object}
                        onInput={(e: any) => setForm({ ...form, object: e.target.value })}
                        style={inputStyle}
                    />
                    <input
                        placeholder="viewer"
                        value={form.relation}
                        onInput={(e: any) => setForm({ ...form, relation: e.target.value })}
                        style={inputStyle}
                    />
                    <input
                        placeholder="user:abc"
                        value={form.subject}
                        onInput={(e: any) => setForm({ ...form, subject: e.target.value })}
                        style={inputStyle}
                    />
                    <button
                        onClick={() => {
                            if (!form.object || !form.relation || !form.subject) return;
                            if (!filterType) setFilterType(form.object.split(':')[0]);
                            writeRel('touch', form.object, form.relation, form.subject);
                        }}
                        style={smallButton}
                    >
                        Add
                    </button>
                </div>
            </div>

            {msg?.error && (
                <p style={{ color: '#ef4444', fontSize: '0.75rem', marginTop: '0.5rem', whiteSpace: 'pre-wrap' }}>{msg.error}</p>
            )}
            {msg?.ok && <p style={{ color: '#16a34a', fontSize: '0.75rem', marginTop: '0.5rem' }}>{msg.ok}</p>}
        </div>
    );
}

function AuthzSection({ apiBaseUrl, tenant }: { apiBaseUrl: string; tenant: string }) {
    const [open, setOpen] = useState(false);
    return (
        <div style={{ marginTop: '0.75rem', borderTop: '1px solid #f4f4f5', paddingTop: '0.75rem' }}>
            <button
                onClick={() => setOpen(!open)}
                style={{
                    padding: '0.25rem 0',
                    background: 'none',
                    border: 'none',
                    color: '#18181b',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                }}
            >
                {open ? '▾' : '▸'} Authorization
            </button>
            {open && <AuthzPanel apiBaseUrl={apiBaseUrl} tenant={tenant} />}
        </div>
    );
}

function ActiveDetails({ domain, provisionerBaseUrl, apiBaseUrl }: { domain: Domain; provisionerBaseUrl: string; apiBaseUrl: string }) {
    const endpoint = `${CNAME_NAME}.${domain.domain}`;
    const [sslStatus, setSslStatus] = useState<string | null>(domain.ssl_status || null);

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
            {sslStatus !== null && !sslReady && (
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

            <InstallationPrompt domain={domain.domain} />

            <div style={{ display: 'flex', gap: '0.5rem' }}>
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
                {sslReady && (
                    <a
                        href={`https://${endpoint}/authz`}
                        target="_blank"
                        rel="noopener"
                        style={{
                            display: 'inline-block',
                            padding: '0.375rem 0.75rem',
                            background: '#f4f4f5',
                            border: '1px solid #d4d4d8',
                            borderRadius: '0.375rem',
                            fontSize: '0.75rem',
                            color: '#18181b',
                            textDecoration: 'none',
                            fontWeight: 500,
                        }}
                    >
                        Authz Console
                    </a>
                )}
            </div>

            <AuthzSection apiBaseUrl={apiBaseUrl} tenant={domain.domain} />
        </div>
    );
}

function ActivatingDetails({ domain, provisionerBaseUrl, onClaimed }: {
    domain: Domain;
    provisionerBaseUrl: string;
    onClaimed: () => void;
}) {
    // Silently poll activate until claimed, then show SSL + installation prompt
    useEffect(() => {
        const poll = async () => {
            try {
                const res = await fetch(`${provisionerBaseUrl}/claims/${domain.id}/activate`, {
                    method: 'POST',
                    credentials: 'include',
                });
                if (res.ok) {
                    const data = await res.json() as any;
                    if (data.status === 'claimed') {
                        onClaimed();
                    }
                }
            } catch {
                // Ignore transient errors
            }
        };

        poll();
        const interval = setInterval(poll, 5000);
        return () => clearInterval(interval);
    }, [domain.id, provisionerBaseUrl, onClaimed]);

    return (
        <div style={{ padding: '0.75rem 0 0' }}>
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

            <InstallationPrompt domain={domain.domain} />
        </div>
    );
}

type Sandbox = {
    id: string;
    tenant: string;
    endpoint: string;
    created_at: number;
};

function SandboxSection({ apiBaseUrl }: { apiBaseUrl: string }) {
    const [sandboxes, setSandboxes] = useState<Sandbox[]>([]);
    const [loading, setLoading] = useState(true);
    const [creating, setCreating] = useState(false);
    const [deleting, setDeleting] = useState<string | null>(null);
    const [error, setError] = useState('');

    const fetchSandboxes = useCallback(async () => {
        try {
            const res = await fetch(`${apiBaseUrl}/sandboxes`, { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                setSandboxes(data.sandboxes || []);
            }
        } catch {
            // ignore transient errors
        } finally {
            setLoading(false);
        }
    }, [apiBaseUrl]);

    useEffect(() => {
        fetchSandboxes();
    }, [fetchSandboxes]);

    const handleCreate = async () => {
        setCreating(true);
        setError('');
        try {
            const res = await fetch(`${apiBaseUrl}/sandbox`, {
                method: 'POST',
                credentials: 'include',
            });
            if (!res.ok) {
                const data = await res.json();
                setError(data.error || 'Failed to create sandbox');
                return;
            }
            await fetchSandboxes();
        } catch {
            setError('Network error');
        } finally {
            setCreating(false);
        }
    };

    const handleDelete = async (s: Sandbox) => {
        if (!confirm(`Delete sandbox ${s.id}? Its users and passkeys are removed.`)) return;

        setDeleting(s.id);
        setError('');
        try {
            const res = await fetch(`${apiBaseUrl}/sandboxes/${s.id}`, {
                method: 'DELETE',
                credentials: 'include',
            });
            if (!res.ok) {
                const data = await res.json();
                setError(data.error || 'Failed to delete sandbox');
                return;
            }
            setSandboxes(prev => prev.filter(x => x.id !== s.id));
        } catch {
            setError('Network error');
        } finally {
            setDeleting(null);
        }
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
        <div style={{ marginTop: '3rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Sandboxes</h2>
                <button
                    onClick={handleCreate}
                    disabled={creating}
                    style={{
                        padding: '0.5rem 1rem',
                        background: '#18181b',
                        color: '#fff',
                        border: 'none',
                        borderRadius: '0.375rem',
                        fontSize: '0.875rem',
                        fontWeight: 600,
                        cursor: creating ? 'not-allowed' : 'pointer',
                        opacity: creating ? 0.6 : 1,
                    }}
                >
                    {creating ? 'Creating...' : 'New Sandbox'}
                </button>
            </div>
            <p style={{ color: '#71717a', fontSize: '0.8rem', marginBottom: '1rem', lineHeight: 1.5 }}>
                Instant, isolated auth endpoints for local development — no domain, no DNS.
                Run <span style={codeStyle}>npx @authgravity/cli listen --endpoint &lt;endpoint&gt;</span> next
                to your dev server. The authz console is then available
                at <span style={codeStyle}>localhost:8787/authz</span>.
            </p>

            {error && (
                <p style={{ color: '#ef4444', fontSize: '0.875rem', marginBottom: '1rem' }}>{error}</p>
            )}

            {loading ? (
                <p style={{ color: '#71717a', fontSize: '0.875rem' }}>Loading...</p>
            ) : sandboxes.length === 0 ? (
                <div style={{
                    border: '1px dashed #d4d4d8',
                    borderRadius: '0.5rem',
                    padding: '1.5rem',
                    textAlign: 'center',
                }}>
                    <p style={{ color: '#71717a', fontSize: '0.875rem' }}>No sandboxes yet.</p>
                </div>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {sandboxes.map(s => (
                        <div
                            key={s.id}
                            style={{
                                background: '#fff',
                                border: '1px solid #e4e4e7',
                                borderRadius: '0.5rem',
                                padding: '1rem 1.25rem',
                            }}
                        >
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
                                <div style={{ minWidth: 0 }}>
                                    <div>
                                        <span style={codeStyle}>{s.endpoint}</span>
                                        <CopyButton text={s.endpoint} />
                                    </div>
                                    <div style={{ fontSize: '0.75rem', color: '#71717a', marginTop: '0.375rem' }}>
                                        Created {new Date(s.created_at).toLocaleDateString()}
                                    </div>
                                </div>
                                <button
                                    onClick={() => handleDelete(s)}
                                    disabled={deleting === s.id}
                                    style={{
                                        padding: '0.375rem 0.75rem',
                                        background: 'none',
                                        border: '1px solid #fca5a5',
                                        borderRadius: '0.375rem',
                                        color: '#dc2626',
                                        fontSize: '0.8rem',
                                        cursor: deleting === s.id ? 'not-allowed' : 'pointer',
                                        opacity: deleting === s.id ? 0.5 : 1,
                                        flexShrink: 0,
                                    }}
                                >
                                    {deleting === s.id ? 'Deleting...' : 'Delete'}
                                </button>
                            </div>
                            <AuthzSection apiBaseUrl={apiBaseUrl} tenant={s.tenant} />
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

function DomainListInner({ apiBaseUrl, provisionerBaseUrl }: { apiBaseUrl: string; provisionerBaseUrl: string }) {
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
            const claimed = data.claimed || [];
            const all: Domain[] = [
                ...claimed,
                ...(data.pending || []),
            ];
            setDomains(all);

            // Fetch stats for active domains in parallel
            const statsPromises = claimed.map(async (d: any) => {
                try {
                    const statsRes = await fetch(`${provisionerBaseUrl}/domains/${d.id}/stats`, {
                        credentials: 'include',
                    });
                    if (statsRes.ok) {
                        const stats = await statsRes.json();
                        return { id: d.id, ...stats };
                    }
                } catch {}
                return null;
            });
            const statsResults = await Promise.all(statsPromises);
            setDomains(prev => prev.map(d => {
                const stats = statsResults.find((s: any) => s && s.id === d.id);
                return stats ? { ...d, users: stats.users, sessions: stats.sessions } : d;
            }));
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
                                            background: d.status === 'active' ? '#22c55e' : d.activating ? '#3b82f6' : '#f59e0b',
                                        }} />
                                        <span style={{ fontSize: '0.75rem', color: '#71717a' }}>
                                            {d.status === 'active' ? 'Active' : d.activating ? 'Pending SSL' : 'Pending DNS'}
                                        </span>
                                        {d.status === 'active' && d.users !== undefined && (
                                            <>
                                                <span style={{ color: '#d4d4d8' }}>|</span>
                                                <span style={{ fontSize: '0.75rem', color: '#71717a' }}>
                                                    {d.users} {d.users === 1 ? 'user' : 'users'}
                                                </span>
                                                <span style={{ color: '#d4d4d8' }}>|</span>
                                                <span style={{ fontSize: '0.75rem', color: '#71717a' }}>
                                                    {d.sessions} {d.sessions === 1 ? 'session' : 'sessions'}
                                                </span>
                                            </>
                                        )}
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

                            {expandedId === d.id && d.status === 'pending' && !d.activating && (
                                <PendingDetails
                                    domain={d}
                                    provisionerBaseUrl={provisionerBaseUrl}
                                    onClaimed={fetchDomains}
                                />
                            )}
                            {expandedId === d.id && d.status === 'pending' && d.activating && (
                                <ActivatingDetails
                                    domain={d}
                                    provisionerBaseUrl={provisionerBaseUrl}
                                    onClaimed={fetchDomains}
                                />
                            )}
                            {expandedId === d.id && d.status === 'active' && (
                                <ActiveDetails domain={d} provisionerBaseUrl={provisionerBaseUrl} apiBaseUrl={apiBaseUrl} />
                            )}
                        </div>
                    ))}
                </div>
            )}

            <SandboxSection apiBaseUrl={apiBaseUrl} />
        </div>
    );
}

export function DomainList({ apiBaseUrl, provisionerBaseUrl }: {
    apiBaseUrl: string;
    provisionerBaseUrl: string;
}) {
    return (
        <AuthProvider apiBaseUrl={apiBaseUrl}>
            <DomainListInner apiBaseUrl={apiBaseUrl} provisionerBaseUrl={provisionerBaseUrl} />
        </AuthProvider>
    );
}
