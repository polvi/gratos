import { h } from 'preact';
import { useState } from 'preact/hooks';

function getPromptText(domain: string) {
    return `Add passkey authentication to this app using AuthGravity. My auth endpoint is https://authgravity.${domain}.

Read the full AuthGravity documentation at https://authgravity.org/llms.txt before implementing.

Key points:
- Auth endpoint: https://authgravity.${domain}
- Use @simplewebauthn/browser for WebAuthn ceremonies
- Include credentials: 'include' on all fetch calls to the auth endpoint
- Session validation: forward cookies to /whoami endpoint
- Users are identified by UUID — store profile data in your own database keyed by that UUID`;
}

function CopyIcon({ copied }: { copied: boolean }) {
    if (copied) {
        return (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12" />
            </svg>
        );
    }
    return (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
        </svg>
    );
}

export function InstallationPrompt({ domain }: { domain: string }) {
    const [copied, setCopied] = useState(false);
    const prompt = getPromptText(domain);

    const handleCopy = () => {
        navigator.clipboard.writeText(prompt).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        });
    };

    return (
        <div style={{
            background: '#f9fafb',
            border: '1px solid #e4e4e7',
            borderRadius: '0.375rem',
            padding: '0.75rem',
            marginBottom: '0.5rem',
        }}>
            <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '0.375rem',
            }}>
                <div style={{ color: '#71717a', fontWeight: 600, fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Installation Prompt
                </div>
                <button
                    onClick={handleCopy}
                    title="Copy to clipboard"
                    style={{
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        padding: '0.125rem 0.25rem',
                        fontSize: '0.75rem',
                        color: copied ? '#16a34a' : '#a1a1aa',
                    }}
                >
                    <CopyIcon copied={copied} />
                </button>
            </div>
            <pre style={{
                background: '#f4f4f5',
                padding: '0.5rem',
                borderRadius: '0.25rem',
                fontSize: '0.7rem',
                fontFamily: 'monospace',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                lineHeight: 1.5,
                margin: 0,
            }}>
                <code>{prompt}</code>
            </pre>
        </div>
    );
}
