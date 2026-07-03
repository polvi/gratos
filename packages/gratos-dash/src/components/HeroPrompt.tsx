import { h } from 'preact';
import { useState } from 'preact/hooks';

const PROMPT = `Build a hello world app with Astro and AuthGravity. Details are at authgravity.org/llms.txt`;

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

export function HeroPrompt() {
    const [copied, setCopied] = useState(false);

    const handleCopy = () => {
        navigator.clipboard.writeText(PROMPT).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        });
    };

    return (
        <div style={{
            background: '#f9fafb',
            border: '1px solid #e4e4e7',
            borderRadius: '0.5rem',
            padding: '1rem',
            marginTop: '2.5rem',
            textAlign: 'left',
        }}>
            <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '0.5rem',
            }}>
                <div style={{ color: '#71717a', fontWeight: 600, fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Try it — paste into your coding agent
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
                padding: '0.75rem',
                borderRadius: '0.375rem',
                fontSize: '0.8rem',
                fontFamily: 'monospace',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                lineHeight: 1.6,
                margin: 0,
            }}>
                <code>{PROMPT}</code>
            </pre>
        </div>
    );
}
