import { useEffect, useState } from 'preact/hooks';

interface LoginPromptProps {
  loginUrl: string;
  apiBaseUrl: string;
}

export function LoginPrompt({ loginUrl, apiBaseUrl }: LoginPromptProps) {
  const [idpUser, setIdpUser] = useState<any>(null);

  useEffect(() => {
    fetch(`${apiBaseUrl}/whoami`, {
        credentials: 'include'
    })
    .then(res => res.ok ? res.json() : null)
    .then(data => {
        if (data && data.user) {
            setIdpUser(data.user);
        }
    })
    .catch(() => { /* ignore error */ });
  }, [apiBaseUrl]);

  return (
    <div style={{
      position: 'fixed',
      top: '20px',
      right: '20px',
      zIndex: 1000,
      backgroundColor: 'white',
      borderRadius: '4px',
      boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
      fontFamily: 'Roboto, arial, sans-serif',
      display: 'flex',
      flexDirection: 'column',
      width: '300px',
      overflow: 'hidden'
    }}>
      <div style={{ padding: '16px', display: 'flex', alignItems: 'center', borderBottom: '1px solid #e0e0e0' }}>
        <span style={{ fontSize: '14px', fontWeight: 500, color: '#3c4043' }}>
            {idpUser ? 'Welcome back' : 'Sign in to Gratos Demo'}
        </span>
      </div>

      <div style={{ padding: '16px' }}>
         <div style={{ marginBottom: '16px', fontSize: '12px', color: '#5f6368' }}>
            {idpUser 
                ? `Continue as ${idpUser.email || 'User'} to access your account.`
                : 'Continue with your Gratos account to save your progress.'}
         </div>
         <a href={loginUrl} style={{
            display: 'block',
            backgroundColor: '#1a73e8',
            color: 'white',
            textAlign: 'center',
            padding: '8px 16px',
            borderRadius: '4px',
            textDecoration: 'none',
            fontSize: '14px',
            fontWeight: 500
         }}>
            {idpUser ? `Continue as ${idpUser.email || 'User'}` : 'Sign in as User'}
         </a>
      </div>
    </div>
  );
}

