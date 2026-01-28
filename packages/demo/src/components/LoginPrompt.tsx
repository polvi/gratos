import { useEffect, useState } from 'preact/hooks';

interface LoginPromptProps {
  loginBaseUrl: string;
  apiBaseUrl: string;
  clientId?: string;
}

export function LoginPrompt({ loginBaseUrl, apiBaseUrl, clientId }: LoginPromptProps) {
  const [idpUser, setIdpUser] = useState<any>(null);

  const fetchUser = () => {
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
  };

  useEffect(() => {
    fetchUser();

    const handleMessage = (event: MessageEvent) => {
        if (event.data && event.data.type === 'GRATOS_LOGIN_SUCCESS') {
            fetchUser();
        }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [apiBaseUrl]);

  const handleLogout = async () => {
    try {
      await fetch(`${apiBaseUrl}/logout`, {
        method: 'POST',
        credentials: 'include'
      });
      setIdpUser(null);
    } catch (e) {
      console.error('Logout failed', e);
    }
  };

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
         
         {!idpUser ? (
             <iframe 
                src={`${loginBaseUrl}/login/prompt?client_id=${clientId}&return_to=${encodeURIComponent(typeof window !== 'undefined' ? window.location.origin + '/iframe-callback' : '')}`}
                title="Sign in with Gratos"
                allow="publickey-credentials-get *"
                style={{
                    width: '100%',
                    height: '40px',
                    border: 'none',
                    overflow: 'hidden'
                }}
             />

         ) : (
             <button 
                onClick={handleLogout}
                style={{
                    display: 'block',
                    width: '100%',
                    background: 'none',
                    border: 'none',
                    color: '#5f6368',
                    cursor: 'pointer',
                    fontSize: '12px',
                    textDecoration: 'underline',
                    textAlign: 'left',
                    padding: 0
                }}
             >
                Sign out
             </button>
         )}
      </div>
    </div>
  );
}


