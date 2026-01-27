import { useEffect } from 'preact/hooks';

interface LoginPromptProps {
  loginUrl: string;
}

export function LoginPrompt({ loginUrl }: LoginPromptProps) {

  useEffect(() => {
    // Determine if we should show the prompt (e.g., check if already logged in or dismissed)
    // For this demo, we'll just show it.
  }, []);

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
        <img src="https://www.gstatic.com/images/branding/product/1x/googleg_48dp.png" alt="Google Logo" style={{ width: '20px', height: '20px', marginRight: '12px' }} />
        <span style={{ fontSize: '14px', fontWeight: 500, color: '#3c4043' }}>Sign in to Gratos Demo</span>
      </div>
      <div style={{ padding: '16px' }}>
         <div style={{ marginBottom: '16px', fontSize: '12px', color: '#5f6368' }}>
            Continue with your Gratos account to save your progress.
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
            Sign in as User
         </a>
      </div>
    </div>
  );
}
