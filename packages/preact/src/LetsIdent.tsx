import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';

interface LetsIdentProps {
  loginBaseUrl: string;
  apiBaseUrl: string;
  clientId?: string;
}

export function LetsIdent({ loginBaseUrl, apiBaseUrl, clientId }: LetsIdentProps) {
  const [idpUser, setIdpUser] = useState<any>(null);
  const [iframeHeight, setIframeHeight] = useState(60);

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

  const openRegister = () => {
    const registerUrl = `${loginBaseUrl}/register?client_id=${clientId}&return_to=${encodeURIComponent(loginBaseUrl + '/login/success')}`;
    // On mobile, open as a normal navigation (popups don't work well).
    // On desktop, open as a centered popup.
    const isMobile = window.innerWidth <= 600;
    if (isMobile) {
        window.open(registerUrl, '_blank');
    } else {
        const w = 450, h = 550;
        const left = (screen.width - w) / 2;
        const top = (screen.height - h) / 2;
        window.open(registerUrl, 'gratos_register', `width=${w},height=${h},left=${left},top=${top},popup=yes`);
    }
  };

  useEffect(() => {
    fetchUser();

    const handleMessage = (event: MessageEvent) => {
        if (event.data && event.data.type === 'GRATOS_LOGIN_SUCCESS') {
            fetchUser();
        }
        if (event.data && event.data.type === 'GRATOS_RESIZE' && typeof event.data.height === 'number') {
            setIframeHeight(event.data.height);
        }
        if (event.data && event.data.type === 'GRATOS_OPEN_REGISTER') {
            openRegister();
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
    <>
      <style>{`
        .letsident-card {
          position: fixed;
          bottom: 0;
          left: 0;
          right: 0;
          z-index: 1000;
          background-color: white;
          border-radius: 12px 12px 0 0;
          box-shadow: 0 -2px 12px rgba(0,0,0,0.15);
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, arial, sans-serif;
          display: flex;
          flex-direction: column;
          overflow: hidden;
          max-width: 100%;
        }
        @media (min-width: 480px) {
          .letsident-card {
            bottom: auto;
            top: 20px;
            right: 20px;
            left: auto;
            width: 320px;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.15);
          }
        }
        .letsident-header {
          padding: 14px 16px;
          display: flex;
          align-items: center;
          border-bottom: 1px solid #e0e0e0;
        }
        .letsident-header span {
          font-size: 15px;
          font-weight: 600;
          color: #202124;
        }
        .letsident-body {
          padding: 16px;
        }
        .letsident-subtitle {
          margin-bottom: 14px;
          font-size: 13px;
          color: #5f6368;
          line-height: 1.4;
        }
        .letsident-iframe {
          width: 100%;
          border: none;
          overflow: hidden;
        }
        .letsident-signout {
          display: block;
          width: 100%;
          background: none;
          border: 1px solid #dadce0;
          border-radius: 8px;
          color: #5f6368;
          cursor: pointer;
          font-size: 14px;
          text-align: center;
          padding: 10px 0;
          -webkit-tap-highlight-color: transparent;
        }
        .letsident-signout:active {
          background: #f1f3f4;
        }
      `}</style>
      <div className="letsident-card">
        <div className="letsident-header">
          <span>{idpUser ? 'Welcome back' : "Let's Ident"}</span>
        </div>

        <div className="letsident-body">
          <div className="letsident-subtitle">
            {idpUser
                ? `Continue as ${idpUser.email || 'User'} to access your account.`
                : 'Sign in or create an account to continue.'}
          </div>

          {!idpUser ? (
              <iframe
                src={`${loginBaseUrl}/login/prompt?client_id=${clientId}&return_to=${encodeURIComponent(loginBaseUrl + '/login/success')}`}
                title="Sign in with Let's Ident"
                allow="publickey-credentials-get *"
                className="letsident-iframe"
                style={{ height: `${iframeHeight}px` }}
              />
          ) : (
              <button
                onClick={handleLogout}
                className="letsident-signout"
              >
                Sign out
              </button>
          )}
        </div>
      </div>
    </>
  );
}
