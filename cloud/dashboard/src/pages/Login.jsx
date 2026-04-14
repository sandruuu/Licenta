import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login, verifyMFA, setToken } from '../api';
import { Shield } from 'lucide-react';

export default function Login() {
  const navigate = useNavigate();
  const [step, setStep] = useState('login'); // 'login' | 'mfa'
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await login(username, password);

      if (data.status === 'mfa_required') {
        setMfaToken(data.mfa_token || data.token);
        setStep('mfa');
      } else if (data.token || data.auth_token) {
        setToken(data.token || data.auth_token);
        navigate('/dashboard');
      } else {
        setError(data.message || data.error || 'Login failed');
      }
    } catch {
      setError('Connection failed');
    } finally {
      setLoading(false);
    }
  };

  const handleMFA = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await verifyMFA(mfaToken, mfaCode);

      if (data.token || data.auth_token) {
        setToken(data.token || data.auth_token);
        navigate('/dashboard');
      } else {
        setError(data.message || data.error || 'MFA verification failed');
      }
    } catch {
      setError('Connection failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <Shield size={36} color="var(--accent)" />
        </div>
        <h1>ZeroTrust Cloud</h1>
        <p className="subtitle">Policy Decision Point — Admin Console</p>

        {error && <div className="login-error">{error}</div>}

        {step === 'login' ? (
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label>Username</label>
              <input
                className="form-input"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                autoFocus
                required
              />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input
                className="form-input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
              />
            </div>
            <button
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}
              type="submit"
              disabled={loading}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleMFA}>
            <p className="text-sm text-muted" style={{ marginBottom: 16 }}>
              Enter the 6-digit code from your authenticator app.
            </p>
            <div className="form-group">
              <label>TOTP Code</label>
              <input
                className="form-input"
                type="text"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="000000"
                maxLength={6}
                autoFocus
                required
              />
            </div>
            <button
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}
              type="submit"
              disabled={loading}
            >
              {loading ? 'Verifying...' : 'Verify'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
