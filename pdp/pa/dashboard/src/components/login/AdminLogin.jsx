import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { login, verifyMFA, setToken } from '../../api';
import Button from '../ui/Button';
import FormField, { FormInput } from '../ui/FormField';

function AdminLogin() {
  const navigate = useNavigate();
  const [step, setStep] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (event) => {
    event.preventDefault();
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

  const handleMFA = async (event) => {
    event.preventDefault();
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
    <div className="min-h-screen flex items-center justify-center bg-surface p-4">
      <div className="bg-surface-card border border-border rounded-md shadow-xl w-full max-w-[400px] p-8 animate-[cardFadeIn_0.35s_ease-out_both]">
        <div className="text-center mb-5">
          <div className="w-12 h-12 rounded-xl bg-accent-muted flex items-center justify-center mx-auto mb-3">
            <Shield size={24} className="text-accent" />
          </div>
          <h1 className="text-lg font-bold text-text-primary">ZeroTrust Cloud</h1>
          <p className="text-xs text-text-secondary mt-1">Policy Decision Point - Admin Console</p>
        </div>

        {error && (
          <div className="bg-danger-muted border border-danger rounded-md p-3 mb-4 text-sm text-danger text-center">
            {error}
          </div>
        )}

        {step === 'login' ? (
          <form onSubmit={handleLogin}>
            <FormField label="Username" htmlFor="login-username">
              <FormInput
                id="login-username"
                type="text"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="admin"
                autoFocus
                required
              />
            </FormField>
            <FormField label="Password" htmlFor="login-password">
              <FormInput
                id="login-password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="********"
                required
              />
            </FormField>
            <Button variant="primary" type="submit" disabled={loading} className="w-full justify-center mt-2">
              {loading ? 'Signing in...' : 'Sign in'}
            </Button>
          </form>
        ) : (
          <form onSubmit={handleMFA}>
            <p className="text-xs text-text-muted mb-4">
              Enter the 6-digit code from your authenticator app.
            </p>
            <FormField label="TOTP code" htmlFor="login-totp">
              <FormInput
                id="login-totp"
                type="text"
                value={mfaCode}
                onChange={(event) => setMfaCode(event.target.value)}
                placeholder="000000"
                maxLength={6}
                autoFocus
                required
              />
            </FormField>
            <Button variant="primary" type="submit" disabled={loading} className="w-full justify-center mt-2">
              {loading ? 'Verifying...' : 'Verify'}
            </Button>
          </form>
        )}
      </div>
    </div>
  );
}

export default AdminLogin;
