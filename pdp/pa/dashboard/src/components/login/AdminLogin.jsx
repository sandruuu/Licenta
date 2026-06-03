import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login, setToken, verifyMFA } from '../../api';
import Button from '../ui/Button';
import BrandLogo from '../ui/BrandLogo';
import FormField, { FormInput } from '../ui/FormField';
import ThemeToggle from '../ui/ThemeToggle';

function AdminLogin() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMFACode] = useState('');
  const [challenge, setChallenge] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSetupKey, setShowSetupKey] = useState(false);
  const mfaDigits = Array.from({ length: 6 }, (_, index) => mfaCode[index] || '');

  const focusMFAInput = (index) => {
    document.getElementById(`login-mfa-code-${index}`)?.focus();
  };

  const updateMFADigits = (index, value) => {
    const digits = value.replace(/\D/g, '');
    const next = [...mfaDigits];

    if (!digits) {
      next[index] = '';
      setMFACode(next.join(''));
      return;
    }

    digits
      .slice(0, 6 - index)
      .split('')
      .forEach((digit, offset) => {
        next[index + offset] = digit;
      });

    setMFACode(next.join(''));
    requestAnimationFrame(() => focusMFAInput(Math.min(index + digits.length, 5)));
  };

  const handleMFADigitKeyDown = (index, event) => {
    if (event.key === 'Backspace') {
      event.preventDefault();
      const next = [...mfaDigits];
      if (next[index]) {
        next[index] = '';
        setMFACode(next.join(''));
        return;
      }
      if (index > 0) {
        next[index - 1] = '';
        setMFACode(next.join(''));
        requestAnimationFrame(() => focusMFAInput(index - 1));
      }
      return;
    }

    if (event.key === 'ArrowLeft' && index > 0) {
      event.preventDefault();
      focusMFAInput(index - 1);
    }

    if (event.key === 'ArrowRight' && index < 5) {
      event.preventDefault();
      focusMFAInput(index + 1);
    }
  };

  const handleMFADigitPaste = (index, event) => {
    const pasted = event.clipboardData.getData('text');
    if (!pasted) return;
    event.preventDefault();
    updateMFADigits(index, pasted);
  };

  const handleLogin = async (event) => {
    event.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await login(username, password);

      if (data.token || data.auth_token) {
        setToken(data.token || data.auth_token);
        navigate('/');
      } else if (data.challenge_id && data.mfa_required) {
        setChallenge(data);
        setMFACode('');
        setShowSetupKey(false);
      } else {
        setError(data.message || data.error || 'Login failed');
      }
    } catch {
      setError('Connection failed');
    } finally {
      setLoading(false);
    }
  };

  const handleMFAVerify = async (event) => {
    event.preventDefault();
    setError('');

    const normalizedCode = mfaCode.replace(/\D/g, '').slice(0, 6);
    if (normalizedCode.length !== 6) {
      setError('Enter the 6-digit MFA code');
      return;
    }

    setLoading(true);

    try {
      const data = await verifyMFA(challenge?.challenge_id, normalizedCode);
      if (data.token || data.auth_token) {
        setToken(data.token || data.auth_token);
        navigate('/');
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
    <div className="relative min-h-screen flex items-center justify-center bg-surface p-4">
      <ThemeToggle className="absolute right-4 top-4" />
      <div className="bg-surface-card border border-border rounded-md shadow-xl w-full max-w-[400px] p-8 animate-[cardFadeIn_0.35s_ease-out_both]">
        <div className="mb-6 flex justify-center">
          <BrandLogo
            className="flex items-center justify-center gap-3"
            titleClassName="text-xl font-bold leading-none text-text-primary"
          />
        </div>

        {error && (
          <div className="bg-danger-muted border border-danger rounded-md p-3 mb-4 text-sm text-danger text-center">
            {error}
          </div>
        )}

        {!challenge ? (
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
          <form onSubmit={handleMFAVerify}>
            {challenge.mfa_setup && (
              <div className="mb-4 text-sm text-text-secondary">
                <p className="mb-2 text-left text-sm font-semibold text-text-primary">Set up authenticator app</p>
                {challenge.qr_code_image && (
                  <img
                    src={challenge.qr_code_image}
                    alt="TOTP QR code"
                    className="mx-auto mb-3 h-44 w-44 rounded-md border border-border bg-white p-2"
                  />
                )}
                {challenge.secret && (
                  <div className="mt-3 text-left">
                    <p className="text-xs font-semibold text-text-secondary">
                      {showSetupKey ? 'Finished with setup token? ' : "Can't scan? "}
                      <button
                        type="button"
                        className="border-0 bg-transparent p-0 text-xs font-semibold text-text-secondary transition-colors hover:text-text-primary"
                        onClick={() => setShowSetupKey((current) => !current)}
                      >
                        {showSetupKey ? 'Hide' : 'Show setup token'}
                      </button>
                    </p>
                    <div className="mt-2 min-h-5">
                      {showSetupKey && (
                        <p className="break-all font-mono text-xs leading-5 text-text-primary">{challenge.secret}</p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
            <div className="mb-4">
              <label htmlFor="login-mfa-code-0" className="mb-2 block text-left text-sm font-semibold text-text-primary">
                CODE
              </label>
              <div className="grid grid-cols-6 gap-2">
                {mfaDigits.map((digit, index) => (
                  <input
                    key={index}
                    id={`login-mfa-code-${index}`}
                    type="text"
                    value={digit}
                    onChange={(event) => updateMFADigits(index, event.target.value)}
                    onKeyDown={(event) => handleMFADigitKeyDown(index, event)}
                    onPaste={(event) => handleMFADigitPaste(index, event)}
                    inputMode="numeric"
                    autoComplete={index === 0 ? 'one-time-code' : 'off'}
                    maxLength={6}
                    autoFocus={index === 0}
                    aria-label={`MFA digit ${index + 1}`}
                    className="h-11 min-w-0 rounded-md border border-border bg-surface text-center font-mono text-lg font-semibold text-text-primary outline-none transition focus:border-accent focus:ring-[3px] focus:ring-accent-muted"
                    required
                  />
                ))}
              </div>
            </div>
            <Button variant="primary" type="submit" disabled={loading} className="w-full justify-center mt-2">
              {loading ? 'Verifying...' : 'Verify'}
            </Button>
            <Button
              variant="ghost"
              type="button"
              disabled={loading}
              className="w-full justify-center mt-2"
              onClick={() => {
                setChallenge(null);
                setMFACode('');
                setShowSetupKey(false);
              }}
            >
              Back
            </Button>
          </form>
        )}
      </div>
    </div>
  );
}

export default AdminLogin;
