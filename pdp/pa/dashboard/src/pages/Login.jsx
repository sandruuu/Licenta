import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Bell,
  Check,
  CheckCircle2,
  KeyRound,
  LoaderCircle,
  RefreshCw,
  Shield,
  Smartphone,
  XCircle,
} from 'lucide-react';
import { login, verifyMFA, setToken } from '../api';
import Button from '../components/ui/Button';
import FormField, { FormInput } from '../components/ui/FormField';

const HEALTH_AGENT_URL = 'http://127.0.0.1:12080';

const methodMeta = {
  totp: {
    icon: Smartphone,
    name: 'Authenticator app',
    desc: 'Enter a 6-digit code from your authenticator app',
  },
  webauthn: {
    icon: KeyRound,
    name: 'Security key',
    desc: 'Use your passkey or hardware security key',
  },
  push: {
    icon: Bell,
    name: 'Push notification',
    desc: 'Approve the login request on your device',
  },
};

function getCSRFToken() {
  const match = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : '';
}

async function readJSON(resp) {
  try {
    return await resp.json();
  } catch {
    return {};
  }
}

async function apiJSON(path, options = {}) {
  const resp = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const data = await readJSON(resp);
  if (!resp.ok) {
    throw new Error(data.error || data.message || 'Request failed');
  }
  return data;
}

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
  const binary = atob(base64 + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function HealthBadge({ status }) {
  const normalized = String(status || 'unknown').toLowerCase();
  const styles = {
    good: 'bg-success-muted text-success border-success/20',
    pass: 'bg-success-muted text-success border-success/20',
    ok: 'bg-success-muted text-success border-success/20',
    warning: 'bg-warning-muted text-warning border-warning/20',
    critical: 'bg-danger-muted text-danger border-danger/20',
    fail: 'bg-danger-muted text-danger border-danger/20',
  };

  return (
    <span className={`px-2 py-0.5 rounded-full border text-[10px] font-semibold uppercase ${styles[normalized] || 'bg-surface-secondary text-text-secondary border-border'}`}>
      {normalized}
    </span>
  );
}

function DeviceHealthSummary({ health }) {
  if (!health) return null;

  const score = Number(health.overall_score || 0);
  const scoreStyle = score >= 70 ? 'bg-success' : score >= 40 ? 'bg-warning' : 'bg-danger';

  return (
    <div className="mt-5 pt-4 border-t border-border">
      <div className="flex items-center gap-2 text-[11px] font-semibold uppercase text-text-muted mb-3">
        <Activity size={14} />
        Device health
      </div>
      <div className="space-y-2">
        {(health.checks || []).map((check, idx) => (
          <div key={`${check.name || 'check'}-${idx}`} className="flex items-center justify-between gap-3 text-[13px]">
            <span className="text-text-secondary truncate">{check.name || 'Device check'}</span>
            <HealthBadge status={check.status} />
          </div>
        ))}
      </div>
      <div className="h-1.5 bg-surface-secondary rounded-full overflow-hidden mt-3">
        <div className={`h-full rounded-full transition-all ${scoreStyle}`} style={{ width: `${Math.max(0, Math.min(score, 100))}%` }} />
      </div>
      <div className="text-right text-[11px] text-text-secondary mt-1">Device score: {score}/100</div>
    </div>
  );
}

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

function AccessPortalLogin() {
  const params = useMemo(() => new URLSearchParams(window.location.search), []);
  const sessionId = params.get('session') || '';
  const oidcSessionId = params.get('oidc_session') || '';
  const enrollSessionId = params.get('enroll_session') || '';
  const isMFAStepUp = params.get('mfa_step') === 'true';

  const [step, setStep] = useState(oidcSessionId ? 'health' : 'login');
  const [healthGate, setHealthGate] = useState('checking');
  const [deviceHealth, setDeviceHealth] = useState(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [mfaMethods, setMfaMethods] = useState([]);
  const [mfaMessage, setMfaMessage] = useState('');
  const [flowError, setFlowError] = useState('');
  const [result, setResult] = useState({ type: '', message: '' });
  const [loading, setLoading] = useState(false);

  const usernameRef = useRef(null);
  const totpRef = useRef(null);
  const healthIntervalRef = useRef(null);
  const pushIntervalRef = useRef(null);

  const sessionLabel = useMemo(() => {
    if (sessionId) return `Session: ${sessionId.slice(0, 12)}...`;
    if (oidcSessionId) return `OIDC session: ${oidcSessionId.slice(0, 12)}...`;
    if (enrollSessionId) return `Device enrollment: ${enrollSessionId.slice(0, 12)}...`;
    return '';
  }, [enrollSessionId, oidcSessionId, sessionId]);

  const clearPushPolling = useCallback(() => {
    if (pushIntervalRef.current) {
      clearInterval(pushIntervalRef.current);
      pushIntervalRef.current = null;
    }
  }, []);

  const showDenied = useCallback((message) => {
    clearPushPolling();
    setResult({ type: 'denied', message: message || 'Access denied by security policy.' });
    setStep('denied');
  }, [clearPushPolling]);

  const showSuccess = useCallback((message) => {
    clearPushPolling();
    setResult({ type: 'success', message: message || 'Authentication successful. Your secure connection is being established.' });
    setStep('success');
  }, [clearPushPolling]);

  const requestMFAStepUp = useCallback(async (authToken) => {
    try {
      const data = await apiJSON('/api/auth/mfa-step-up', {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCSRFToken() },
        body: JSON.stringify({
          auth_token: authToken,
          oidc_session_id: oidcSessionId || '',
        }),
      });

      if (data.status !== 'mfa_required') {
        setFlowError(data.message || 'MFA step-up failed');
        setStep('login');
        return;
      }

      const methods = data.mfa_methods || [];
      setMfaToken(data.mfa_token || '');
      setMfaMethods(methods);
      setMfaMessage(data.message || 'Additional verification is required.');

      if (methods.length === 1 && methods[0] === 'totp') {
        setStep('totp');
      } else {
        setStep('mfa-select');
      }
    } catch (err) {
      setFlowError(err.message || 'Connection error during MFA step-up.');
      setStep('login');
    }
  }, [oidcSessionId]);

  const completeAuthSession = useCallback(async (authToken) => {
    if (enrollSessionId) {
      try {
        const data = await apiJSON('/api/enroll/complete-session', {
          method: 'POST',
          body: JSON.stringify({ session_id: enrollSessionId, auth_token: authToken }),
        });
        if (data.success) {
          showSuccess('Device enrolled successfully. You can close this window.');
        } else {
          showDenied(data.error || 'Enrollment failed.');
        }
      } catch (err) {
        showDenied(err.message || 'Connection error during enrollment.');
      }
      return;
    }

    if (oidcSessionId) {
      try {
        const data = await apiJSON('/api/auth/oidc-complete', {
          method: 'POST',
          body: JSON.stringify({ oidc_session: oidcSessionId, auth_token: authToken }),
        });
        if (data.redirect_url) {
          showSuccess('Authentication successful. Redirecting to your application...');
          setTimeout(() => {
            window.location.href = data.redirect_url;
          }, 500);
        } else {
          showDenied(data.error || 'OIDC authorization failed.');
        }
      } catch (err) {
        showDenied(err.message || 'Connection error during OIDC completion.');
      }
      return;
    }

    if (!sessionId) {
      showSuccess('Authentication successful. You can close this window.');
      return;
    }

    try {
      const data = await apiJSON('/api/auth/complete-session', {
        method: 'POST',
        body: JSON.stringify({ session_id: sessionId, auth_token: authToken }),
      });

      if (data.success) {
        showSuccess(data.message || 'Access granted.');
      } else if (data.decision === 'mfa_required') {
        await requestMFAStepUp(authToken);
      } else {
        showDenied(data.message || 'Access denied by security policy.');
      }
    } catch {
      showSuccess('Authentication submitted. The client application will validate the session.');
    }
  }, [enrollSessionId, oidcSessionId, requestMFAStepUp, sessionId, showDenied, showSuccess]);

  const startWebAuthn = useCallback(async (token = mfaToken) => {
    setFlowError('');
    setMfaMessage('Verifying with your security key or passkey...');
    setStep('mfa-select');

    try {
      const options = await apiJSON('/api/mfa/webauthn/authenticate/begin', {
        method: 'POST',
        body: JSON.stringify({ mfa_token: token }),
      });

      options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
      if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((credential) => ({
          ...credential,
          id: base64urlToBuffer(credential.id),
        }));
      }

      const assertion = await navigator.credentials.get({ publicKey: options.publicKey });
      const assertionJSON = JSON.stringify({
        id: assertion.id,
        rawId: bufferToBase64url(assertion.rawId),
        type: assertion.type,
        response: {
          authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
          clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
          signature: bufferToBase64url(assertion.response.signature),
          userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : '',
        },
      });

      const finishData = await apiJSON(`/api/mfa/webauthn/authenticate/finish?mfa_token=${encodeURIComponent(token)}`, {
        method: 'POST',
        body: assertionJSON,
      });

      if (finishData.status === 'authenticated') {
        await completeAuthSession(finishData.auth_token);
      } else {
        setFlowError(finishData.message || 'WebAuthn verification failed');
      }
    } catch (err) {
      setFlowError(err.name === 'NotAllowedError' ? 'Security key request was cancelled or timed out.' : err.message || 'WebAuthn verification failed');
    }
  }, [completeAuthSession, mfaToken]);

  const startPushApproval = useCallback(async (token = mfaToken) => {
    clearPushPolling();
    setFlowError('');
    setMfaMessage('Sending push notification to your device...');
    setStep('mfa-select');

    try {
      const beginData = await apiJSON('/api/mfa/push/begin', {
        method: 'POST',
        body: JSON.stringify({ mfa_token: token }),
      });
      const challengeId = beginData.challenge_id;
      setMfaMessage('Waiting for approval on your device. The request expires in 2 minutes.');

      let pollCount = 0;
      pushIntervalRef.current = setInterval(async () => {
        pollCount += 1;
        if (pollCount > 40) {
          clearPushPolling();
          setFlowError('Push notification expired. Please try again.');
          return;
        }

        try {
          const statusData = await apiJSON(`/api/mfa/push/status?challenge_id=${encodeURIComponent(challengeId)}&mfa_token=${encodeURIComponent(token)}`);
          if (statusData.status === 'approved') {
            clearPushPolling();
            setMfaMessage('Approved. Completing authentication...');
            await completeAuthSession(statusData.auth_token);
          } else if (statusData.status === 'denied') {
            clearPushPolling();
            setFlowError('Push request was denied.');
          } else if (statusData.status === 'expired') {
            clearPushPolling();
            setFlowError('Push request expired. Please try again.');
          }
        } catch {
          // Keep polling on transient network errors.
        }
      }, 3000);
    } catch (err) {
      setFlowError(err.message || 'Failed to send push notification');
    }
  }, [clearPushPolling, completeAuthSession, mfaToken]);

  const selectMFAMethod = useCallback((method, token = mfaToken) => {
    setFlowError('');
    if (method === 'totp') {
      setMfaMessage('Enter the 6-digit verification code from your authenticator app.');
      setStep('totp');
    } else if (method === 'webauthn') {
      startWebAuthn(token);
    } else if (method === 'push') {
      startPushApproval(token);
    } else {
      setFlowError(`Unsupported MFA method: ${method}`);
    }
  }, [mfaToken, startPushApproval, startWebAuthn]);

  const handleLogin = async (event) => {
    event.preventDefault();
    setFlowError('');
    setLoading(true);

    try {
      const data = await apiJSON('/api/auth/login', {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCSRFToken() },
        body: JSON.stringify({ username, password }),
      });

      if (data.status === 'authenticated') {
        if (isMFAStepUp && data.mfa_methods && data.mfa_methods.length > 0) {
          await requestMFAStepUp(data.auth_token);
        } else {
          await completeAuthSession(data.auth_token);
        }
      } else if (data.status === 'mfa_required') {
        setMfaToken(data.mfa_token || data.token || '');
        setMfaMethods(data.mfa_methods || ['totp']);
        setStep('totp');
      } else {
        setFlowError(data.message || 'Authentication failed');
      }
    } catch (err) {
      setFlowError(err.message || 'Connection error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleTOTP = async (event) => {
    event.preventDefault();
    setFlowError('');
    setLoading(true);

    try {
      const data = await apiJSON('/api/auth/verify-mfa', {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCSRFToken() },
        body: JSON.stringify({ mfa_token: mfaToken, method: 'totp', totp_code: totpCode }),
      });

      if (data.status === 'authenticated') {
        await completeAuthSession(data.auth_token);
      } else {
        setFlowError(data.message || 'Invalid verification code');
        setTotpCode('');
      }
    } catch (err) {
      setFlowError(err.message || 'Connection error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const checkDeviceHealthAgent = useCallback(async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    try {
      const resp = await fetch(`${HEALTH_AGENT_URL}/health`, { mode: 'cors', signal: controller.signal });
      if (!resp.ok) return null;
      const data = await resp.json();
      return data.status === 'ok' ? data : null;
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }, []);

  const fetchAgentHealthStatus = useCallback(async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    try {
      const resp = await fetch(`${HEALTH_AGENT_URL}/status`, { mode: 'cors', signal: controller.signal });
      if (!resp.ok) return null;
      return await resp.json();
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }, []);

  const stopHealthAutoRetry = useCallback(() => {
    if (healthIntervalRef.current) {
      clearInterval(healthIntervalRef.current);
      healthIntervalRef.current = null;
    }
  }, []);

  const performHealthCheck = useCallback(async () => {
    setHealthGate('checking');
    const alive = await checkDeviceHealthAgent();
    if (!alive) {
      setHealthGate('missing');
      return false;
    }

    stopHealthAutoRetry();
    const status = await fetchAgentHealthStatus();
    if (status && status.overall_score !== undefined) {
      setDeviceHealth({
        overall_score: status.overall_score,
        checks: status.checks || [],
      });
    }
    setStep('login');
    return true;
  }, [checkDeviceHealthAgent, fetchAgentHealthStatus, stopHealthAutoRetry]);

  const startHealthAutoRetry = useCallback(() => {
    if (healthIntervalRef.current) return;
    healthIntervalRef.current = setInterval(async () => {
      const alive = await checkDeviceHealthAgent();
      if (alive) await performHealthCheck();
    }, 5000);
  }, [checkDeviceHealthAgent, performHealthCheck]);

  useEffect(() => {
    if (!sessionId) return undefined;

    let cancelled = false;
    apiJSON(`/api/auth/session-info?session=${encodeURIComponent(sessionId)}`)
      .then((data) => {
        if (!cancelled && data.device_health) setDeviceHealth(data.device_health);
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  useEffect(() => {
    if (!oidcSessionId) return undefined;

    let cancelled = false;
    performHealthCheck().then((ok) => {
      if (!cancelled && !ok) startHealthAutoRetry();
    });

    return () => {
      cancelled = true;
      stopHealthAutoRetry();
    };
  }, [oidcSessionId, performHealthCheck, startHealthAutoRetry, stopHealthAutoRetry]);

  useEffect(() => {
    if (step === 'login') usernameRef.current?.focus();
    if (step === 'totp') totpRef.current?.focus();
  }, [step]);

  useEffect(() => () => {
    clearPushPolling();
    stopHealthAutoRetry();
  }, [clearPushPolling, stopHealthAutoRetry]);

  return (
    <div className="min-h-screen bg-surface flex items-center justify-center px-4 py-8">
      <div className="w-full max-w-[420px] bg-surface-card border border-border rounded-lg shadow-xl p-8 animate-[cardFadeIn_0.35s_ease-out_both]">
        <div className="text-center mb-6">
          <div className="w-12 h-12 rounded-xl bg-accent-muted flex items-center justify-center mx-auto mb-3">
            <Shield size={24} className="text-accent" />
          </div>
          <h1 className="text-xl font-bold text-text-primary">Secure Access Portal</h1>
          <p className="text-xs text-text-secondary mt-1">Zero Trust Network Access</p>
        </div>

        {flowError && (
          <div className="bg-danger-muted border border-danger/25 rounded-md p-3 mb-4 text-sm text-danger">
            {flowError}
          </div>
        )}

        {step === 'health' && (
          <div className="text-center">
            {healthGate === 'checking' ? (
              <>
                <div className="w-[72px] h-[72px] rounded-full bg-info-muted border-2 border-info/20 flex items-center justify-center mx-auto mb-5">
                  <LoaderCircle size={34} className="text-info spinner-icon" />
                </div>
                <h2 className="text-lg font-bold text-text-primary mb-2">Device health check</h2>
                <p className="text-sm text-text-secondary">Checking if Device Health App is running on your device.</p>
              </>
            ) : (
              <>
                <div className="w-[72px] h-[72px] rounded-full bg-danger-muted border-2 border-danger/20 flex items-center justify-center mx-auto mb-5">
                  <AlertTriangle size={34} className="text-danger" />
                </div>
                <h2 className="text-lg font-bold text-text-primary mb-2">Device Health App not running</h2>
                <p className="text-sm text-text-secondary leading-6">
                  Device Health App must be running before access can continue.
                </p>
                <Button type="button" variant="secondary" className="w-full justify-center mt-5" onClick={performHealthCheck}>
                  <RefreshCw size={14} />
                  Retry
                </Button>
                <p className="text-[11px] text-text-muted mt-3">Auto-retrying every 5 seconds.</p>
              </>
            )}
          </div>
        )}

        {step === 'login' && (
          <>
            <form onSubmit={handleLogin}>
              <FormField label="Username" htmlFor="access-username">
                <FormInput
                  ref={usernameRef}
                  id="access-username"
                  type="text"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  placeholder="Enter your username"
                  autoComplete="username"
                  required
                />
              </FormField>
              <FormField label="Password" htmlFor="access-password">
                <FormInput
                  id="access-password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                  required
                />
              </FormField>
              <Button type="submit" variant="primary" disabled={loading} className="w-full justify-center mt-2">
                {loading ? (
                  <>
                    <LoaderCircle size={14} className="spinner-icon" />
                    Please wait
                  </>
                ) : 'Sign in'}
              </Button>
            </form>
            <DeviceHealthSummary health={deviceHealth} />
          </>
        )}

        {step === 'mfa-select' && (
          <div>
            <div className="bg-info-muted border border-info/20 rounded-md p-3 mb-4 text-sm text-info">
              {mfaMessage || 'Additional verification is required.'}
            </div>
            <div className="space-y-2">
              {mfaMethods.map((method) => {
                const meta = methodMeta[method] || { icon: KeyRound, name: method, desc: '' };
                const Icon = meta.icon;
                return (
                  <button
                    key={method}
                    type="button"
                    onClick={() => selectMFAMethod(method)}
                    className="w-full p-3 bg-surface-card border border-border rounded-md hover:border-accent hover:ring-[3px] hover:ring-accent-muted transition flex items-center gap-3 text-left"
                  >
                    <span className="w-9 h-9 rounded-md bg-accent-muted flex items-center justify-center text-accent shrink-0">
                      <Icon size={18} />
                    </span>
                    <span className="min-w-0">
                      <span className="block text-sm font-semibold text-text-primary">{meta.name}</span>
                      <span className="block text-xs text-text-secondary truncate">{meta.desc}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {step === 'totp' && (
          <form onSubmit={handleTOTP}>
            <div className="bg-info-muted border border-info/20 rounded-md p-3 mb-4 text-sm text-info">
              {mfaMessage || 'Enter the 6-digit verification code from your authenticator app.'}
            </div>
            <FormField label="Verification code" htmlFor="access-totp">
              <FormInput
                ref={totpRef}
                id="access-totp"
                type="text"
                value={totpCode}
                onChange={(event) => setTotpCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                maxLength={6}
                inputMode="numeric"
                autoComplete="one-time-code"
                className="text-center text-2xl font-bold tracking-[0.4em] font-mono"
                required
              />
            </FormField>
            <Button type="submit" variant="primary" disabled={loading} className="w-full justify-center mt-2">
              {loading ? (
                <>
                  <LoaderCircle size={14} className="spinner-icon" />
                  Verifying
                </>
              ) : 'Verify'}
            </Button>
          </form>
        )}

        {step === 'success' && (
          <div className="text-center">
            <div className="w-[72px] h-[72px] rounded-full bg-success flex items-center justify-center mx-auto mb-5 text-white">
              <Check size={36} />
            </div>
            <h2 className="text-xl font-bold text-text-primary mb-2">Access granted</h2>
            <p className="text-sm text-text-secondary leading-6">{result.message}</p>
          </div>
        )}

        {step === 'denied' && (
          <div className="text-center">
            <div className="w-[72px] h-[72px] rounded-full bg-danger flex items-center justify-center mx-auto mb-5 text-white">
              <XCircle size={36} />
            </div>
            <h2 className="text-xl font-bold text-text-primary mb-2">Access denied</h2>
            <p className="text-sm text-text-secondary leading-6">{result.message}</p>
          </div>
        )}

        {sessionLabel && (
          <div className="text-center text-[11px] text-text-muted mt-5">
            {result.type === 'success' ? <CheckCircle2 size={12} className="inline mr-1" /> : null}
            {sessionLabel}
          </div>
        )}
      </div>
    </div>
  );
}

export default function Login() {
  const location = useLocation();
  if (location.pathname === '/auth/login') {
    return <AccessPortalLogin />;
  }
  return <AdminLogin />;
}
