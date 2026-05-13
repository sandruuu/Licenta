import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import AccessPortalShell from './AccessPortalShell';
import AccessResult from './AccessResult';
import CredentialsForm from './CredentialsForm';
import HealthGatePanel from './HealthGatePanel';
import MFASelection from './MFASelection';
import TOTPForm from './TOTPForm';
import { apiJSON, getCSRFToken } from './loginUtils';
import useDeviceHealthGate from './useDeviceHealthGate';
import { authenticateWithWebAuthn } from './webauthnAuth';

function AccessPortalLogin() {
  const params = useMemo(() => new URLSearchParams(window.location.search), []);
  const sessionId = params.get('session') || '';
  const oidcSessionId = params.get('oidc_session') || '';
  const enrollSessionId = params.get('enroll_session') || '';
  const isMFAStepUp = params.get('mfa_step') === 'true';

  const [step, setStep] = useState(oidcSessionId ? 'health' : 'login');
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

  const sessionLabel = useMemo(() => {
    if (sessionId) return `Session: ${sessionId.slice(0, 12)}...`;
    if (oidcSessionId) return `OIDC session: ${oidcSessionId.slice(0, 12)}...`;
    if (enrollSessionId) return `Device enrollment: ${enrollSessionId.slice(0, 12)}...`;
    return '';
  }, [enrollSessionId, oidcSessionId, sessionId]);

  const { healthGate, deviceHealth, performHealthCheck } = useDeviceHealthGate({
    sessionId,
    oidcSessionId,
    setStep,
  });

  const showDenied = useCallback((message) => {
    setResult({ type: 'denied', message: message || 'Access denied by security policy.' });
    setStep('denied');
  }, []);

  const showSuccess = useCallback((message) => {
    setResult({ type: 'success', message: message || 'Authentication successful. Your secure connection is being established.' });
    setStep('success');
  }, []);

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
      const finishData = await authenticateWithWebAuthn(token);
      if (finishData.status === 'authenticated') {
        await completeAuthSession(finishData.auth_token);
      } else {
        setFlowError(finishData.message || 'WebAuthn verification failed');
      }
    } catch (err) {
      setFlowError(err.name === 'NotAllowedError' ? 'Security key request was cancelled or timed out.' : err.message || 'WebAuthn verification failed');
    }
  }, [completeAuthSession, mfaToken]);

  const selectMFAMethod = useCallback((method, token = mfaToken) => {
    setFlowError('');
    if (method === 'totp') {
      setMfaMessage('Enter the 6-digit verification code from your authenticator app.');
      setStep('totp');
    } else if (method === 'webauthn') {
      startWebAuthn(token);
    } else {
      setFlowError(`Unsupported MFA method: ${method}`);
    }
  }, [mfaToken, startWebAuthn]);

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

  useEffect(() => {
    if (step === 'login') usernameRef.current?.focus();
    if (step === 'totp') totpRef.current?.focus();
  }, [step]);

  return (
    <AccessPortalShell flowError={flowError} sessionLabel={sessionLabel} resultType={result.type}>
      {step === 'health' ? (
        <HealthGatePanel healthGate={healthGate} onRetry={performHealthCheck} />
      ) : null}

      {step === 'login' ? (
        <CredentialsForm
          username={username}
          password={password}
          onUsernameChange={setUsername}
          onPasswordChange={setPassword}
          onSubmit={handleLogin}
          loading={loading}
          usernameRef={usernameRef}
          deviceHealth={deviceHealth}
        />
      ) : null}

      {step === 'mfa-select' ? (
        <MFASelection
          mfaMessage={mfaMessage}
          mfaMethods={mfaMethods}
          onSelect={selectMFAMethod}
        />
      ) : null}

      {step === 'totp' ? (
        <TOTPForm
          mfaMessage={mfaMessage}
          totpCode={totpCode}
          setTotpCode={setTotpCode}
          onSubmit={handleTOTP}
          loading={loading}
          totpRef={totpRef}
        />
      ) : null}

      {step === 'success' || step === 'denied' ? (
        <AccessResult kind={step} message={result.message} />
      ) : null}
    </AccessPortalShell>
  );
}

export default AccessPortalLogin;
