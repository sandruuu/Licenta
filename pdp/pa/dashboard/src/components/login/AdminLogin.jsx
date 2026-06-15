import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { ChevronDown, ChevronUp, CircleAlert, Eye, KeyRound } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  beginPasskeyAuthentication,
  beginPasskeyRegistration,
  finishPasskeyAuthentication,
  finishPasskeyRegistration,
  login,
  setToken,
  verifyMFA,
} from '../../api';
import { applyTheme, getCurrentTheme } from '../../theme';
import BrandLogo from '../ui/BrandLogo';
import FormField, { FormInput } from '../ui/FormField';

const PASSKEY_NOT_CONFIGURED_ERROR = 'Passkey sign-in is not configured yet. Sign in with password to continue.';
const PASSKEY_ENROLLMENT_PURPOSE = 'passkey_enrollment';
const PASSKEY_PURPOSE_REQUIRED_ERROR = 'Passkey enrollment requires a TOTP challenge. Restart the PDP service and try again.';
const PASSKEY_REGISTERING_ERROR = 'Identity verified. Create your passkey to continue.';
const PASSKEY_DOMAIN_ERROR =
  'Passkey domain mismatch. Open the configured PDP URL or update WebAuthn RP settings for this domain.';
const PASSKEY_CANCELLED_ERROR = 'Passkey setup was cancelled or timed out. Try again when the passkey prompt appears.';
const PASSKEY_DEVICE_ERROR = 'This device cannot save a passkey right now. Check passkey, Face ID, and iCloud Keychain settings.';
const PASSKEY_SESSION_ERROR = 'Passkey setup session expired. Sign in with password and TOTP again.';
const PASSKEY_SAVE_ERROR = 'The passkey was created, but PDP could not save it. Try again.';
const PASSKEY_START_ERROR = 'Passkey setup could not be started. Try again.';
const PASSKEY_GENERIC_ERROR = 'Passkey setup failed. Check the device passkey settings and try again.';
const PASSKEY_SIGN_IN_CANCELLED_ERROR = 'Passkey sign-in was cancelled or timed out. Try again when the passkey prompt appears.';
const PASSKEY_SIGN_IN_DEVICE_ERROR = 'This device cannot use a passkey right now. Check passkey, Face ID, and iCloud Keychain settings.';
const PASSKEY_SIGN_IN_GENERIC_ERROR = 'Passkey sign-in failed. Check the device passkey settings and try again.';
const PASSWORD_REVEAL_MS = 1500;

function b64urlToBuffer(value) {
  const pad = '='.repeat((4 - (value.length % 4)) % 4);
  const b64 = (value + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = window.atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let index = 0; index < bin.length; index += 1) bytes[index] = bin.charCodeAt(index);
  return bytes.buffer;
}

function bufferToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let bin = '';
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return window.btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function mapCredentialList(list) {
  return (list || []).map((credential) => ({ ...credential, id: b64urlToBuffer(credential.id) }));
}

function prepareCreationOptions(options) {
  const publicKey = options.publicKey || options;
  publicKey.challenge = b64urlToBuffer(publicKey.challenge);
  if (publicKey.user && typeof publicKey.user.id === 'string') publicKey.user.id = b64urlToBuffer(publicKey.user.id);
  if (publicKey.excludeCredentials) publicKey.excludeCredentials = mapCredentialList(publicKey.excludeCredentials);
  return publicKey;
}

function prepareRequestOptions(options) {
  const publicKey = options.publicKey || options;
  publicKey.challenge = b64urlToBuffer(publicKey.challenge);
  if (publicKey.allowCredentials) publicKey.allowCredentials = mapCredentialList(publicKey.allowCredentials);
  return publicKey;
}

function credentialToJSON(credential) {
  const response = { clientDataJSON: bufferToB64url(credential.response.clientDataJSON) };
  if (credential.response.attestationObject) response.attestationObject = bufferToB64url(credential.response.attestationObject);
  if (credential.response.authenticatorData) response.authenticatorData = bufferToB64url(credential.response.authenticatorData);
  if (credential.response.signature) response.signature = bufferToB64url(credential.response.signature);
  if (credential.response.userHandle) response.userHandle = bufferToB64url(credential.response.userHandle);
  if (credential.response.getTransports) response.transports = credential.response.getTransports();
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response,
    clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
  };
}

function getPasskeyError(err, action = 'setup') {
  const name = err?.name || '';
  const message = err?.message || '';
  const normalized = `${name} ${message}`.toLowerCase();
  const signingIn = action === 'sign-in';

  if (
    name === 'SecurityError' ||
    normalized.includes('invalid domain') ||
    normalized.includes('relying party') ||
    normalized.includes('rp id') ||
    normalized.includes('effective domain')
  ) {
    return PASSKEY_DOMAIN_ERROR;
  }

  if (normalized.includes('not configured') || normalized.includes('no webauthn credentials')) {
    return PASSKEY_NOT_CONFIGURED_ERROR;
  }

  if (
    name === 'NotAllowedError' ||
    name === 'AbortError' ||
    normalized.includes('timed out') ||
    normalized.includes('timeout') ||
    normalized.includes('not allowed') ||
    normalized.includes('cancelled') ||
    normalized.includes('canceled')
  ) {
    return signingIn ? PASSKEY_SIGN_IN_CANCELLED_ERROR : PASSKEY_CANCELLED_ERROR;
  }

  if (
    name === 'NotSupportedError' ||
    normalized.includes('not support') ||
    normalized.includes('not available') ||
    normalized.includes('icloud') ||
    normalized.includes('keychain') ||
    normalized.includes('face id') ||
    normalized.includes('touch id')
  ) {
    return signingIn ? PASSKEY_SIGN_IN_DEVICE_ERROR : PASSKEY_DEVICE_ERROR;
  }

  if (
    name === 'InvalidStateError' ||
    normalized.includes('already registered') ||
    normalized.includes('already exists') ||
    normalized.includes('excluded')
  ) {
    return 'A passkey is already saved for this account on this device.';
  }

  if (
    normalized.includes('enrollment token') ||
    normalized.includes('invalid or expired') ||
    normalized.includes('session')
  ) {
    return PASSKEY_SESSION_ERROR;
  }

  if (normalized.includes('save passkey') || normalized.includes('could not save') || normalized.includes('failed to save')) {
    return PASSKEY_SAVE_ERROR;
  }

  if (normalized.includes('start passkey') || normalized.includes('start webauthn') || normalized.includes('not configured')) {
    return PASSKEY_START_ERROR;
  }

  return signingIn ? PASSKEY_SIGN_IN_GENERIC_ERROR : PASSKEY_GENERIC_ERROR;
}

function PasswordHiddenIcon() {
  return (
    <span className="relative grid h-[18px] w-[18px] place-items-center" aria-hidden="true">
      <Eye size={18} strokeWidth={2.3} />
      <span className="absolute h-0.5 w-[19px] rotate-45 rounded-full bg-current" />
    </span>
  );
}

function AdminLogin() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMFACode] = useState('');
  const [challenge, setChallenge] = useState(null);
  const [authMode, setAuthMode] = useState('password');
  const [loginPurpose, setLoginPurpose] = useState('');
  const [passkeyEnrollmentToken, setPasskeyEnrollmentToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSetupKey, setShowSetupKey] = useState(false);
  const [passwordVisible, setPasswordVisible] = useState(false);
  const passwordRevealTimer = useRef(null);
  const mfaDigits = Array.from({ length: 6 }, (_, index) => mfaCode[index] || '');

  useLayoutEffect(() => {
    const previousTheme = getCurrentTheme();
    applyTheme('light');

    return () => {
      applyTheme(previousTheme);
    };
  }, []);

  useEffect(() => () => {
    if (passwordRevealTimer.current) window.clearTimeout(passwordRevealTimer.current);
  }, []);

  const clearPasswordRevealTimer = () => {
    if (!passwordRevealTimer.current) return;
    window.clearTimeout(passwordRevealTimer.current);
    passwordRevealTimer.current = null;
  };

  const hidePassword = () => {
    clearPasswordRevealTimer();
    setPasswordVisible(false);
  };

  const revealPasswordBriefly = () => {
    clearPasswordRevealTimer();
    setPasswordVisible(true);
    passwordRevealTimer.current = window.setTimeout(() => {
      setPasswordVisible(false);
      passwordRevealTimer.current = null;
    }, PASSWORD_REVEAL_MS);
  };

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
      const data = await login(email, password, loginPurpose);

      if (data.challenge_id && data.mfa_required) {
        setChallenge(data);
        setLoginPurpose(data.purpose || loginPurpose);
        setMFACode('');
        setShowSetupKey(false);
      } else if (data.token || data.auth_token) {
        if (loginPurpose === PASSKEY_ENROLLMENT_PURPOSE) {
          setPassword('');
          setError(PASSKEY_PURPOSE_REQUIRED_ERROR);
        } else {
          setToken(data.token || data.auth_token);
          navigate('/');
        }
      } else {
        setError(data.message || data.error || 'Login failed');
      }
    } catch {
      setError('Connection failed');
    } finally {
      setLoading(false);
    }
  };

  const handlePasskeyLogin = async (event) => {
    event.preventDefault();
    if (passkeyEnrollmentToken) {
      void registerPasskey(passkeyEnrollmentToken);
      return;
    }
    await authenticatePasskey();
  };

  const switchAuthMode = (mode, purpose = '') => {
    setAuthMode(mode);
    setLoginPurpose(purpose);
    setPasskeyEnrollmentToken('');
    setError('');
    setPassword('');
    hidePassword();
  };

  const registerPasskey = async (token) => {
    if (!window.PublicKeyCredential) {
      setError(PASSKEY_DEVICE_ERROR);
      return;
    }

    setLoading(true);
    setError(PASSKEY_REGISTERING_ERROR);

    try {
      const options = await beginPasskeyRegistration(token);
      const credential = await navigator.credentials.create({ publicKey: prepareCreationOptions(options) });
      if (!credential) throw new Error('Passkey registration was cancelled');
      const data = await finishPasskeyRegistration(token, credentialToJSON(credential));
      if (data.token || data.auth_token) {
        setToken(data.token || data.auth_token);
        navigate('/');
      } else {
        setError(data.message || data.error || 'Passkey registration failed');
      }
    } catch (err) {
      setError(getPasskeyError(err));
    } finally {
      setLoading(false);
    }
  };

  const authenticatePasskey = async () => {
    if (!window.PublicKeyCredential) {
      setError(PASSKEY_SIGN_IN_DEVICE_ERROR);
      return;
    }

    setLoading(true);
    setError('');

    try {
      const options = await beginPasskeyAuthentication(email);
      const challengeID = options.challenge_id;
      const credential = await navigator.credentials.get({ publicKey: prepareRequestOptions(options) });
      if (!credential) throw new Error('Passkey sign-in was cancelled');
      const data = await finishPasskeyAuthentication(email, challengeID, credentialToJSON(credential));
      if (data.token || data.auth_token) {
        setToken(data.token || data.auth_token);
        navigate('/');
      } else {
        setError(PASSKEY_SIGN_IN_GENERIC_ERROR);
      }
    } catch (err) {
      const nextError = getPasskeyError(err, 'sign-in');
      if (nextError === PASSKEY_NOT_CONFIGURED_ERROR) {
        setLoginPurpose(PASSKEY_ENROLLMENT_PURPOSE);
      }
      setError(nextError);
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
        if (loginPurpose === PASSKEY_ENROLLMENT_PURPOSE) {
          if (data.purpose === PASSKEY_ENROLLMENT_PURPOSE) {
            const enrollmentToken = data.token || data.auth_token;
            setChallenge(null);
            setAuthMode('passkey');
            setPasskeyEnrollmentToken(enrollmentToken);
            setPassword('');
            setMFACode('');
            await registerPasskey(enrollmentToken);
          } else {
            setChallenge(null);
            setMFACode('');
            setError(PASSKEY_PURPOSE_REQUIRED_ERROR);
          }
        } else {
          setToken(data.token || data.auth_token);
          navigate('/');
        }
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
      <div className="bg-surface-card border border-border rounded-md shadow-xl w-full max-w-[400px] p-8 animate-[cardFadeIn_0.35s_ease-out_both]">
        <div className="mb-5 flex justify-center">
          <BrandLogo
            className="flex flex-col items-center justify-center gap-2"
            iconBoxClassName="grid h-20 w-20 shrink-0 place-items-center"
            iconClassName="h-20 w-20"
            titleClassName="text-[24px] font-bold leading-none text-text-primary"
          />
        </div>

        {!challenge && (
          <div className="mx-auto mb-4 h-10 max-w-[320px]">
            {error && (
              <div role="alert" className="flex h-full items-center gap-2.5 text-left text-sm font-normal leading-[18px] text-danger">
                <CircleAlert size={18} strokeWidth={2.4} className="shrink-0 text-danger" aria-hidden="true" />
                <span>
                  {error === PASSKEY_NOT_CONFIGURED_ERROR ? (
                    <>
                      Passkey sign-in is not configured yet. <strong className="font-bold">Sign in with password</strong> to continue.
                    </>
                  ) : (
                    error
                  )}
                </span>
              </div>
            )}
          </div>
        )}

        {!challenge && authMode === 'password' && (
          <form onSubmit={handleLogin} className="mx-auto max-w-[300px] text-left">
            <FormField label="Email" htmlFor="login-email">
              <FormInput
                id="login-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="admin@company.com"
                autoComplete="email"
                autoFocus
                required
              />
            </FormField>
            <FormField label="Password" htmlFor="login-password" className="mb-7">
              <div className="relative">
                <FormInput
                  id="login-password"
                  type={passwordVisible ? 'text' : 'password'}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  className="pr-11"
                  required
                />
                <button
                  type="button"
                  onClick={passwordVisible ? hidePassword : revealPasswordBriefly}
                  className="absolute inset-y-0 right-0 grid w-10 place-items-center border-0 bg-transparent p-0 text-text-muted shadow-none transition-colors hover:bg-transparent hover:text-text-primary focus:outline-none focus-visible:ring-[3px] focus-visible:ring-accent-muted"
                  aria-label={passwordVisible ? 'Hide password' : 'Show password briefly'}
                  title={passwordVisible ? 'Hide password' : 'Show password'}
                >
                  {passwordVisible ? (
                    <Eye size={18} strokeWidth={2.3} aria-hidden="true" />
                  ) : (
                    <PasswordHiddenIcon />
                  )}
                </button>
              </div>
            </FormField>
            <button
              type="submit"
              disabled={loading}
              className="mx-auto flex h-10 w-full max-w-[220px] items-center justify-center rounded-full border border-accent bg-accent px-5 text-[13px] font-semibold text-white-smoke shadow-md transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
            <div className="my-6 flex items-center gap-3 text-[10px] text-text-muted">
              <span className="h-px flex-1 bg-border" />
              <span>or</span>
              <span className="h-px flex-1 bg-border" />
            </div>
            <button
              type="button"
              disabled={loading}
              onClick={() => switchAuthMode('passkey')}
              className="mx-auto flex h-10 w-full max-w-[220px] items-center justify-center gap-2 rounded-full border border-border bg-surface-card px-5 text-[13px] font-medium text-text-secondary shadow-md transition-colors hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              <KeyRound size={14} strokeWidth={2.2} aria-hidden="true" />
              Sign in with passkey
            </button>
          </form>
        )}

        {!challenge && authMode === 'passkey' && (
          <form onSubmit={handlePasskeyLogin} className="mx-auto max-w-[300px] text-left">
            <FormField label="Email" htmlFor="login-passkey-email" className="mb-7">
              <FormInput
                id="login-passkey-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="admin@company.com"
                autoComplete="email"
                autoFocus
                required
              />
            </FormField>
            <button
              type="submit"
              disabled={loading}
              className="mx-auto flex h-10 w-full max-w-[220px] items-center justify-center rounded-full border border-accent bg-accent px-5 text-[13px] font-semibold text-white-smoke shadow-md transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
            <div className="my-6 flex items-center gap-3 text-[10px] text-text-muted">
              <span className="h-px flex-1 bg-border" />
              <span>or</span>
              <span className="h-px flex-1 bg-border" />
            </div>
            <button
              type="button"
              disabled={loading}
              onClick={() => switchAuthMode(
                'password',
                error === PASSKEY_NOT_CONFIGURED_ERROR ? PASSKEY_ENROLLMENT_PURPOSE : '',
              )}
              className="mx-auto flex h-10 w-full max-w-[220px] items-center justify-center rounded-full border border-border bg-surface-card px-5 text-[13px] font-medium text-text-secondary shadow-md transition-colors hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              Sign in with password
            </button>
          </form>
        )}

        {challenge && (
          <form onSubmit={handleMFAVerify} className="mx-auto max-w-[300px] text-left">
            <div className="mb-5">
              <h2 className="text-center text-[18px] font-bold leading-6 text-text-primary">
                {challenge.mfa_setup ? 'Set up Authenticator App' : 'Two-factor authentication'}
              </h2>
              <p className="mt-3 text-left text-[13px] leading-5 text-text-secondary">
                {challenge.mfa_setup
                  ? 'Scan the QR code with your Authenticator App'
                  : 'Open the Authenticator App that you used to set up two-factor authentication. Type the security code provided by the application.'}
              </p>
            </div>
            <div className="mb-3 h-10">
              {error && (
                <div role="alert" className="flex h-full items-center gap-2.5 text-left text-sm font-normal leading-[18px] text-danger">
                  <CircleAlert size={18} strokeWidth={2.4} className="shrink-0 text-danger" aria-hidden="true" />
                  <span>{error}</span>
                </div>
              )}
            </div>
            {challenge.mfa_setup && (
              <div className="mb-4 text-sm text-text-secondary">
                {challenge.qr_code_image && (
                  <img
                    src={challenge.qr_code_image}
                    alt="TOTP QR code"
                    className="mx-auto mb-3 h-44 w-44 rounded-md border border-border bg-white p-2"
                  />
                )}
                {challenge.secret && (
                  <div className="mt-3 text-left">
                    <button
                      type="button"
                      className="flex items-center gap-1 border-0 bg-transparent p-0 text-xs font-semibold text-text-secondary transition-colors hover:text-text-primary"
                      onClick={() => setShowSetupKey((current) => !current)}
                      aria-expanded={showSetupKey}
                    >
                      Setup token
                      {showSetupKey ? (
                        <ChevronUp size={14} strokeWidth={2.3} aria-hidden="true" />
                      ) : (
                        <ChevronDown size={14} strokeWidth={2.3} aria-hidden="true" />
                      )}
                    </button>
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
            <button
              type="submit"
              disabled={loading}
              className="mx-auto mt-6 flex h-10 w-full max-w-[220px] items-center justify-center rounded-full border border-accent bg-accent px-5 text-[13px] font-semibold text-white-smoke shadow-md transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify'}
            </button>
            <button
              type="button"
              disabled={loading}
              className="mx-auto mt-2 flex h-10 w-full max-w-[220px] items-center justify-center rounded-full border border-border bg-surface-card px-5 text-[13px] font-medium text-text-secondary shadow-md transition-colors hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-50"
              onClick={() => {
                setChallenge(null);
                setMFACode('');
                setLoginPurpose('');
                setPasskeyEnrollmentToken('');
                setShowSetupKey(false);
              }}
            >
              Back
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default AdminLogin;
