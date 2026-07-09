import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { ChevronDown, ChevronUp, CircleAlert, CircleCheck, Eye, KeyRound, Save } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  beginPasskeyAuthentication,
  beginPasskeyRegistration,
  changeInitialPassword,
  finishPasskeyAuthentication,
  finishPasskeyRegistration,
  login,
  setAuthSession,
  verifyMFA,
  verifyMFARecovery,
} from '../../api';
import { applyTheme, getCurrentTheme } from '../../theme';
import { formatPasswordPolicyError, getPasswordPolicyIssues } from '../../passwordPolicy';
import { isBlank, requiredFieldsMessage } from '../../formValidation';
import { credentialToJSON, prepareCreationOptions, prepareRequestOptions } from '../../webauthn';
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

function passwordLength(value = '') {
  return [...String(value || '').normalize('NFC')].length;
}

function hasPolicyIssue(issues, fragments) {
  return issues.some((issue) => {
    const normalized = String(issue || '').toLowerCase();
    return fragments.some((fragment) => normalized.includes(fragment));
  });
}

function initialPasswordRequirements(password, confirmation, issues) {
  const length = passwordLength(password);
  const hasPassword = length > 0;
  return [
    {
      key: 'min-length',
      label: 'Use at least 15 characters.',
      met: length >= 15,
    },
    {
      key: 'max-length',
      label: 'Use at most 256 characters.',
      met: hasPassword && length <= 256,
    },
    {
      key: 'predictable',
      label: 'Do not use common, predictable, or repetitive passwords.',
      met: hasPassword && !hasPolicyIssue(issues, ['common', 'predictable', 'repetitive']),
    },
    {
      key: 'account',
      label: 'Do not use account information such as the username or email address.',
      met: hasPassword && !hasPolicyIssue(issues, ['account', 'email', 'username', 'identifier']),
    },
    {
      key: 'confirmation',
      label: 'The confirmation must match the new password.',
      met: hasPassword && confirmation.length > 0 && password === confirmation,
    },
  ];
}

function PasswordRequirementList({ items }) {
  return (
    <ul className="mt-2 grid min-h-[92px] gap-1 text-[11px] leading-4">
      {items.map((item) => (
        <li key={item.key} className={`flex items-start gap-2 ${item.met ? 'text-success' : 'text-text-muted'}`}>
          <span className="mt-[1px] flex h-4 w-4 shrink-0 items-center justify-center">
            {item.met ? (
              <CircleCheck size={13} strokeWidth={2.6} aria-hidden="true" />
            ) : (
              <span className="h-1.5 w-1.5 rounded-full bg-border" aria-hidden="true" />
            )}
          </span>
          <span>{item.label}</span>
        </li>
      ))}
    </ul>
  );
}

function downloadRecoveryCodes(codes) {
  if (!codes?.length) return;
  const content = [
    'TRUSTCloud recovery codes',
    '',
    'Store these codes somewhere safe. Each code works once.',
    '',
    ...codes,
    '',
  ].join('\n');
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'trustcloud-recovery-codes.txt';
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

function AdminLogin() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [mfaCode, setMFACode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [challenge, setChallenge] = useState(null);
  const [passwordChangeChallenge, setPasswordChangeChallenge] = useState(null);
  const [authMode, setAuthMode] = useState('password');
  const [loginPurpose, setLoginPurpose] = useState('');
  const [passkeyEnrollmentToken, setPasskeyEnrollmentToken] = useState('');
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState([]);
  const [pendingAuthResponse, setPendingAuthResponse] = useState(null);
  const [error, setError] = useState('');
  const [errorDetails, setErrorDetails] = useState([]);
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSetupKey, setShowSetupKey] = useState(false);
  const [passwordVisible, setPasswordVisible] = useState(false);
  const passwordRevealTimer = useRef(null);
  const mfaDigits = Array.from({ length: 6 }, (_, index) => mfaCode[index] || '');
  const showingRecoveryCodes = recoveryCodes.length > 0;
  const initialPasswordPolicyIssues = passwordChangeChallenge
    ? getPasswordPolicyIssues(newPassword, {
      account: { email, username: email },
      confirmPassword,
      checkConfirmation: !!confirmPassword,
    })
    : [];
  const initialPasswordRequirementItems = initialPasswordRequirements(newPassword, confirmPassword, initialPasswordPolicyIssues);

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
    setErrorDetails([]);
    setNotice('');
    setRecoveryCodes([]);
    setPendingAuthResponse(null);

    const missingFields = [];
    if (isBlank(email)) missingFields.push('Email');
    if (!password) missingFields.push('Password');
    if (missingFields.length) {
      setError(requiredFieldsMessage(missingFields));
      return;
    }

    setLoading(true);

    try {
      const data = await login(email, password, loginPurpose);

      if (data.password_change_required || data.status === 'password_change_required') {
        setPasswordChangeChallenge(data);
        setChallenge(null);
        setNewPassword('');
        setConfirmPassword('');
        setMFACode('');
        setRecoveryCode('');
        setUseRecoveryCode(false);
        setPassword('');
        hidePassword();
      } else if (data.challenge_id && data.mfa_required) {
        setChallenge(data);
        setLoginPurpose(data.purpose || loginPurpose);
        setMFACode('');
        setRecoveryCode('');
        setUseRecoveryCode(false);
        setShowSetupKey(false);
      } else if (data.token || data.auth_token) {
        if (loginPurpose === PASSKEY_ENROLLMENT_PURPOSE) {
          setPassword('');
          setError(PASSKEY_PURPOSE_REQUIRED_ERROR);
        } else {
          setAuthSession(data);
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

  const handleInitialPasswordChange = async (event) => {
    event.preventDefault();
    setError('');
    setErrorDetails([]);
    setNotice('');

    const missingFields = [];
    if (!newPassword) missingFields.push('New password');
    if (!confirmPassword) missingFields.push('Confirm password');
    if (missingFields.length) {
      setError(requiredFieldsMessage(missingFields));
      return;
    }

    const policyIssues = getPasswordPolicyIssues(newPassword, {
      account: { email, username: email },
      confirmPassword,
      checkConfirmation: true,
    });
    if (policyIssues.length) {
      setError('The password does not meet the policy.');
      setErrorDetails(policyIssues);
      return;
    }

    setLoading(true);

    try {
      const data = await changeInitialPassword(passwordChangeChallenge?.challenge_id, newPassword, confirmPassword);
      setPasswordChangeChallenge(null);
      setNewPassword('');
      setConfirmPassword('');
      setPassword('');
      setLoginPurpose('');
      setNotice(data.message || 'Password changed. Sign in with the new password.');
    } catch (err) {
      const policyError = formatPasswordPolicyError(err, 'Password change failed');
      setError(policyError.message);
      setErrorDetails(policyError.details);
    } finally {
      setLoading(false);
    }
  };

  const handlePasskeyLogin = async (event) => {
    event.preventDefault();
    setError('');
    setErrorDetails([]);
    setNotice('');

    if (passkeyEnrollmentToken) {
      void registerPasskey(passkeyEnrollmentToken);
      return;
    }

    if (isBlank(email)) {
      setError(requiredFieldsMessage(['Email']));
      return;
    }

    await authenticatePasskey();
  };

  const switchAuthMode = (mode, purpose = '') => {
    setAuthMode(mode);
    setLoginPurpose(purpose);
    setPasskeyEnrollmentToken('');
    setPasswordChangeChallenge(null);
    setError('');
    setErrorDetails([]);
    setNotice('');
    setPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setRecoveryCode('');
    setRecoveryCodes([]);
    setPendingAuthResponse(null);
    setUseRecoveryCode(false);
    hidePassword();
  };

  const registerPasskey = async (token) => {
    if (!window.PublicKeyCredential) {
      setError(PASSKEY_DEVICE_ERROR);
      return;
    }

    setLoading(true);
    setError(PASSKEY_REGISTERING_ERROR);
    setErrorDetails([]);

    try {
      const options = await beginPasskeyRegistration(token);
      const credential = await navigator.credentials.create({ publicKey: prepareCreationOptions(options) });
      if (!credential) throw new Error('Passkey registration was cancelled');
      const data = await finishPasskeyRegistration(token, credentialToJSON(credential));
      if (data.token || data.auth_token) {
        setAuthSession(data);
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
    setErrorDetails([]);

    try {
      const options = await beginPasskeyAuthentication(email);
      const challengeID = options.challenge_id;
      const credential = await navigator.credentials.get({ publicKey: prepareRequestOptions(options) });
      if (!credential) throw new Error('Passkey sign-in was cancelled');
      const data = await finishPasskeyAuthentication(email, challengeID, credentialToJSON(credential));
      if (data.token || data.auth_token) {
        setAuthSession(data);
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

  const completeAuthenticatedResponse = async (data) => {
    if (loginPurpose === PASSKEY_ENROLLMENT_PURPOSE || data.purpose === PASSKEY_ENROLLMENT_PURPOSE) {
      const enrollmentToken = data.token || data.auth_token;
      setChallenge(null);
      setAuthMode('passkey');
      setPasskeyEnrollmentToken(enrollmentToken);
      setPassword('');
      setMFACode('');
      await registerPasskey(enrollmentToken);
      return;
    }

    setAuthSession(data);
    navigate('/');
  };

  const handleAuthenticatedResponse = async (data) => {
    if (data.recovery_codes?.length) {
      setRecoveryCodes(data.recovery_codes);
      setPendingAuthResponse(data);
      setChallenge(null);
      setMFACode('');
      setRecoveryCode('');
      setUseRecoveryCode(false);
      setError('');
      return;
    }
    await completeAuthenticatedResponse(data);
  };

  const handleRecoveryCodesContinue = async () => {
    if (!pendingAuthResponse) return;
    const data = pendingAuthResponse;
    setRecoveryCodes([]);
    setPendingAuthResponse(null);
    await completeAuthenticatedResponse(data);
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
        if (loginPurpose === PASSKEY_ENROLLMENT_PURPOSE && data.purpose !== PASSKEY_ENROLLMENT_PURPOSE) {
          setChallenge(null);
          setMFACode('');
          setError(PASSKEY_PURPOSE_REQUIRED_ERROR);
        } else {
          await handleAuthenticatedResponse(data);
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

  const handleMFARecovery = async (event) => {
    event.preventDefault();
    setError('');

    if (!recoveryCode.trim()) {
      setError('Enter a recovery code');
      return;
    }

    setLoading(true);

    try {
      const data = await verifyMFARecovery(challenge?.challenge_id, recoveryCode);
      if (data.challenge_id && data.mfa_setup) {
        setChallenge(data);
        setRecoveryCode('');
        setMFACode('');
        setUseRecoveryCode(false);
        setShowSetupKey(false);
      } else {
        setError(data.message || data.error || 'Recovery code verification failed');
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

        {!showingRecoveryCodes && !challenge && (
          <div className="mx-auto mb-4 min-h-10 max-w-[320px]">
            {error && (
              <div role="alert" className="flex items-start gap-2.5 text-left text-sm font-normal leading-[18px] text-danger">
                <CircleAlert size={18} strokeWidth={2.4} className="mt-0.5 shrink-0 text-danger" aria-hidden="true" />
                <div>
                  {error === PASSKEY_NOT_CONFIGURED_ERROR ? (
                    <>
                      Passkey sign-in is not configured yet. <strong className="font-bold">Sign in with password</strong> to continue.
                    </>
                  ) : (
                    error
                  )}
                  {errorDetails.length > 0 && (
                    <ul className="mt-2 list-disc space-y-1 pl-4 text-[12px] leading-4 text-danger">
                      {errorDetails.map((detail) => (
                        <li key={detail}>{detail}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}
            {!error && notice && (
              <div role="status" className="flex h-full items-center gap-2.5 text-left text-sm font-normal leading-[18px] text-success">
                <CircleCheck size={18} strokeWidth={2.4} className="shrink-0 text-success" aria-hidden="true" />
                <span>{notice}</span>
              </div>
            )}
          </div>
        )}

        {showingRecoveryCodes && (
          <div className="mx-auto max-w-[300px] text-left">
            <div className="mb-5">
              <h2 className="text-center text-[18px] font-bold leading-6 text-text-primary">Save recovery codes</h2>
              <p className="mt-3 text-left text-[13px] leading-5 text-text-secondary">
                These codes can be used if you lose access to your MFA methods. Each code works once.
              </p>
            </div>
            <button
              type="button"
              className="mb-3 ml-auto flex h-8 items-center justify-center gap-1.5 rounded-md border border-border bg-surface-card px-3 text-[12px] font-semibold text-text-secondary transition-colors hover:bg-surface-hover hover:text-text-primary"
              onClick={() => downloadRecoveryCodes(recoveryCodes)}
            >
              <Save size={14} strokeWidth={2.2} aria-hidden="true" />
              Save .txt
            </button>
            <div className="mb-5 grid gap-2 rounded-md border border-border bg-surface p-3">
              {recoveryCodes.map((code) => (
                <div key={code} className="font-mono text-sm font-semibold tracking-[0.08em] text-text-primary">
                  {code}
                </div>
              ))}
            </div>
            <button
              type="button"
              disabled={loading}
              className="mx-auto flex h-10 w-full max-w-[220px] items-center justify-center rounded-full border border-accent bg-accent px-5 text-[13px] font-semibold text-white-smoke shadow-md transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
              onClick={handleRecoveryCodesContinue}
            >
              I saved these codes
            </button>
          </div>
        )}

        {!showingRecoveryCodes && !challenge && passwordChangeChallenge && (
          <form noValidate onSubmit={handleInitialPasswordChange} className="mx-auto max-w-[300px] text-left">
            <div className="mb-5">
              <h2 className="text-center text-[18px] font-bold leading-6 text-text-primary">Change temporary password</h2>
              <p className="mt-3 text-left text-[13px] leading-5 text-text-secondary">
                Set a new password before accessing the administration console.
              </p>
            </div>
            <FormField label="New password" htmlFor="initial-new-password">
              <FormInput
                id="initial-new-password"
                type="password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                placeholder="At least 15 characters"
                minLength={15}
                autoComplete="new-password"
                required
              />
              <PasswordRequirementList items={initialPasswordRequirementItems} />
            </FormField>
            <FormField label="Confirm password" htmlFor="initial-confirm-password" className="mb-7">
              <FormInput
                id="initial-confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                placeholder="Repeat new password"
                autoComplete="new-password"
                minLength={15}
                required
              />
            </FormField>
            <button
              type="submit"
              disabled={loading}
              className="mx-auto flex h-10 w-full max-w-[220px] items-center justify-center rounded-full border border-accent bg-accent px-5 text-[13px] font-semibold text-white-smoke shadow-md transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? 'Changing...' : 'Change password'}
            </button>
            <button
              type="button"
              disabled={loading}
              className="mx-auto mt-2 flex h-10 w-full max-w-[220px] items-center justify-center rounded-full border border-border bg-surface-card px-5 text-[13px] font-medium text-text-secondary shadow-md transition-colors hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-50"
              onClick={() => {
                setPasswordChangeChallenge(null);
                setNewPassword('');
                setConfirmPassword('');
                setError('');
                setErrorDetails([]);
              }}
            >
              Back to sign in
            </button>
          </form>
        )}

        {!showingRecoveryCodes && !challenge && !passwordChangeChallenge && authMode === 'password' && (
          <form noValidate onSubmit={handleLogin} className="mx-auto max-w-[300px] text-left">
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

        {!showingRecoveryCodes && !challenge && !passwordChangeChallenge && authMode === 'passkey' && (
          <form noValidate onSubmit={handlePasskeyLogin} className="mx-auto max-w-[300px] text-left">
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

        {!showingRecoveryCodes && challenge && (
          <form noValidate onSubmit={useRecoveryCode ? handleMFARecovery : handleMFAVerify} className="mx-auto max-w-[300px] text-left">
            <div className="mb-5">
              <h2 className="text-center text-[18px] font-bold leading-6 text-text-primary">
                {challenge.mfa_setup ? 'Set up Authenticator App' : 'Two-factor authentication'}
              </h2>
              <p className="mt-3 text-left text-[13px] leading-5 text-text-secondary">
                {challenge.recovery_used
                  ? 'Your recovery code was accepted. Set up Authenticator App again to continue.'
                  : challenge.mfa_setup
                  ? 'Scan the QR code with your Authenticator App'
                  : useRecoveryCode
                    ? 'Enter one of the recovery codes saved for this account.'
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
            {useRecoveryCode && !challenge.mfa_setup ? (
              <FormField label="Recovery code" htmlFor="login-recovery-code" className="mb-4">
                <FormInput
                  id="login-recovery-code"
                  type="text"
                  value={recoveryCode}
                  onChange={(event) => setRecoveryCode(event.target.value)}
                  placeholder="XXXX-XXXX-XXXX"
                  autoComplete="one-time-code"
                  autoFocus
                  required
                />
              </FormField>
            ) : (
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
            )}
            <button
              type="submit"
              disabled={loading}
              className="mx-auto mt-6 flex h-10 w-full max-w-[220px] items-center justify-center rounded-full border border-accent bg-accent px-5 text-[13px] font-semibold text-white-smoke shadow-md transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? 'Verifying...' : useRecoveryCode ? 'Continue' : 'Verify'}
            </button>
            {!challenge.mfa_setup && (
              <button
                type="button"
                disabled={loading}
                className="mx-auto mt-2 flex h-10 w-full max-w-[220px] items-center justify-center rounded-full border border-border bg-surface-card px-5 text-[13px] font-medium text-text-secondary shadow-md transition-colors hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-50"
                onClick={() => {
                  setUseRecoveryCode((current) => !current);
                  setError('');
                  setMFACode('');
                  setRecoveryCode('');
                }}
              >
                {useRecoveryCode ? 'Use Authenticator App' : 'Use recovery code'}
              </button>
            )}
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
                setUseRecoveryCode(false);
                setRecoveryCode('');
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
