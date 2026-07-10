import { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronRight, CircleAlert, KeyRound, Trash2 } from 'lucide-react';
import {
  beginPasskeyRegistration,
  changeAdminPassword,
  createAdminPasskeyEnrollmentToken,
  deleteAdminPasskey,
  finishPasskeyRegistration,
  getAdminAccount,
  getAdminPasskeys,
  regenerateAdminRecoveryCodes,
  setAuthSession,
} from '../../api';
import { formatPasswordPolicyError, getPasswordPolicyIssues, passwordPolicyRequirements } from '../../passwordPolicy';
import { requiredFieldsMessage } from '../../formValidation';
import { credentialToJSON, prepareCreationOptions } from '../../webauthn';
import Button from '../ui/Button';
import FormField, { FormInput } from '../ui/FormField';
import LoadingSpinner from '../ui/LoadingSpinner';
import Modal from '../ui/Modal';

function passkeyErrorMessage(err) {
  const message = err?.message || '';
  const name = err?.name || '';
  const normalized = `${name} ${message}`.toLowerCase();
  if (normalized.includes('notallowed')) return 'Passkey setup was cancelled or timed out.';
  if (normalized.includes('security') || normalized.includes('rp id') || normalized.includes('domain')) {
    return 'Passkey domain mismatch. Open the configured PDP URL.';
  }
  return message || 'Passkey operation failed.';
}

async function fetchAccountSettings() {
  const [account, passkeys] = await Promise.all([
    getAdminAccount(),
    getAdminPasskeys(),
  ]);
  return {
    account,
    passkeys: Array.isArray(passkeys) ? passkeys : [],
  };
}

function normalizeMethods(methods) {
  if (!Array.isArray(methods)) return [];
  return methods
    .map((method) => String(method || '').trim().toLowerCase())
    .filter(Boolean);
}

function displayNameFromAccount(account) {
  const identity = account?.email || account?.username || '';
  if (!identity) return 'Administrator';
  const localPart = identity.split('@')[0] || identity;
  return localPart
    .split(/[._\-\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ') || identity;
}

function initialsFromName(name) {
  const parts = String(name || '')
    .split(/\s+/)
    .filter(Boolean);
  if (!parts.length) return 'AD';
  return parts
    .slice(0, 2)
    .map((part) => part.charAt(0).toUpperCase())
    .join('');
}

function formatTimestamp(value) {
  if (!value) return '';
  const normalized = String(value).includes('T') ? value : String(value).replace(' ', 'T');
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString(undefined, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  });
}

function Alert({ type = 'success', children, details = [] }) {
  const color = type === 'error' ? 'text-danger' : 'text-success';

  if (type === 'error') {
    return (
      <div role="alert" className={`mt-3 flex items-start gap-2.5 text-[13px] font-medium ${color}`}>
        <CircleAlert size={16} strokeWidth={2.4} className="mt-0.5 shrink-0 text-danger" aria-hidden="true" />
        <div>
          <div>{children}</div>
          {details.length > 0 && (
            <ul className="mt-2 list-disc space-y-1 pl-4 text-[13px] font-normal leading-5">
              {details.map((detail) => (
                <li key={detail}>{detail}</li>
              ))}
            </ul>
          )}
        </div>
      </div>
    );
  }

  return (
    <div role="status" className={`mt-3 text-[13px] font-medium ${color}`}>
      <div>{children}</div>
      {details.length > 0 && (
        <ul className="mt-2 list-disc space-y-1 pl-4 text-[13px] font-normal leading-5">
          {details.map((detail) => (
            <li key={detail}>{detail}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function StatusText({ tone = 'neutral', children }) {
  const tones = {
    success: 'text-success',
    muted: 'text-text-muted',
    neutral: 'text-text-secondary',
  };
  return (
    <span className={`shrink-0 text-right text-[13px] font-medium leading-5 ${tones[tone] || tones.neutral}`}>
      {children}
    </span>
  );
}

function AccountHeader({ account }) {
  const email = account?.email || account?.username || '-';
  const displayName = displayNameFromAccount(account);
  const initials = initialsFromName(displayName);

  return (
    <section className="flex items-center gap-3.5 rounded-lg border border-border bg-surface-card px-4 py-4">
      <div className="flex min-w-0 items-center gap-3.5">
        <div className="grid h-14 w-14 shrink-0 place-items-center rounded-full bg-accent text-[18px] font-semibold text-white-smoke">
          {initials}
        </div>
        <div className="min-w-0">
          <h2 className="truncate text-[19px] font-semibold leading-7 text-text-primary">{displayName}</h2>
          <p className="mt-0.5 truncate text-[13px] font-normal leading-5 text-text-secondary">{email}</p>
        </div>
      </div>
    </section>
  );
}

function SecurityRow({
  sectionKey,
  title,
  description,
  status,
  statusTone = 'neutral',
  open = false,
  onToggle,
  children,
}) {
  const isExpandable = typeof onToggle === 'function';

  return (
    <section
      data-settings-section={sectionKey}
      className="border-t border-border-light first:border-t-0"
    >
      {isExpandable ? (
        <button
          type="button"
          onClick={() => onToggle(sectionKey)}
          aria-expanded={open}
          aria-controls={`settings-${sectionKey}-panel`}
          className="flex w-full items-center gap-4 bg-transparent px-4 py-3.5 text-left transition-colors hover:bg-surface-hover focus:outline-none focus-visible:ring-[3px] focus-visible:ring-accent-muted"
        >
          <div className="min-w-0 flex-1">
            <p className="text-[15px] font-semibold leading-5 text-text-primary">{title}</p>
            {description && <p className="mt-1 text-[13px] font-normal leading-5 text-text-muted">{description}</p>}
          </div>
          <StatusText tone={statusTone}>{status}</StatusText>
          <ChevronRight
            size={18}
            strokeWidth={2.3}
            className={`shrink-0 text-text-muted transition-transform ${open ? 'rotate-90' : ''}`}
            aria-hidden="true"
          />
        </button>
      ) : (
        <div className="flex w-full items-center gap-4 px-4 py-3.5">
          <div className="min-w-0 flex-1">
            <p className="text-[15px] font-semibold leading-5 text-text-primary">{title}</p>
            {description && <p className="mt-1 text-[13px] font-normal leading-5 text-text-muted">{description}</p>}
          </div>
          <StatusText tone={statusTone}>{status}</StatusText>
        </div>
      )}

      {open && (
        <div id={`settings-${sectionKey}-panel`} className="border-t border-border-light bg-surface px-4 py-4">
          {children}
        </div>
      )}
    </section>
  );
}

export default function SettingsModal({ open, onClose }) {
  const [account, setAccount] = useState(null);
  const [passkeys, setPasskeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [passwordSaving, setPasswordSaving] = useState(false);
  const [passwordMessage, setPasswordMessage] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [passwordErrorDetails, setPasswordErrorDetails] = useState([]);
  const [recoveryPassword, setRecoveryPassword] = useState('');
  const [recoverySaving, setRecoverySaving] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState([]);
  const [recoveryError, setRecoveryError] = useState('');
  const [passkeyPassword, setPasskeyPassword] = useState('');
  const [passkeySaving, setPasskeySaving] = useState(false);
  const [passkeyDeleting, setPasskeyDeleting] = useState('');
  const [passkeyMessage, setPasskeyMessage] = useState('');
  const [passkeyError, setPasskeyError] = useState('');
  const [activeSection, setActiveSection] = useState('');
  const modalBodyRef = useRef(null);

  const methods = useMemo(() => normalizeMethods(account?.mfa_methods), [account]);
  const mfaActive = !!account?.mfa_enabled;
  const authenticatorActive = methods.includes('totp');
  const recoveryCodeCount = Number(account?.recovery_code_count || 0);
  const recoveryCodesActive = recoveryCodeCount > 0;
  const passkeyCount = passkeys.length;
  const passwordChangedText = account?.password_changed_at
    ? `Changed ${formatTimestamp(account.password_changed_at)}`
    : 'Configured';
  const passwordPolicyIssues = getPasswordPolicyIssues(passwordForm.newPassword, {
    account,
    currentPassword: passwordForm.currentPassword,
    confirmPassword: passwordForm.confirmPassword,
    checkConfirmation: !!passwordForm.confirmPassword,
  });

  useEffect(() => {
    let cancelled = false;

    async function loadAccount() {
      setLoading(true);
      setLoadError('');
      try {
        const data = await fetchAccountSettings();
        if (!cancelled) {
          setAccount(data.account);
          setPasskeys(data.passkeys);
        }
      } catch (err) {
        if (!cancelled) setLoadError(err.message || 'Account settings could not be loaded');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    if (open) void loadAccount();
    return () => {
      cancelled = true;
    };
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const frame = window.requestAnimationFrame(() => {
      const body = modalBodyRef.current;
      if (!body) return;
      if (activeSection) {
        body
          .querySelector(`[data-settings-section="${activeSection}"]`)
          ?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        return;
      }
      const maxScroll = Math.max(0, body.scrollHeight - body.clientHeight);
      if (body.scrollTop > maxScroll) {
        body.scrollTo({ top: maxScroll, behavior: 'smooth' });
      }
    });
    return () => window.cancelAnimationFrame(frame);
  }, [activeSection, open]);

  const toggleSection = (sectionKey) => {
    setActiveSection((current) => (current === sectionKey ? '' : sectionKey));
  };

  const handlePasswordChange = async (event) => {
    event.preventDefault();
    setPasswordError('');
    setPasswordErrorDetails([]);
    setPasswordMessage('');

    const missingFields = [];
    if (!passwordForm.currentPassword) missingFields.push('Current password');
    if (!passwordForm.newPassword) missingFields.push('New password');
    if (!passwordForm.confirmPassword) missingFields.push('Confirm password');
    if (missingFields.length) {
      setPasswordError(requiredFieldsMessage(missingFields));
      return;
    }

    const policyIssues = getPasswordPolicyIssues(passwordForm.newPassword, {
      account,
      currentPassword: passwordForm.currentPassword,
      confirmPassword: passwordForm.confirmPassword,
      checkConfirmation: true,
    });
    if (policyIssues.length) {
      setPasswordError('The password does not meet the policy.');
      setPasswordErrorDetails(policyIssues);
      return;
    }
    setPasswordSaving(true);
    try {
      const updated = await changeAdminPassword(
        passwordForm.currentPassword,
        passwordForm.newPassword,
        passwordForm.confirmPassword,
      );
      setAccount(updated);
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
      setPasswordMessage('Password changed.');
    } catch (err) {
      const policyError = formatPasswordPolicyError(err, 'Password could not be changed');
      setPasswordError(policyError.message);
      setPasswordErrorDetails(policyError.details);
    } finally {
      setPasswordSaving(false);
    }
  };

  const handleRecoveryRegenerate = async (event) => {
    event.preventDefault();
    setRecoveryError('');
    setRecoveryCodes([]);
    if (!recoveryPassword) {
      setRecoveryError(requiredFieldsMessage(['Current password']));
      return;
    }

    setRecoverySaving(true);
    try {
      const data = await regenerateAdminRecoveryCodes(recoveryPassword);
      const codes = Array.isArray(data?.recovery_codes) ? data.recovery_codes : [];
      setRecoveryCodes(codes);
      setRecoveryPassword('');
      setAccount((current) => current ? { ...current, recovery_code_count: codes.length } : current);
    } catch (err) {
      setRecoveryError(err.message || 'Recovery codes could not be regenerated');
    } finally {
      setRecoverySaving(false);
    }
  };

  const refreshSettings = async () => {
    const data = await fetchAccountSettings();
    setAccount(data.account);
    setPasskeys(data.passkeys);
  };

  const handlePasskeyAdd = async (event) => {
    event.preventDefault();
    setPasskeyError('');
    setPasskeyMessage('');

    if (!passkeyPassword) {
      setPasskeyError(requiredFieldsMessage(['Current password']));
      return;
    }
    if (!window.PublicKeyCredential) {
      setPasskeyError('This browser cannot create a passkey.');
      return;
    }

    setPasskeySaving(true);
    try {
      const tokenData = await createAdminPasskeyEnrollmentToken(passkeyPassword);
      const enrollmentToken = tokenData?.auth_token || tokenData?.token;
      if (!enrollmentToken) {
        throw new Error('Passkey setup could not be started');
      }
      const options = await beginPasskeyRegistration(enrollmentToken);
      const credential = await navigator.credentials.create({ publicKey: prepareCreationOptions(options) });
      if (!credential) {
        throw new Error('Passkey setup was cancelled');
      }
      const session = await finishPasskeyRegistration(enrollmentToken, credentialToJSON(credential));
      if (session?.auth_token || session?.token) {
        setAuthSession(session);
      }
      await refreshSettings();
      setPasskeyPassword('');
      setPasskeyMessage('Passkey added.');
    } catch (err) {
      setPasskeyError(passkeyErrorMessage(err));
    } finally {
      setPasskeySaving(false);
    }
  };

  const handlePasskeyDelete = async (passkey) => {
    setPasskeyError('');
    setPasskeyMessage('');
    if (!passkeyPassword) {
      setPasskeyError(requiredFieldsMessage(['Current password']));
      return;
    }
    if (!window.confirm('Delete this passkey?')) {
      return;
    }

    setPasskeyDeleting(passkey.id);
    try {
      await deleteAdminPasskey(passkey.id, passkeyPassword);
      await refreshSettings();
      setPasskeyPassword('');
      setPasskeyMessage('Passkey deleted.');
    } catch (err) {
      setPasskeyError(err.message || 'Passkey could not be deleted');
    } finally {
      setPasskeyDeleting('');
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Settings"
      size="2xl"
      panelClassName="h-[580px] !rounded-xl"
      bodyClassName="!space-y-0 !p-0"
      bodyRef={modalBodyRef}
    >
      {loading ? (
        <div className="grid min-h-full place-items-center">
          <LoadingSpinner size="lg" />
        </div>
      ) : loadError ? (
        <div className="p-6">
          <Alert type="error">{loadError}</Alert>
        </div>
      ) : (
        <div className="space-y-5 px-6 py-5">
          <AccountHeader account={account} />

          <section>
            <div className="overflow-hidden rounded-lg border border-border bg-surface-card">
              <SecurityRow
                sectionKey="authenticator"
                title="Authenticator app"
                description="Verification code method"
                status={authenticatorActive ? 'Active' : 'Not active'}
                statusTone={authenticatorActive ? 'success' : 'muted'}
              />

              <SecurityRow
                sectionKey="password"
                title="Password"
                description="Change account password"
                status={passwordChangedText}
                open={activeSection === 'password'}
                onToggle={toggleSection}
              >
                <form noValidate onSubmit={handlePasswordChange} className="grid w-full gap-1">
                  {passwordError && <Alert type="error" details={passwordErrorDetails}>{passwordError}</Alert>}
                  <FormField label="Current password" htmlFor="settings-current-password" labelClassName="[font-size:12px]">
                    <FormInput
                      id="settings-current-password"
                      type="password"
                      value={passwordForm.currentPassword}
                      onChange={(event) => setPasswordForm((current) => ({ ...current, currentPassword: event.target.value }))}
                      autoComplete="current-password"
                      className="[font-size:14px] py-2.5"
                      required
                    />
                  </FormField>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <FormField
                      label="New password"
                      htmlFor="settings-new-password"
                      labelClassName="[font-size:12px]"
                    >
                      <FormInput
                        id="settings-new-password"
                        type="password"
                        value={passwordForm.newPassword}
                        onChange={(event) => setPasswordForm((current) => ({ ...current, newPassword: event.target.value }))}
                        autoComplete="new-password"
                        minLength={15}
                        className="[font-size:14px] py-2.5"
                        required
                      />
                      {passwordForm.newPassword ? (
                        passwordPolicyIssues.length ? (
                          <ul className="mt-2 list-disc space-y-1 pl-4 text-[13px] leading-5 text-text-muted">
                            {passwordPolicyIssues.map((issue) => (
                              <li key={issue}>{issue}</li>
                            ))}
                          </ul>
                        ) : (
                          <p className="mt-2 text-[13px] font-medium text-success">Password meets the policy.</p>
                        )
                      ) : (
                        <ul className="mt-2 list-disc space-y-1 pl-4 text-[13px] leading-5 text-text-muted">
                          {passwordPolicyRequirements.map((requirement) => (
                            <li key={requirement}>{requirement}</li>
                          ))}
                        </ul>
                      )}
                    </FormField>
                    <FormField label="Confirm password" htmlFor="settings-confirm-password" labelClassName="[font-size:12px]">
                      <FormInput
                        id="settings-confirm-password"
                        type="password"
                        value={passwordForm.confirmPassword}
                        onChange={(event) => setPasswordForm((current) => ({ ...current, confirmPassword: event.target.value }))}
                        autoComplete="new-password"
                        minLength={15}
                        className="[font-size:14px] py-2.5"
                        required
                      />
                    </FormField>
                  </div>
                  <div className="mt-1">
                    <Button type="submit" disabled={passwordSaving} className="[font-size:13px] px-4 py-2">
                      {passwordSaving ? 'Saving...' : 'Save password'}
                    </Button>
                  </div>
                  {passwordMessage && <Alert>{passwordMessage}</Alert>}
                </form>
              </SecurityRow>

              <SecurityRow
                sectionKey="recovery"
                title="Recovery codes"
                description="Backup access codes"
                status={recoveryCodesActive ? `${recoveryCodeCount} active` : 'Not created'}
                statusTone={recoveryCodesActive ? 'success' : 'muted'}
                open={activeSection === 'recovery'}
                onToggle={toggleSection}
              >
                <form noValidate onSubmit={handleRecoveryRegenerate} className="grid w-full gap-1">
                  {!mfaActive && <Alert type="error">MFA is not active for this account.</Alert>}
                  {recoveryError && <Alert type="error">{recoveryError}</Alert>}
                  <FormField label="Current password" htmlFor="settings-recovery-password" labelClassName="[font-size:12px]">
                    <FormInput
                      id="settings-recovery-password"
                      type="password"
                      value={recoveryPassword}
                      onChange={(event) => setRecoveryPassword(event.target.value)}
                      autoComplete="current-password"
                      disabled={!mfaActive}
                      className="[font-size:14px] py-2.5"
                      required
                    />
                  </FormField>
                  <div className="mt-1">
                    <Button type="submit" disabled={!mfaActive || recoverySaving} className="[font-size:13px] px-4 py-2">
                      {recoverySaving ? 'Generating...' : 'Regenerate recovery codes'}
                    </Button>
                  </div>
                </form>

                {recoveryCodes.length > 0 && (
                  <div className="mt-4 rounded-lg border border-border bg-surface-card px-4 py-3">
                    <p className="text-[13px] font-semibold text-text-primary">Save these recovery codes</p>
                    <div className="mt-3 grid gap-2 sm:grid-cols-2">
                      {recoveryCodes.map((code) => (
                        <code key={code} className="text-[13px] font-semibold tracking-[0.08em] text-text-primary">
                          {code}
                        </code>
                      ))}
                    </div>
                  </div>
                )}
              </SecurityRow>

              <SecurityRow
                sectionKey="passkeys"
                title="Passkeys"
                description="Biometric or device authentication"
                status={passkeyCount > 0 ? `${passkeyCount} added` : 'Not added'}
                statusTone={passkeyCount > 0 ? 'success' : 'muted'}
                open={activeSection === 'passkeys'}
                onToggle={toggleSection}
              >
                <form noValidate onSubmit={handlePasskeyAdd} className="grid w-full gap-1">
                  {passkeyError && <Alert type="error">{passkeyError}</Alert>}
                  {passkeyMessage && <Alert>{passkeyMessage}</Alert>}
                  <FormField label="Current password" htmlFor="settings-passkey-password" labelClassName="[font-size:12px]">
                    <FormInput
                      id="settings-passkey-password"
                      type="password"
                      value={passkeyPassword}
                      onChange={(event) => setPasskeyPassword(event.target.value)}
                      autoComplete="current-password"
                      className="[font-size:14px] py-2.5"
                      required
                    />
                  </FormField>
                  <div className="mt-1">
                    <Button type="submit" disabled={passkeySaving || !!passkeyDeleting} className="[font-size:13px] px-4 py-2">
                      <KeyRound size={14} strokeWidth={2.3} aria-hidden="true" />
                      {passkeySaving ? 'Adding...' : 'Add passkey'}
                    </Button>
                  </div>
                </form>

                <div className="mt-4 grid gap-2">
                  {passkeys.length > 0 ? (
                    passkeys.map((passkey) => (
                      <div
                        key={passkey.id}
                        className="flex items-center justify-between gap-3 rounded-lg border border-border bg-surface-card px-3 py-2.5"
                      >
                        <div className="min-w-0">
                          <p className="truncate text-[14px] font-medium text-text-primary">{passkey.name || 'Passkey'}</p>
                          <p className="mt-0.5 text-[12px] font-normal text-text-secondary">{passkey.created_at || 'Date unavailable'}</p>
                        </div>
                        <Button
                          type="button"
                          variant="danger"
                          disabled={passkeySaving || passkeyDeleting === passkey.id}
                          onClick={() => handlePasskeyDelete(passkey)}
                          className="shrink-0 [font-size:12px]"
                        >
                          <Trash2 size={13} strokeWidth={2.3} aria-hidden="true" />
                          {passkeyDeleting === passkey.id ? 'Deleting...' : 'Delete'}
                        </Button>
                      </div>
                    ))
                  ) : (
                    <p className="text-[13px] font-normal text-text-secondary">No passkeys enrolled.</p>
                  )}
                </div>
              </SecurityRow>
            </div>
          </section>
        </div>
      )}
    </Modal>
  );
}
