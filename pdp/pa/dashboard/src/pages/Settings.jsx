import { useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronUp, CircleAlert } from 'lucide-react';
import {
  changeAdminPassword,
  getAdminAccount,
  regenerateAdminRecoveryCodes,
} from '../api';
import { formatPasswordPolicyError, getPasswordPolicyIssues, passwordPolicyRequirements } from '../passwordPolicy';
import { requiredFieldsMessage } from '../formValidation';
import PageHeader from '../components/ui/PageHeader';
import Button from '../components/ui/Button';
import FormField, { FormInput } from '../components/ui/FormField';
import LoadingSpinner from '../components/ui/LoadingSpinner';

const methodLabels = {
  totp: 'Authenticator app',
  webauthn: 'Passkey',
};

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

function Alert({ type = 'success', children, details = [] }) {
  const color = type === 'error' ? 'text-danger' : 'text-success';

  if (type === 'error') {
    return (
      <div role="alert" className={`mt-3 flex items-start gap-2.5 text-[15px] font-semibold ${color}`}>
        <CircleAlert size={18} strokeWidth={2.4} className="mt-0.5 shrink-0 text-danger" aria-hidden="true" />
        <div>
          <div>{children}</div>
          {details.length > 0 && (
            <ul className="mt-2 list-disc space-y-1 pl-4 text-[13px] font-medium leading-5">
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
    <div role="status" className={`mt-3 text-[15px] font-semibold ${color}`}>
      <div>{children}</div>
      {details.length > 0 && (
        <ul className="mt-2 list-disc space-y-1 pl-4 text-[13px] font-medium leading-5">
          {details.map((detail) => (
            <li key={detail}>{detail}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function CollapsibleSection({ title, open, onToggle, children }) {
  return (
    <section className="pt-2">
      <button
        type="button"
        onClick={onToggle}
        className="inline-flex items-center gap-2 border-0 bg-transparent p-0 text-left shadow-none transition-colors hover:text-accent focus:outline-none focus-visible:ring-[3px] focus-visible:ring-accent-muted"
        aria-expanded={open}
      >
        <span className="text-[21px] font-bold leading-7 text-text-primary">{title}</span>
        {open ? (
          <ChevronUp size={20} strokeWidth={2.4} className="text-text-secondary" aria-hidden="true" />
        ) : (
          <ChevronDown size={20} strokeWidth={2.4} className="text-text-secondary" aria-hidden="true" />
        )}
      </button>
      {open && <div className="mt-5">{children}</div>}
    </section>
  );
}

function ProfileMetric({ label, children }) {
  return (
    <div className="min-w-[150px]">
      <p className="text-[13px] font-semibold uppercase tracking-[0.2px] text-text-secondary">{label}</p>
      <div className="mt-1 text-[18px] font-bold leading-7 text-text-primary">{children}</div>
    </div>
  );
}

function AccountProfile({ account, activeMethodsText, mfaActive, recoveryCodeCount, recoveryCodesActive }) {
  const email = account?.email || account?.username || '-';
  const displayName = displayNameFromAccount(account);
  const initials = initialsFromName(displayName);

  return (
    <section className="max-w-4xl overflow-hidden rounded-md border border-border bg-surface-card shadow-sm">
      <div
        className="h-28"
        style={{
          background:
            'linear-gradient(135deg, rgba(44,97,100,0.96) 0%, rgba(118,178,183,0.45) 38%, rgba(246,194,91,0.58) 68%, rgba(244,152,164,0.48) 100%)',
        }}
      />
      <div className="px-6 pb-6">
        <div className="-mt-10 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-end">
            <div className="grid h-20 w-20 shrink-0 place-items-center rounded-full border-4 border-surface-card bg-accent text-2xl font-bold text-white-smoke shadow-md">
              {initials}
            </div>
            <div className="min-w-0 pb-1">
              <p className="text-[13px] font-semibold uppercase tracking-[0.2px] text-text-secondary">Administrator account</p>
              <h2 className="mt-1 text-[24px] font-bold leading-8 text-text-primary">{displayName}</h2>
              <p className="mt-1 break-all text-[15px] font-semibold text-text-secondary">{email}</p>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:pb-2">
            <ProfileMetric label="MFA methods">
              <span className={mfaActive ? 'text-text-primary' : 'text-text-muted'}>{activeMethodsText}</span>
            </ProfileMetric>
            <ProfileMetric label="Recovery codes">
              <span className={recoveryCodesActive ? 'text-success' : 'text-text-muted'}>
                {recoveryCodesActive ? `${recoveryCodeCount} active` : 'Inactive'}
              </span>
            </ProfileMetric>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function Settings() {
  const [account, setAccount] = useState(null);
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
  const [passwordSectionOpen, setPasswordSectionOpen] = useState(false);
  const [recoverySectionOpen, setRecoverySectionOpen] = useState(false);

  const methods = useMemo(() => normalizeMethods(account?.mfa_methods), [account]);
  const mfaActive = !!account?.mfa_enabled;
  const recoveryCodeCount = Number(account?.recovery_code_count || 0);
  const recoveryCodesActive = recoveryCodeCount > 0;
  const activeMethodsText = mfaActive && methods.length
    ? methods.map((method) => methodLabels[method] || method).join(', ')
    : 'No active methods';
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
        const data = await getAdminAccount();
        if (!cancelled) setAccount(data);
      } catch (err) {
        if (!cancelled) setLoadError(err.message || 'Account settings could not be loaded');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void loadAccount();
    return () => {
      cancelled = true;
    };
  }, []);

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

  if (loading) {
    return (
      <div className="grid min-h-[420px] place-items-center">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div className="w-full pb-10">
      <PageHeader title="Settings" />

      {loadError ? (
        <div className="max-w-4xl">
          <Alert type="error">{loadError}</Alert>
        </div>
      ) : (
        <div className="max-w-4xl space-y-8">
          <AccountProfile
            account={account}
            activeMethodsText={activeMethodsText}
            mfaActive={mfaActive}
            recoveryCodeCount={recoveryCodeCount}
            recoveryCodesActive={recoveryCodesActive}
          />

          <section className="space-y-6">
            <h2 className="text-[19px] font-bold text-text-primary">Security</h2>

            <CollapsibleSection
              title="Change password"
              open={passwordSectionOpen}
              onToggle={() => setPasswordSectionOpen((current) => !current)}
            >
              <form noValidate onSubmit={handlePasswordChange} className="grid w-full max-w-3xl gap-1">
                {passwordError && <Alert type="error" details={passwordErrorDetails}>{passwordError}</Alert>}
                <FormField label="Current password" htmlFor="settings-current-password" labelClassName="[font-size:13px]">
                  <FormInput
                    id="settings-current-password"
                    type="password"
                    value={passwordForm.currentPassword}
                    onChange={(event) => setPasswordForm((current) => ({ ...current, currentPassword: event.target.value }))}
                    autoComplete="current-password"
                    className="[font-size:15px] py-3"
                    required
                  />
                </FormField>
                <div className="grid gap-4 sm:grid-cols-2">
                  <FormField
                    label="New password"
                    htmlFor="settings-new-password"
                    labelClassName="[font-size:13px]"
                  >
                    <FormInput
                      id="settings-new-password"
                      type="password"
                      value={passwordForm.newPassword}
                      onChange={(event) => setPasswordForm((current) => ({ ...current, newPassword: event.target.value }))}
                      autoComplete="new-password"
                      minLength={15}
                      className="[font-size:15px] py-3"
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
                        <p className="mt-2 text-[13px] font-semibold text-success">Password meets the policy.</p>
                      )
                    ) : (
                      <ul className="mt-2 list-disc space-y-1 pl-4 text-[13px] leading-5 text-text-muted">
                        {passwordPolicyRequirements.map((requirement) => (
                          <li key={requirement}>{requirement}</li>
                        ))}
                      </ul>
                    )}
                  </FormField>
                  <FormField label="Confirm password" htmlFor="settings-confirm-password" labelClassName="[font-size:13px]">
                    <FormInput
                      id="settings-confirm-password"
                      type="password"
                      value={passwordForm.confirmPassword}
                      onChange={(event) => setPasswordForm((current) => ({ ...current, confirmPassword: event.target.value }))}
                      autoComplete="new-password"
                      minLength={15}
                      className="[font-size:15px] py-3"
                      required
                    />
                  </FormField>
                </div>
                <div className="mt-2">
                  <Button type="submit" disabled={passwordSaving} className="[font-size:14px] px-5 py-2.5">
                    {passwordSaving ? 'Saving...' : 'Save password'}
                  </Button>
                </div>
                {passwordMessage && <Alert>{passwordMessage}</Alert>}
              </form>
            </CollapsibleSection>

            <CollapsibleSection
              title="Recovery codes"
              open={recoverySectionOpen}
              onToggle={() => setRecoverySectionOpen((current) => !current)}
            >
              <form noValidate onSubmit={handleRecoveryRegenerate} className="grid w-full max-w-3xl gap-1">
                {!mfaActive && <Alert type="error">MFA is not active for this account.</Alert>}
                {recoveryError && <Alert type="error">{recoveryError}</Alert>}
                <FormField label="Current password" htmlFor="settings-recovery-password" labelClassName="[font-size:13px]">
                  <FormInput
                    id="settings-recovery-password"
                    type="password"
                    value={recoveryPassword}
                    onChange={(event) => setRecoveryPassword(event.target.value)}
                    autoComplete="current-password"
                    disabled={!mfaActive}
                    className="[font-size:15px] py-3"
                    required
                  />
                </FormField>
                <div className="mt-2">
                  <Button type="submit" disabled={!mfaActive || recoverySaving} className="[font-size:14px] px-5 py-2.5">
                    {recoverySaving ? 'Generating...' : 'Regenerate recovery codes'}
                  </Button>
                </div>
              </form>

              {recoveryCodes.length > 0 && (
                <div className="mt-5 max-w-3xl">
                  <p className="text-[15px] font-bold text-text-primary">Save these recovery codes</p>
                  <div className="mt-3 grid gap-2 sm:grid-cols-2">
                    {recoveryCodes.map((code) => (
                      <code key={code} className="text-[15px] font-bold tracking-[0.08em] text-text-primary">
                        {code}
                      </code>
                    ))}
                  </div>
                </div>
              )}
            </CollapsibleSection>
          </section>
        </div>
      )}
    </div>
  );
}
