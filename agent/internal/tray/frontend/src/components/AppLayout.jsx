import {
  AlertCircle,
  CircleUserRound,
  Database,
  LogOut,
  Minus,
  ShieldCheck,
  X,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import {
  BrowserOpenURL,
  WindowMinimise,
} from '../../wailsjs/runtime/runtime';
import {
  isDeviceEnrolled,
} from '../lib/dashboard';
import SecurityView from './SecurityView';

function AppLayout({
  dashboard,
  dashboardError,
  dashboardLoading,
  enrollmentError,
  enrollmentLoading,
  loginError,
  loginLoading,
  onHide,
  onLogout,
  onStartEnrollment,
  onStartLogin,
}) {
  const enrolled = isDeviceEnrolled(dashboard);
  const waitingForDashboard = dashboardLoading && !dashboard;
  const userSession = dashboard?.user_session || {};
  const userSessionState = String(userSession.state || 'SIGNED_OUT').toUpperCase();
  const authenticated = userSessionState === 'AUTHENTICATED';
  const [activeView, setActiveView] = useState('security');

  return (
    <div className="flex h-full w-full flex-col bg-[var(--surface)]">
      <WindowTitleBar dashboard={dashboard} onClose={onHide} />

      <div className="relative min-h-0 flex-1">
        {waitingForDashboard ? (
          <AgentLoadingScreen />
        ) : enrolled && authenticated ? (
          <>
            <Sidebar
              activeView={activeView}
              loginLoading={loginLoading}
              onLogout={onLogout}
              onSelectView={setActiveView}
            />
            <EnrolledScreen
              activeView={activeView}
              dashboard={dashboard}
              error={dashboardError}
              loading={dashboardLoading}
              loginError={loginError}
            />
          </>
        ) : enrolled ? (
          <EnrolledSignInScreen
            dashboard={dashboard}
            error={dashboardError}
            loginError={loginError}
            loginLoading={loginLoading}
            onStartLogin={onStartLogin}
          />
        ) : (
          <UnenrolledScreen
            error={dashboardError}
            enrollmentError={enrollmentError}
            enrollmentLoading={enrollmentLoading}
            onStartEnrollment={onStartEnrollment}
          />
        )}
      </div>
    </div>
  );
}

function EnrolledScreen({
  activeView = 'security',
  dashboard,
  error = '',
  loading = false,
  loginError = '',
}) {
  const userSession = dashboard?.user_session || {};
  const displayError = loginError || userSession.last_error || error;
  const stepUpURL = userSession.step_up_url || '';
  const stepUpMessage = stepUpURL ? (userSession.message || 'Additional verification is required.') : '';
  const openedStepUpURLRef = useRef('');

  useEffect(() => {
    if (!stepUpURL) {
      openedStepUpURLRef.current = '';
      return;
    }
    if (openedStepUpURLRef.current === stepUpURL) {
      return;
    }
    openedStepUpURLRef.current = stepUpURL;
    if (stepUpURL.startsWith('https://') && window?.runtime?.BrowserOpenURL) {
      BrowserOpenURL(stepUpURL);
    }
  }, [stepUpURL]);

  return (
    <main className="h-full min-w-0 overflow-hidden bg-[#f9faf9] text-[var(--text-primary)]">
      {stepUpMessage ? (
        <div className="ml-[76px] px-5 pt-4">
          <div className="flex gap-2 rounded-md border border-[color-mix(in_srgb,var(--accent)_28%,transparent)] bg-[var(--accent-muted)] px-3 py-2 text-sm font-semibold text-[var(--accent)]">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span className="min-w-0 break-words leading-5">{stepUpMessage}</span>
          </div>
        </div>
      ) : null}

      {displayError ? (
        <div className="ml-[76px] px-5 pt-4">
          <div className="flex gap-2 rounded-md border border-[color-mix(in_srgb,var(--danger)_28%,transparent)] bg-[var(--danger-muted)] px-3 py-2 text-sm font-semibold text-[var(--danger)]">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <p className="min-w-0 break-words leading-5">{displayError}</p>
          </div>
        </div>
      ) : null}

      {activeView === 'resources' ? (
        <ResourcesView dashboard={dashboard} />
      ) : (
        <SecurityView dashboard={dashboard} error="" loading={loading} />
      )}
    </main>
  );
}

function ResourcesView({ dashboard }) {
  const catalog = dashboard?.catalog || {};
  const resources = Array.isArray(catalog.resources) ? catalog.resources : [];

  return (
    <section className="ml-[76px] h-full overflow-auto bg-[#f9faf9] px-5 py-4 text-[#202427]">
      <header className="mb-4">
        <p className="text-lg font-extrabold leading-none text-[#1f262b]">Resources</p>
        <p className="mt-2 max-w-[480px] text-sm font-medium leading-5 text-[#667078]">
          Applications available for the authenticated user.
        </p>
      </header>

      <div className="grid gap-2">
        {resources.length > 0 ? (
          resources.map((resource) => (
            <article
              key={resource.resource_id || resource.fqdn}
              className="rounded-md border border-[var(--border)] bg-white px-4 py-3 shadow-[0_8px_22px_color-mix(in_srgb,var(--graphite)_5%,transparent)]"
            >
              <div className="flex min-w-0 items-start gap-3">
                <div className="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-[#d5d9da] bg-[#f0f2f2] text-[var(--accent)]">
                  <Database className="h-5 w-5" strokeWidth={2.2} />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-base font-semibold leading-5 text-[#1f262b]">
                    {resource.display_name || resource.resource_id || resource.fqdn}
                  </p>
                  <p className="mt-1 truncate text-xs font-semibold text-[#687179]">
                    {resource.fqdn || resource.resource_id}
                  </p>
                  <p className="mt-1 text-xs font-medium text-[#7a838a]">
                    {[resource.protocol, resource.port ? String(resource.port) : ''].filter(Boolean).join(' : ') || 'Resource access'}
                  </p>
                </div>
              </div>
            </article>
          ))
        ) : (
          <div className="rounded-md border border-[var(--border)] bg-white px-4 py-4 text-sm font-medium text-[var(--text-secondary)]">
            No resources available.
          </div>
        )}
      </div>
    </section>
  );
}

function EnrolledSignInScreen({
  dashboard,
  error = '',
  loginError = '',
  loginLoading = false,
  onStartLogin,
}) {
  const userSession = dashboard?.user_session || {};
  const state = String(userSession.state || 'SIGNED_OUT').toUpperCase();
  const authenticating = state === 'AUTHENTICATING' || loginLoading;
  const displayError = loginError || userSession.last_error || error;
  const message = userSession.message || 'Sign in required to access protected resources.';

  return (
    <section className="grid h-full place-items-center bg-[#f9faf9] px-8 py-8 text-[var(--text-primary)]">
      <div className="flex w-full max-w-[340px] flex-col items-center text-center">
        <h1 className="text-xl font-semibold leading-tight text-[var(--text-primary)]">Device enrolled</h1>
        <p className="mt-3 text-base font-medium leading-6 text-[var(--text-primary)]">{message}</p>

        <button
          type="button"
          className="mt-5 inline-flex h-10 min-w-[112px] items-center justify-center rounded-xl bg-[var(--accent)] px-6 text-sm font-bold tracking-normal text-white transition-colors hover:bg-[color-mix(in_srgb,var(--accent)_86%,black)] disabled:cursor-wait disabled:opacity-70"
          onClick={onStartLogin}
          disabled={authenticating}
        >
          {authenticating ? 'STARTING...' : 'SIGN IN'}
        </button>

        {displayError ? (
          <div className="mt-4 flex gap-2 rounded-md border border-[color-mix(in_srgb,var(--danger)_28%,transparent)] bg-[var(--danger-muted)] px-3 py-2 text-sm font-semibold text-[var(--danger)]">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <p className="min-w-0 break-words leading-5">{displayError}</p>
          </div>
        ) : null}
      </div>
    </section>
  );
}

function WindowTitleBar({ dashboard, onClose }) {
  const userSession = dashboard?.user_session || {};
  const accountName = userSession.display_name || userSession.email || '';
  const authenticated = String(userSession.state || '').toUpperCase() === 'AUTHENTICATED';
  const initials = accountInitials(accountName);

  return (
    <header
      className="flex h-8 shrink-0 items-center justify-between border-b text-[#111111]"
      style={{
        background: 'color-mix(in srgb, var(--cool-steel) 24%, var(--white-smoke) 76%)',
        borderColor: 'color-mix(in srgb, var(--border) 42%, transparent)',
      }}
    >
      <div
        className="flex h-full min-w-0 flex-1 items-center gap-2 px-3"
        style={{ '--wails-draggable': 'drag' }}
      >
        <div className="min-w-0 overflow-hidden whitespace-nowrap">
          <h2 className="m-0 truncate text-lg font-extrabold leading-none text-[var(--text-primary)]">
            <span className="text-[var(--accent)]">TRUST</span>AGENT
          </h2>
        </div>
      </div>
      <div className="flex h-full shrink-0 items-center">
        {authenticated ? (
          <div
            className="flex h-full max-w-[245px] items-center gap-2 px-3 text-xs font-semibold text-[#53595d]"
            title={accountName}
          >
            <span className="min-w-0 truncate">My Account</span>
            <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-[#74b6ef] text-[10px] font-bold uppercase leading-none text-white">
              {initials}
            </span>
            <CircleUserRound className="h-[19px] w-[19px] shrink-0 text-[#555b60]" strokeWidth={2} />
          </div>
        ) : null}
        <button
          type="button"
          className="grid h-full w-12 cursor-pointer place-items-center bg-transparent text-[#111111] transition-colors duration-150 hover:bg-[#efe9e7]"
          onClick={() => WindowMinimise()}
          title="Minimize"
        >
          <Minus size={15} strokeWidth={1.8} />
        </button>
        <button
          type="button"
          className="grid h-full w-12 cursor-pointer place-items-center bg-transparent text-[#111111] transition-colors duration-150 hover:bg-[#c42b1c] hover:text-white"
          onClick={onClose}
          title="Close"
        >
          <X size={16} strokeWidth={1.8} />
        </button>
      </div>
    </header>
  );
}

function accountInitials(name) {
  const clean = String(name || '').trim();
  if (!clean) return 'U';
  const localPart = clean.includes('@') ? clean.split('@')[0] : clean;
  const parts = localPart
    .split(/[\s._-]+/)
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length >= 2) {
    return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
  }
  return localPart.slice(0, 2).toUpperCase();
}

function AgentLoadingScreen() {
  return (
    <section className="grid h-full place-items-center bg-[#f9faf9] px-8 py-8 text-[var(--accent)]">
      <h1 className="text-xl font-medium leading-none text-[var(--accent)]">
        Please wait
        <span className="waiting-dots" aria-hidden="true">
          <span className="waiting-dot waiting-dot-1">.</span>
          <span className="waiting-dot waiting-dot-2">.</span>
          <span className="waiting-dot waiting-dot-3">.</span>
        </span>
      </h1>
    </section>
  );
}

function UnenrolledScreen({
  error = '',
  enrollmentError = '',
  enrollmentLoading = false,
  onStartEnrollment,
}) {
  const displayError = enrollmentError || error;
  return (
    <section className="grid h-full place-items-center bg-[#f9faf9] px-8 py-8 text-[var(--text-primary)]">
      <div className="flex w-full max-w-[320px] flex-col items-center text-center">
        <h1 className="text-xl font-semibold uppercase leading-tight text-[var(--text-primary)]">Unenrolled device</h1>

        <button
          type="button"
          className="mt-5 inline-flex h-10 min-w-[112px] items-center justify-center rounded-xl bg-[var(--accent)] px-6 text-sm font-bold tracking-normal text-white transition-colors hover:bg-[color-mix(in_srgb,var(--accent)_86%,black)] disabled:cursor-wait disabled:opacity-70"
          onClick={onStartEnrollment}
          disabled={enrollmentLoading}
        >
          {enrollmentLoading ? 'STARTING...' : 'ENROLL'}
        </button>

        {displayError ? (
          <div className="mt-4 flex gap-2 rounded-md border border-[color-mix(in_srgb,var(--danger)_28%,transparent)] bg-[var(--danger-muted)] px-3 py-2 text-sm font-semibold text-[var(--danger)]">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <p className="min-w-0 break-words leading-5">{displayError}</p>
          </div>
        ) : null}
      </div>
    </section>
  );
}

function Sidebar({
  activeView = 'security',
  loginLoading = false,
  onLogout,
  onSelectView,
}) {
  return (
    <aside
      className="absolute left-1.5 top-1.5 z-40 flex h-[calc(100%-12px)] w-[64px] flex-col gap-2 rounded-md border p-1 shadow-[0_12px_32px_color-mix(in_srgb,var(--graphite)_8%,transparent)] backdrop-blur-[10px]"
      style={{
        background: 'color-mix(in srgb, var(--cool-steel) 24%, var(--white-smoke) 76%)',
        borderColor: 'color-mix(in srgb, var(--border) 42%, transparent)',
      }}
    >
      <div className="min-h-0 flex-1 overflow-hidden rounded-md border bg-[#fafafa] shadow-[inset_0_0_0_1px_color-mix(in_srgb,var(--white-smoke)_34%,transparent),0_8px_20px_color-mix(in_srgb,var(--graphite)_7%,transparent)]" style={{ borderColor: 'color-mix(in srgb, var(--border) 82%, transparent)' }}>
        <nav className="flex h-full flex-col items-center gap-2 py-3">
          <SidebarButton
            active={activeView === 'security'}
            icon={ShieldCheck}
            label="Security"
            onClick={() => onSelectView?.('security')}
          />
          <SidebarButton
            active={activeView === 'resources'}
            icon={Database}
            label="Resources"
            onClick={() => onSelectView?.('resources')}
          />
          <div className="flex-1" />
          <SidebarButton
            danger
            disabled={loginLoading}
            icon={LogOut}
            label="Logout"
            onClick={onLogout}
          />
        </nav>
      </div>
    </aside>
  );
}

function SidebarButton({
  active = false,
  danger = false,
  disabled = false,
  icon: Icon,
  label,
  onClick,
}) {
  const colorClass = danger
    ? 'text-[var(--danger)] hover:bg-[var(--danger-muted)]'
    : active
      ? 'bg-[var(--accent-muted)] text-[var(--accent)]'
      : 'text-[#596268] hover:bg-[#edf0f0] hover:text-[var(--accent)]';

  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      aria-pressed={active}
      className={`grid h-11 w-11 place-items-center rounded-md transition-colors disabled:cursor-wait disabled:opacity-60 ${colorClass}`}
      onClick={onClick}
      disabled={disabled}
    >
      <Icon className="h-[23px] w-[23px]" strokeWidth={2.2} />
    </button>
  );
}

export default AppLayout;
