import {
  AlertCircle,
  ExternalLink,
  LogIn,
  LogOut,
  Minus,
  ShieldCheck,
  X,
} from 'lucide-react';
import {
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

  return (
    <div className="flex h-full w-full flex-col bg-[var(--surface)]">
      <WindowTitleBar dashboard={dashboard} onClose={onHide} />

      <div className="relative min-h-0 flex-1">
        {waitingForDashboard ? (
          <AgentLoadingScreen />
        ) : enrolled ? (
          <>
            <Sidebar />
            <EnrolledScreen
              dashboard={dashboard}
              error={dashboardError}
              loading={dashboardLoading}
              loginError={loginError}
              loginLoading={loginLoading}
              onLogout={onLogout}
              onStartLogin={onStartLogin}
            />
          </>
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
  dashboard,
  error = '',
  loading = false,
  loginError = '',
  loginLoading = false,
  onLogout,
  onStartLogin,
}) {
  const userSession = dashboard?.user_session || {};
  const catalog = dashboard?.catalog || {};
  const state = String(userSession.state || 'SIGNED_OUT').toUpperCase();
  const authenticated = state === 'AUTHENTICATED';
  const authenticating = state === 'AUTHENTICATING' || loginLoading;
  const displayError = loginError || userSession.last_error || error;
  return (
    <main className="ml-[78px] flex h-full min-w-0 flex-col overflow-auto bg-[#f9faf9] px-5 py-4 text-[var(--text-primary)]">
      <section className="mb-4 rounded-md border border-[color-mix(in_srgb,var(--border)_72%,transparent)] bg-white px-4 py-3 shadow-[0_8px_22px_color-mix(in_srgb,var(--graphite)_7%,transparent)]">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <h1 className="m-0 text-base font-semibold leading-6">
              {authenticated ? `Authenticated as ${userSession.display_name || userSession.email || 'user'}` : 'Device enrolled'}
            </h1>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              {authenticated ? 'Resources are available for this Windows session.' : 'Sign in to load your resource catalog.'}
            </p>
          </div>
          {authenticated ? (
            <button
              type="button"
              className="inline-flex h-10 shrink-0 items-center gap-2 rounded-md border border-[var(--border)] bg-white px-3 text-sm font-semibold text-[var(--text-primary)] hover:bg-[#f5f7f7] disabled:cursor-wait disabled:opacity-70"
              onClick={onLogout}
              disabled={loginLoading}
            >
              <LogOut className="h-4 w-4" />
              Logout
            </button>
          ) : (
            <button
              type="button"
              className="inline-flex h-10 shrink-0 items-center gap-2 rounded-md bg-[var(--accent)] px-3 text-sm font-semibold text-white hover:bg-[color-mix(in_srgb,var(--accent)_86%,black)] disabled:cursor-wait disabled:opacity-70"
              onClick={onStartLogin}
              disabled={authenticating}
            >
              <LogIn className="h-4 w-4" />
              {authenticating ? 'Starting...' : 'Sign in'}
            </button>
          )}
        </div>
        {displayError ? (
          <div className="mt-3 flex gap-2 rounded-md border border-[color-mix(in_srgb,var(--danger)_28%,transparent)] bg-[var(--danger-muted)] px-3 py-2 text-sm font-semibold text-[var(--danger)]">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <p className="min-w-0 break-words leading-5">{displayError}</p>
          </div>
        ) : null}
      </section>

      {authenticated ? (
        <section className="mb-4">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-normal text-[var(--text-secondary)]">Resources</h2>
          <div className="grid gap-2">
            {(catalog.resources || []).length > 0 ? (
              catalog.resources.map((resource) => (
                <div key={resource.resource_id || resource.fqdn} className="rounded-md border border-[var(--border)] bg-white px-3 py-2">
                  <div className="text-sm font-semibold">{resource.display_name || resource.resource_id || resource.fqdn}</div>
                  <div className="mt-0.5 text-xs text-[var(--text-secondary)]">{resource.fqdn || resource.resource_id}</div>
                </div>
              ))
            ) : (
              <div className="rounded-md border border-[var(--border)] bg-white px-3 py-3 text-sm text-[var(--text-secondary)]">
                No resources available.
              </div>
            )}
          </div>
        </section>
      ) : null}

      <SecurityView dashboard={dashboard} error="" loading={loading} />
    </main>
  );
}

function WindowTitleBar({ dashboard, onClose }) {
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
      <div className="flex h-full shrink-0 items-stretch">
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
          className="mt-5 inline-flex h-10 items-center gap-2 rounded-md bg-[var(--accent)] px-4 text-sm font-semibold text-white transition-colors hover:bg-[color-mix(in_srgb,var(--accent)_86%,black)] disabled:cursor-wait disabled:opacity-70"
          onClick={onStartEnrollment}
          disabled={enrollmentLoading}
        >
          <ExternalLink className="h-4 w-4" />
          {enrollmentLoading ? 'Starting...' : 'Enroll device'}
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

function Sidebar() {
  return (
    <aside
      className="absolute left-1.5 top-1.5 z-40 flex h-[calc(100%-12px)] w-[64px] flex-col gap-2 rounded-md border p-1 shadow-[0_12px_32px_color-mix(in_srgb,var(--graphite)_8%,transparent)] backdrop-blur-[10px]"
      style={{
        background: 'color-mix(in srgb, var(--cool-steel) 24%, var(--white-smoke) 76%)',
        borderColor: 'color-mix(in srgb, var(--border) 42%, transparent)',
      }}
    >
      <div className="min-h-0 flex-1 overflow-hidden rounded-md border bg-[#fafafa] shadow-[inset_0_0_0_1px_color-mix(in_srgb,var(--white-smoke)_34%,transparent),0_8px_20px_color-mix(in_srgb,var(--graphite)_7%,transparent)]" style={{ borderColor: 'color-mix(in srgb, var(--border) 82%, transparent)' }}>
        <nav className="flex h-full flex-col items-center justify-center">
          <button
            type="button"
            title="Security"
            className="grid h-11 w-11 cursor-default place-items-center rounded-md bg-transparent text-[var(--accent)]"
          >
            <ShieldCheck className="h-[23px] w-[23px]" />
          </button>
        </nav>
      </div>
    </aside>
  );
}

export default AppLayout;
