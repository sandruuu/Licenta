import {
  AlertCircle,
  Bell,
  CheckCircle2,
  Database,
  LaptopMinimalCheck,
  LogOut,
  Minus,
  XCircle,
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
import logoMark from '../assets/trust-agent-mark.svg';
import SecurityView from './SecurityView';

function AppLayout({
  dashboard,
  dashboardError,
  dashboardLoading,
  enrollmentError,
  enrollmentLoading,
  loginError,
  loginLoading,
  logoutLoading,
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
  const stepUpURL = userSession.step_up_url || '';
  const sessionMessageAt = notificationTimestamp(userSession.message_at || userSession.messageAt);
  const stepUpMessage = stepUpURL ? formatStepUpToastMessage(userSession.message) : '';
  const sessionMessage = authenticated && !stepUpURL && isDisplayableSessionMessage(userSession.message)
    ? userSession.message
    : '';
  const sessionError = authenticated ? (loginError || userSession.last_error || dashboardError) : '';
  const [notifications, setNotifications] = useState([]);
  const [hasUnreadNotifications, setHasUnreadNotifications] = useState(false);
  const [activeView, setActiveView] = useState('security');
  const notificationIdsRef = useRef(new Set());
  const activeViewRef = useRef(activeView);
  const openedStepUpURLRef = useRef('');

  useEffect(() => {
    if (authenticated) {
      return;
    }
    setNotifications([]);
    setHasUnreadNotifications(false);
    notificationIdsRef.current.clear();
    openedStepUpURLRef.current = '';
  }, [authenticated]);

  useEffect(() => {
    activeViewRef.current = activeView;
    if (activeView === 'notifications') {
      setHasUnreadNotifications(false);
    }
  }, [activeView, notifications.length]);

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

  useEffect(() => {
    if (!stepUpURL || !stepUpMessage) {
      return;
    }
    const notification = {
      id: `step-up:${stepUpURL}:${sessionMessageAt || ''}`,
      title: 'Security verification required',
      message: stepUpMessage,
      variant: 'warning',
      createdAt: sessionMessageAt,
    };
    enqueueNotification(setNotifications, setHasUnreadNotifications, notificationIdsRef, activeViewRef, notification);
  }, [sessionMessageAt, stepUpMessage, stepUpURL]);

  useEffect(() => {
    if (!sessionMessage) {
      return;
    }
    const variant = sessionToastVariant(sessionMessage);
    const notification = {
      id: `session:${sessionMessage}:${sessionMessageAt || ''}`,
      title: sessionToastTitle(sessionMessage, variant),
      message: sessionMessage,
      variant,
      createdAt: sessionMessageAt,
    };
    enqueueNotification(setNotifications, setHasUnreadNotifications, notificationIdsRef, activeViewRef, notification);
  }, [sessionMessage, sessionMessageAt]);

  useEffect(() => {
    if (!sessionError) {
      return;
    }
    const notification = {
      id: `error:${sessionError}`,
      title: toastErrorTitle(sessionError),
      message: sessionError,
      variant: 'danger',
    };
    enqueueNotification(setNotifications, setHasUnreadNotifications, notificationIdsRef, activeViewRef, notification);
  }, [sessionError]);

  return (
    <div className="relative flex h-full w-full flex-col bg-[var(--surface)]">
      <WindowTitleBar onClose={onHide} />

      <div className="relative min-h-0 flex-1">
        {waitingForDashboard ? (
          <AgentLoadingScreen />
        ) : enrolled && authenticated ? (
          <>
            <Sidebar
              activeView={activeView}
              hasUnreadNotifications={hasUnreadNotifications}
              logoutLoading={logoutLoading}
              onLogout={onLogout}
              onSelectView={setActiveView}
            />
            <EnrolledScreen
              activeView={activeView}
              dashboard={dashboard}
              loading={dashboardLoading}
              notifications={notifications}
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
  loading = false,
  notifications = [],
}) {
  return (
    <main className="h-full min-w-0 overflow-hidden bg-[#f9faf9] text-[var(--text-primary)]">
      {activeView === 'notifications' ? (
        <NotificationsView notifications={notifications} />
      ) : activeView === 'resources' ? (
        <ResourcesView dashboard={dashboard} />
      ) : (
        <SecurityView dashboard={dashboard} error="" loading={loading} />
      )}
    </main>
  );
}

function enqueueNotification(
  setNotifications,
  setHasUnreadNotifications,
  notificationIdsRef,
  activeViewRef,
  notification,
) {
  const notificationID = String(notification.id || '').trim();
  if (!notificationID || notificationIdsRef.current.has(notificationID)) {
    return;
  }
  notificationIdsRef.current.add(notificationID);
  setNotifications((current) => [
    ...current,
    {
      id: notificationID,
      title: notification.title,
      message: notification.message,
      variant: notification.variant,
      createdAt: notificationTimestamp(notification.createdAt) || Date.now(),
    },
  ]);
  if (activeViewRef.current !== 'notifications') {
    setHasUnreadNotifications(true);
  }
}

function formatStepUpToastMessage(message) {
  const trimmed = String(message || '').trim();
  if (!trimmed) {
    return 'Additional security verification is required to access this resource.';
  }
  return trimmed.replace(/^Additional verification is required/i, 'Additional security verification is required');
}

function isDisplayableSessionMessage(message) {
  const text = String(message || '').trim();
  if (!text || text === 'Authenticated') {
    return false;
  }
  const normalized = text.toLowerCase();
  if (normalized.includes('catalog')) {
    return false;
  }
  return true;
}

function sessionToastVariant(message) {
  const text = String(message || '').trim().toLowerCase();
  if (
    text.startsWith('access granted to ') ||
    text.startsWith('security verification completed for ') ||
    text.includes('restored') ||
    text.includes('available')
  ) {
    return 'success';
  }
  if (
    text.includes('denied') ||
    text.includes('revoked') ||
    text.includes('expired') ||
    text.includes('canceled') ||
    text.includes('cancelled') ||
    text.includes('failed') ||
    text.includes('paused')
  ) {
    return 'danger';
  }
  return 'warning';
}

function sessionToastTitle(message, variant) {
  const text = String(message || '').trim();
  if (/^Access granted to /i.test(text)) {
    return 'Access granted';
  }
  if (/^Security verification completed for /i.test(text)) {
    return 'Security verification completed';
  }
  if (variant === 'danger') {
    return 'Security notification';
  }
  return 'TrustAgent';
}

function toastErrorTitle(message) {
  const text = String(message || '').trim();
  if (/^(Security verification|Access to )/i.test(text)) {
    return 'Security verification failed';
  }
  return 'TrustAgent';
}

function toastTone(variant = 'warning') {
  if (variant === 'success') {
    return {
      color: '#2f7d32',
      background: 'color-mix(in srgb, #dbeedc 72%, white)',
      border: 'color-mix(in srgb, #2f7d32 34%, transparent)',
      iconBackground: 'color-mix(in srgb, #2f7d32 12%, transparent)',
      icon: CheckCircle2,
    };
  }
  if (variant === 'danger') {
    return {
      color: '#b42318',
      background: 'color-mix(in srgb, #ffd9d5 68%, white)',
      border: 'color-mix(in srgb, #b42318 34%, transparent)',
      iconBackground: 'color-mix(in srgb, #b42318 12%, transparent)',
      icon: XCircle,
    };
  }
  return {
    color: '#9a6500',
    background: 'color-mix(in srgb, #fff1c7 72%, white)',
    border: 'color-mix(in srgb, #9a6500 34%, transparent)',
    iconBackground: 'color-mix(in srgb, #9a6500 12%, transparent)',
    icon: AlertCircle,
  };
}

function NotificationsView({ notifications = [] }) {
  return (
    <section className="ml-[54px] flex h-full min-h-0 flex-col overflow-hidden bg-[#f9faf9] text-[#202427]">
      <header className="mx-8 shrink-0 border-b border-[#e3e4e5] py-5">
        <div className="flex min-w-0 items-center gap-3">
          <div className="grid h-12 w-12 shrink-0 place-items-center text-[#334045]">
            <Bell className="h-10 w-10" strokeWidth={2.1} />
          </div>
          <div className="min-w-0">
            <h1 className="truncate text-2xl font-medium leading-none text-[#111820]">Notifications</h1>
            <p className="mt-1 truncate text-xs font-semibold text-[#6b737a]">
              Current session activity.
            </p>
          </div>
        </div>
      </header>

      <div className="min-h-0 flex-1 overflow-auto px-8 pb-6 pt-4">
        {notifications.length > 0 ? (
          <div className="flex flex-col gap-3">
            {notifications.map((notification) => (
              <NotificationCard key={notification.id} notification={notification} />
            ))}
          </div>
        ) : (
          <div className="rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-4 py-4 text-sm font-medium text-[var(--text-secondary)]">
            No notifications for this session.
          </div>
        )}
      </div>
    </section>
  );
}

function NotificationCard({ notification }) {
  const tone = toastTone(notification.variant);
  const Icon = tone.icon;
  return (
    <article
      className="min-w-0 rounded-md border border-[var(--toast-border)] bg-[var(--toast-bg)] px-4 py-3 text-[var(--toast-color)] shadow-[0_10px_24px_color-mix(in_srgb,var(--graphite)_10%,transparent)]"
      style={{
        '--toast-bg': tone.background,
        '--toast-border': tone.border,
        '--toast-color': tone.color,
      }}
    >
      <div className="flex min-w-0 items-start gap-3">
        <Icon className="mt-[2px] h-5 w-5 shrink-0" strokeWidth={2.4} />
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 items-start justify-between gap-3">
            <h3 className="min-w-0 text-sm font-extrabold leading-5 text-[#1f262b]">
              {notification.title}
            </h3>
            <time className="shrink-0 text-[11px] font-bold leading-5 text-[color-mix(in_srgb,var(--toast-color)_74%,white)]">
              {formatNotificationTime(notification.createdAt)}
            </time>
          </div>
          <p className="mt-1 text-sm font-semibold leading-5 text-[var(--toast-color)]">
            <ToastMessage message={notification.message} />
          </p>
        </div>
      </div>
    </article>
  );
}

function formatNotificationTime(value) {
  const timestamp = notificationTimestamp(value);
  if (!timestamp) {
    return '';
  }
  return new Date(timestamp).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function notificationTimestamp(value) {
  if (!value) {
    return 0;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) && value > 0 ? value : 0;
  }
  const parsed = new Date(value).getTime();
  return Number.isNaN(parsed) || parsed <= 0 ? 0 : parsed;
}

function ResourcesView({ dashboard }) {
  const catalog = dashboard?.catalog || {};
  const resources = Array.isArray(catalog.resources) ? catalog.resources : [];

  return (
    <section className="ml-[54px] flex h-full min-h-0 flex-col overflow-hidden bg-[#f9faf9] text-[#202427]">
      <header className="mx-8 shrink-0 border-b border-[#e3e4e5] py-5">
        <div className="flex min-w-0 items-center gap-3">
          <div className="grid h-12 w-12 shrink-0 place-items-center text-[#334045]">
            <Database className="h-10 w-10" strokeWidth={2.1} />
          </div>
          <div className="min-w-0">
            <h1 className="truncate text-2xl font-medium leading-none text-[#111820]">Your resources</h1>
            <p className="mt-1 truncate text-xs font-semibold text-[#6b737a]">
              Resources available for access.
            </p>
          </div>
        </div>
      </header>

      <div className="min-h-0 flex-1 overflow-auto px-8 pb-6 pt-4">
        <div className="grid grid-cols-2 gap-3">
          {resources.length > 0 ? (
            resources.map((resource) => (
              <article
                key={resource.resource_id || resource.fqdn}
                className="min-h-[74px] rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-4 py-3 shadow-[0_8px_16px_rgba(42,42,42,0.12)] transition-[border-color,background-color,box-shadow] duration-150 hover:border-[var(--accent)] hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.14)]"
              >
                <div className="flex min-w-0 items-start justify-between gap-3">
                  <p className="min-w-0 truncate text-base font-semibold leading-5 text-[#1f262b]">
                    {formatResourceName(resource)}
                  </p>
                  <span className="shrink-0 rounded-[4px] border border-[rgba(44,97,100,0.26)] bg-white/70 px-2 py-[2px] text-[10px] font-extrabold uppercase tracking-normal text-[var(--accent)]">
                    {formatResourceType(resource)}
                  </span>
                </div>
                <p
                  className="mt-2 select-all truncate rounded-[4px] bg-white/60 px-2 py-1 font-mono text-xs font-semibold leading-5 text-[#455157]"
                  title={formatResourceAccessAddress(resource)}
                >
                  {formatResourceAccessAddress(resource)}
                </p>
              </article>
            ))
          ) : (
            <div className="rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-4 py-4 text-sm font-medium text-[var(--text-secondary)]">
              No resources available.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function formatResourceName(resource) {
  const displayName = String(resource?.display_name || '').trim();
  const resourceID = String(resource?.resource_id || '').trim();
  if (displayName && !stringsEqual(displayName, resourceID)) {
    return displayName;
  }
  return String(resource?.fqdn || 'Resource').trim();
}

function formatResourceType(resource) {
  const type = String(resource?.type || resource?.access_mode || resource?.protocol || '').trim();
  if (!type) {
    return 'TYPE';
  }
  if (type.toLowerCase() === 'https' || type.toLowerCase() === 'http') {
    return 'WEB';
  }
  return type.toUpperCase();
}

function formatResourceAccessAddress(resource) {
  const host = String(resource?.fqdn || '').trim();
  const port = resource?.port ? String(resource.port).trim() : '';
  if (!host) {
    return 'Resource access unavailable';
  }
  const type = String(resource?.type || resource?.access_mode || resource?.protocol || '').trim().toLowerCase();
  const protocol = String(resource?.protocol || '').trim().toLowerCase();
  const address = port ? `${host}:${port}` : host;
  if (type === 'web' || protocol === 'http' || protocol === 'https') {
    return `http://${address}`;
  }
  return address;
}

function stringsEqual(left, right) {
  return String(left || '').trim().toLowerCase() === String(right || '').trim().toLowerCase();
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
    <section className="grid h-full place-items-center bg-[#f2f2f0] px-8 py-8 text-[var(--text-primary)]">
      <div className="flex w-full max-w-[360px] -translate-y-4 flex-col items-center text-center">
        <BrandMark className="h-[68px] w-[68px]" />
        <h1 className="mt-3 text-2xl font-extrabold leading-none">
          <BrandWordmark />
        </h1>
        <ScreenStatusMessage error={displayError} message={message} />

        <button
          type="button"
          className="mt-8 inline-flex h-9 min-w-[190px] items-center justify-center rounded-full bg-[var(--accent)] px-7 text-sm font-bold tracking-normal text-white shadow-[0_8px_18px_color-mix(in_srgb,var(--accent)_22%,transparent)] transition-colors hover:bg-[color-mix(in_srgb,var(--accent)_86%,black)] disabled:cursor-wait disabled:opacity-70"
          onClick={onStartLogin}
          disabled={authenticating}
        >
          {authenticating ? 'STARTING...' : 'SIGN IN'}
        </button>
      </div>
    </section>
  );
}

function WindowTitleBar({ onClose }) {
  return (
    <header
      className="flex h-10 shrink-0 items-center justify-between border-b text-[#111111]"
      style={{
        background: 'color-mix(in srgb, var(--cool-steel) 24%, var(--white-smoke) 76%)',
        borderColor: 'color-mix(in srgb, var(--border) 42%, transparent)',
      }}
    >
      <div
        className="flex h-full min-w-0 flex-1 items-center gap-2 px-3"
        style={{ '--wails-draggable': 'drag' }}
      >
        <div className="min-w-0 whitespace-nowrap">
          <h2 className="m-0 flex min-w-0 items-center gap-2 text-xl font-extrabold leading-[1.35]">
            <BrandMark className="h-7 w-7 shrink-0" />
            <BrandWordmark className="whitespace-nowrap leading-[1.35]" />
          </h2>
        </div>
      </div>
      <div className="flex h-full shrink-0 items-center">
        <button
          type="button"
          className="grid h-full w-12 cursor-pointer place-items-center bg-transparent text-[#111111] transition-colors duration-150 hover:bg-[#efe9e7]"
          onClick={() => WindowMinimise()}
          title="Minimize"
        >
          <Minus className="translate-y-[4px]" size={16} strokeWidth={1.9} />
        </button>
        <button
          type="button"
          className="grid h-full w-12 cursor-pointer place-items-center bg-transparent text-[#111111] transition-colors duration-150 hover:bg-[#c42b1c] hover:text-white"
          onClick={onClose}
          title="Close"
        >
          <X size={18} strokeWidth={1.8} />
        </button>
      </div>
    </header>
  );
}

function BrandMark({ className = '' }) {
  return (
    <img
      src={logoMark}
      alt=""
      aria-hidden="true"
      className={`object-contain ${className}`}
    />
  );
}

function BrandWordmark({ className = '' }) {
  return (
    <span className={`inline-block text-[var(--text-primary)] ${className}`}>
      <span className="text-[var(--accent)]">TRUST</span>Agent
    </span>
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

function ScreenStatusMessage({ error = '', message = '' }) {
  if (error) {
    return (
      <div className="mt-4 flex w-full max-w-[320px] items-start justify-center gap-2 text-left text-sm font-medium leading-[18px] text-[var(--danger)]">
        <AlertCircle className="mt-px h-[18px] w-[18px] shrink-0" strokeWidth={2.2} />
        <p className="min-w-0 break-words text-[var(--danger)]">{error}</p>
      </div>
    );
  }
  return (
    <p className="mt-4 text-sm font-semibold leading-5 text-[#747b80]">{message}</p>
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
    <section className="grid h-full place-items-center bg-[#f2f2f0] px-8 py-8 text-[var(--text-primary)]">
      <div className="flex w-full max-w-[360px] -translate-y-4 flex-col items-center text-center">
        <BrandMark className="h-[68px] w-[68px]" />
        <h1 className="mt-3 text-2xl font-extrabold leading-none">
          <BrandWordmark />
        </h1>
        <ScreenStatusMessage
          error={displayError}
          message="Device enrollment is required before signing in."
        />

        <button
          type="button"
          className="mt-8 inline-flex h-9 min-w-[190px] items-center justify-center rounded-full bg-[var(--accent)] px-7 text-sm font-bold tracking-normal text-white shadow-[0_8px_18px_color-mix(in_srgb,var(--accent)_22%,transparent)] transition-colors hover:bg-[color-mix(in_srgb,var(--accent)_86%,black)] disabled:cursor-wait disabled:opacity-70"
          onClick={onStartEnrollment}
          disabled={enrollmentLoading}
        >
          {enrollmentLoading ? 'STARTING...' : 'ENROLL'}
        </button>
      </div>
    </section>
  );
}

function ToastMessage({ message = '' }) {
  const text = String(message || '').trim();
  const stepUpMatch = text.match(/^(Additional security verification is required to access )(.+?)(\.)$/i);
  if (stepUpMatch) {
    return (
      <>
        {stepUpMatch[1]}
        <ToastResourceName>{stepUpMatch[2]}</ToastResourceName>
        {stepUpMatch[3]}
      </>
    );
  }
  const successMatch = text.match(/^(Access granted to )(.+?)(\.)$/i);
  if (successMatch) {
    return (
      <>
        {successMatch[1]}
        <ToastResourceName>{successMatch[2]}</ToastResourceName>
        {successMatch[3]}
      </>
    );
  }
  const verificationCompletedMatch = text.match(/^(Security verification completed for )(.+?)(\.)$/i);
  if (verificationCompletedMatch) {
    return (
      <>
        {verificationCompletedMatch[1]}
        <ToastResourceName>{verificationCompletedMatch[2]}</ToastResourceName>
        {verificationCompletedMatch[3]}
      </>
    );
  }
  const verificationMatch = text.match(/^(Security verification (?:expired|was canceled|was rejected|was not completed) for )(.+?)(\. Additional security verification is required to access )(.+?)(\.)$/i);
  if (verificationMatch) {
    return (
      <>
        {verificationMatch[1]}
        <ToastResourceName>{verificationMatch[2]}</ToastResourceName>
        {verificationMatch[3]}
        <ToastResourceName>{verificationMatch[4]}</ToastResourceName>
        {verificationMatch[5]}
      </>
    );
  }
  const deniedMatch = text.match(/^(Access to )(.+?)( was denied\.?\s?.*)$/i);
  if (deniedMatch) {
    return (
      <>
        {deniedMatch[1]}
        <ToastResourceName>{deniedMatch[2]}</ToastResourceName>
        {deniedMatch[3]}
      </>
    );
  }
  return text;
}

function ToastResourceName({ children }) {
  return (
    <strong className="font-extrabold text-[#1f262b]">{children}</strong>
  );
}

function Sidebar({
  activeView = 'security',
  hasUnreadNotifications = false,
  logoutLoading = false,
  onLogout,
  onSelectView,
}) {
  return (
    <aside
      className="absolute left-1.5 top-1.5 z-40 flex h-[calc(100%-12px)] w-[48px] flex-col gap-2 rounded-md border px-0.5 py-1 shadow-[0_12px_32px_color-mix(in_srgb,var(--graphite)_8%,transparent)] backdrop-blur-[10px]"
      style={{
        background: 'color-mix(in srgb, var(--cool-steel) 24%, var(--white-smoke) 76%)',
        borderColor: 'color-mix(in srgb, var(--border) 42%, transparent)',
      }}
    >
      <div className="mx-auto min-h-0 w-[38px] flex-1 overflow-hidden rounded-md border bg-[#fafafa] shadow-[inset_0_0_0_1px_color-mix(in_srgb,var(--white-smoke)_34%,transparent),0_8px_20px_color-mix(in_srgb,var(--graphite)_7%,transparent)]" style={{ borderColor: 'color-mix(in srgb, var(--border) 82%, transparent)' }}>
        <nav className="relative flex h-full w-full flex-col items-center py-3">
          <div className="absolute left-1/2 top-1/2 flex w-full -translate-x-1/2 -translate-y-1/2 flex-col items-center gap-3">
            <SidebarButton
              active={activeView === 'security'}
              icon={LaptopMinimalCheck}
              label="Security"
              onClick={() => onSelectView?.('security')}
            />
            <SidebarButton
              active={activeView === 'resources'}
              icon={Database}
              label="Resources"
              onClick={() => onSelectView?.('resources')}
            />
            <SidebarButton
              active={activeView === 'notifications'}
              icon={Bell}
              label="Notifications"
              showBadge={hasUnreadNotifications}
              onClick={() => onSelectView?.('notifications')}
            />
          </div>
          <div className="flex-1" />
          <SidebarButton
            danger
            disabled={logoutLoading}
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
  showBadge = false,
}) {
  const colorClass = danger
    ? 'text-[var(--danger)] hover:text-[color-mix(in_srgb,var(--danger)_78%,black)]'
    : active
      ? 'text-[var(--accent)]'
      : 'text-[#596268] hover:text-[var(--accent)]';
  const iconClass = active ? 'h-6 w-6' : 'h-5 w-5';
  const strokeWidth = active ? 2.6 : 2.2;

  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      aria-pressed={active}
      className={`relative grid h-9 w-9 place-items-center bg-transparent transition-colors disabled:cursor-wait disabled:opacity-60 ${colorClass}`}
      onClick={onClick}
      disabled={disabled}
    >
      <Icon className={iconClass} strokeWidth={strokeWidth} />
      {showBadge ? (
        <span className="notification-badge-pulse absolute right-[6px] top-[6px] h-2.5 w-2.5 rounded-full bg-[var(--danger)] ring-2 ring-white" />
      ) : null}
    </button>
  );
}

export default AppLayout;
