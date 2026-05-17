import {
  FileText,
  Fingerprint,
  LayoutDashboard,
  Minimize2,
  Radio,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
} from 'lucide-react';
import {
  navigationItems,
  toneForConnection,
  toneForEnrollment,
  toneForSession,
  viewCopy,
} from '../lib/dashboard';

const navIconClass = 'h-5 w-5 shrink-0 transition-[width,height] duration-200 ease-out';
const navItemBase = 'flex h-11 w-full cursor-pointer items-center justify-center gap-0 overflow-hidden rounded-md bg-transparent text-sm font-extrabold transition-[color,background,gap,font-size] duration-200 ease-out group-hover:justify-start group-hover:gap-3';
const navItemState = {
  active: 'bg-[var(--accent-muted)] text-[15px] text-[var(--accent)]',
  inactive: 'text-[var(--text-secondary)] hover:bg-[var(--accent-muted)] hover:text-[15px] hover:text-[var(--accent)]',
};
const metricToneClass = {
  success: 'border-l-4 border-l-[var(--success)]',
  warning: 'border-l-4 border-l-[var(--warning)]',
  danger: 'border-l-4 border-l-[var(--danger)]',
  muted: 'border-l-4 border-l-[var(--text-muted)]',
};
const statusDotStyle = {
  success: { background: 'var(--success)', boxShadow: '0 0 0 4px var(--success-muted)' },
  warning: { background: 'var(--warning)', boxShadow: '0 0 0 4px var(--warning-muted)' },
  danger: { background: 'var(--danger)', boxShadow: '0 0 0 4px var(--danger-muted)' },
  default: { background: 'var(--text-muted)', boxShadow: '0 0 0 4px color-mix(in srgb, var(--text-muted) 14%, transparent)' },
};

const iconsByView = {
  overview: LayoutDashboard,
  enrollment: Fingerprint,
  security: ShieldCheck,
  resources: Server,
  sessions: Radio,
  access: FileText,
};

function AppLayout({
  activeView,
  dashboard,
  lastError,
  postureSummary,
  refreshing,
  onNavigate,
  onRefresh,
  onHide,
  banners,
  children,
}) {
  const statusTone = toneForConnection(dashboard.connection?.state);
  const sessionState = dashboard.user?.session_state || dashboard.status?.session_state;

  return (
    <div className="h-full w-full bg-[var(--surface)]">
      <Sidebar activeView={activeView} onNavigate={onNavigate} />

      <main className="ml-24 flex h-full min-w-0 flex-col overflow-hidden px-8 pb-6 pt-7 max-[980px]:px-5 max-[980px]:pb-5 max-[980px]:pt-6">
        <PageHeader
          activeView={activeView}
          statusTone={statusTone}
          refreshing={refreshing}
          onRefresh={onRefresh}
          onHide={onHide}
        />

        {lastError && (
          <div className="mt-3.5 shrink-0 rounded-md border border-[color-mix(in_srgb,var(--danger)_30%,transparent)] bg-[var(--danger-muted)] px-3 py-2.5 text-[13px] font-bold text-[var(--danger)]">
            {lastError}
          </div>
        )}

        {banners}

        <StatusStrip
          connection={dashboard.connection?.state}
          enrollment={dashboard.enrollment?.state || dashboard.status?.enrollment_state || 'UNKNOWN'}
          session={sessionState || 'missing'}
          posture={postureSummary}
        />

        {children}
      </main>
    </div>
  );
}

function Sidebar({ activeView, onNavigate }) {
  return (
    <aside
      className="group fixed left-1.5 top-1.5 z-40 flex h-[calc(100vh-12px)] w-[88px] flex-col gap-2 rounded-md border p-2 shadow-[0_12px_32px_color-mix(in_srgb,var(--graphite)_8%,transparent)] backdrop-blur-[10px] transition-[width] duration-300 ease-out hover:w-[292px]"
      style={{
        background: 'color-mix(in srgb, var(--cool-steel) 24%, var(--white-smoke) 76%)',
        borderColor: 'color-mix(in srgb, var(--border) 42%, transparent)',
      }}
    >
      <div className="flex h-20 shrink-0 items-center justify-center gap-0 rounded-md border bg-[#fafafa] px-3 shadow-[inset_0_0_0_1px_color-mix(in_srgb,var(--white-smoke)_34%,transparent),0_8px_20px_color-mix(in_srgb,var(--graphite)_7%,transparent)] transition-[gap,justify-content] duration-200 ease-out group-hover:justify-start group-hover:gap-3" style={{ borderColor: 'color-mix(in srgb, var(--border) 82%, transparent)' }}>
        <span className="grid h-10 w-10 shrink-0 place-items-center text-[var(--accent)]">
          <Shield size={28} />
        </span>
        <div className="w-0 min-w-0 overflow-hidden whitespace-nowrap opacity-0 transition-[width,opacity] duration-200 group-hover:w-auto group-hover:opacity-100">
          <h2 className="m-0 text-lg font-extrabold leading-none text-[var(--text-primary)]"><span className="text-[var(--accent)]">TRUST</span>CLOUD</h2>
          <p className="mb-0 mt-1 text-[11px] font-extrabold text-[var(--text-muted)]">Agent</p>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-hidden rounded-md border bg-[#fafafa] shadow-[inset_0_0_0_1px_color-mix(in_srgb,var(--white-smoke)_34%,transparent),0_8px_20px_color-mix(in_srgb,var(--graphite)_7%,transparent)]" style={{ borderColor: 'color-mix(in srgb, var(--border) 82%, transparent)' }}>
        <nav className="flex h-full flex-col gap-1 overflow-y-auto px-3 py-4">
          {navigationItems.map(({ id, label }) => {
            const Icon = iconsByView[id];
            const active = activeView === id;
            return (
              <button
                key={id}
                type="button"
                title={label}
                className={`${navItemBase} ${active ? navItemState.active : navItemState.inactive}`}
                onClick={() => onNavigate(id)}
              >
                <Icon className={navIconClass} />
                <span className="w-0 min-w-0 overflow-hidden whitespace-nowrap opacity-0 transition-[width,opacity] duration-200 group-hover:w-auto group-hover:opacity-100">{label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </aside>
  );
}

function PageHeader({ activeView, statusTone, refreshing, onRefresh, onHide }) {
  const copy = viewCopy[activeView] || viewCopy.overview;

  return (
    <header className="flex shrink-0 items-start justify-between gap-[18px] border-b border-[var(--border)] pb-4">
      <div className="flex min-w-0 items-start gap-3">
        <span className="mt-2 h-3 w-3 shrink-0 rounded-full" style={statusDotStyle[statusTone] || statusDotStyle.default} />
        <div>
          <h1 className="m-0 text-[22px] font-extrabold leading-tight text-[var(--text-primary)]">{copy.title}</h1>
          <p className="mb-0 mt-1 max-w-[720px] overflow-hidden truncate text-sm font-bold leading-snug text-[var(--text-secondary)] max-[980px]:max-w-[520px]">{copy.subtitle}</p>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <button className="grid h-9 w-9 cursor-pointer place-items-center rounded-md border border-[var(--border)] bg-[var(--surface-card)] text-[var(--text-secondary)] transition-colors duration-200 hover:border-[var(--accent)] hover:bg-[var(--surface-hover)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-55" onClick={onRefresh} disabled={refreshing} title="Refresh">
          <RefreshCw className={refreshing ? 'animate-spin' : ''} size={17} />
        </button>
        <button className="grid h-9 w-9 cursor-pointer place-items-center rounded-md border border-[var(--border)] bg-[var(--surface-card)] text-[var(--text-secondary)] transition-colors duration-200 hover:border-[var(--accent)] hover:bg-[var(--surface-hover)] hover:text-[var(--accent)]" onClick={onHide} title="Hide">
          <Minimize2 size={17} />
        </button>
      </div>
    </header>
  );
}

function StatusStrip({ connection, enrollment, session, posture }) {
  return (
    <section className="grid shrink-0 grid-cols-4 gap-3 pt-4 max-[980px]:grid-cols-2">
      <Metric label="Agent" value={connection} tone={toneForConnection(connection)} />
      <Metric label="Enrollment" value={enrollment} tone={toneForEnrollment(enrollment)} />
      <Metric label="Session" value={session} tone={toneForSession(session)} />
      <Metric label="Posture" value={posture.label} tone={posture.tone} />
    </section>
  );
}

function Metric({ label, value, tone }) {
  return (
    <div className={`flex min-h-[78px] min-w-0 flex-col justify-center gap-2 rounded-md border border-[var(--border)] bg-[var(--surface-card)] px-4 py-3.5 transition-colors duration-200 hover:border-[var(--accent)] ${metricToneClass[tone] || metricToneClass.muted}`}>
      <span className="text-[11px] font-extrabold uppercase text-[var(--text-muted)]">{label}</span>
      <strong className="overflow-hidden truncate text-[21px] font-extrabold leading-tight text-[var(--text-primary)]">{value || 'Unknown'}</strong>
    </div>
  );
}

export default AppLayout;
