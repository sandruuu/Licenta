import {
  Minus,
  ShieldCheck,
  X,
} from 'lucide-react';
import {
  WindowMinimise,
} from '../../wailsjs/runtime/runtime';
import {
  formatStatusLabel,
  normalizeStatus,
} from '../lib/dashboard';
import SecurityView from './SecurityView';

function AppLayout({
  dashboard,
  dashboardError,
  dashboardLoading,
  onHide,
}) {
  return (
    <div className="flex h-full w-full flex-col bg-[var(--surface)]">
      <WindowTitleBar dashboard={dashboard} onClose={onHide} />

      <div className="relative min-h-0 flex-1">
        <Sidebar />
        <SecurityView
          dashboard={dashboard}
          error={dashboardError}
          loading={dashboardLoading}
        />
      </div>
    </div>
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
