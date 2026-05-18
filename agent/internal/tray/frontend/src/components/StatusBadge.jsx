import { formatStatusLabel } from '../lib/dashboard';

const toneStyles = {
  success: 'border-[color-mix(in_srgb,var(--success)_26%,transparent)] bg-[var(--success-muted)] text-[var(--success)]',
  warning: 'border-[color-mix(in_srgb,var(--warning)_30%,transparent)] bg-[var(--warning-muted)] text-[var(--warning)]',
  danger: 'border-[color-mix(in_srgb,var(--danger)_28%,transparent)] bg-[var(--danger-muted)] text-[var(--danger)]',
  info: 'border-[color-mix(in_srgb,var(--accent)_24%,transparent)] bg-[var(--accent-muted)] text-[var(--accent)]',
  neutral: 'border-[var(--border-light)] bg-[var(--surface-card)] text-[var(--text-secondary)]',
};

function StatusBadge({ value, tone = 'neutral', children }) {
  return (
    <span className={`inline-flex h-6 shrink-0 items-center rounded-md border px-2 text-[11px] font-extrabold leading-none ${toneStyles[tone] || toneStyles.neutral}`}>
      {children || formatStatusLabel(value)}
    </span>
  );
}

export default StatusBadge;
