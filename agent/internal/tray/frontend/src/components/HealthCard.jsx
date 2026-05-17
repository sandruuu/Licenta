import { useState } from 'react';

const statusLabels = {
  good: 'OK',
  warning: 'Warn',
  critical: 'Fail',
  unavailable: 'N/A'
};

const dotClassByStatus = {
  good: 'bg-[var(--success)]',
  warning: 'bg-[var(--warning)]',
  critical: 'bg-[var(--danger)]',
  unavailable: 'bg-[var(--text-muted)]',
};
const badgeClass = 'shrink-0 rounded-full bg-[color-mix(in_srgb,var(--cool-steel)_22%,transparent)] px-2 py-1 text-[11px] font-extrabold text-[var(--text-secondary)]';

function HealthCard({ check }) {
  const [expanded, setExpanded] = useState(false);
  const details = Object.entries(check?.details || {}).filter(([, value]) => String(value || '').trim() !== '');
  const canExpand = details.length > 0;
  const status = check?.status || 'unavailable';

  return (
    <article
      className="cursor-default rounded-md border border-[var(--border-light)] bg-[var(--surface)] px-3 py-2.5"
      style={expanded ? { background: 'color-mix(in srgb, var(--surface-card) 72%, #ffffff)' } : undefined}
      onClick={() => canExpand && setExpanded(!expanded)}
    >
      <div className="flex items-center gap-2.5">
        <span className={`h-2 w-2 shrink-0 rounded-full ${dotClassByStatus[status] || dotClassByStatus.unavailable}`} />
        <div className="min-w-0 flex-1">
          <h3 className="m-0 overflow-hidden truncate text-[13px] font-extrabold text-[var(--text-primary)]">{check?.name || 'Check'}</h3>
          <p className="mb-0 mt-0.5 overflow-hidden truncate text-xs font-bold leading-snug text-[var(--text-secondary)]">{check?.description || 'Unavailable'}</p>
        </div>
        <span className={badgeClass}>{statusLabels[status] || status}</span>
      </div>
      {expanded && canExpand && (
        <div className="mt-2.5 border-t border-[var(--border-light)] pt-2.5">
          {details.map(([key, value]) => (
            <div className="grid grid-cols-[150px_minmax(0,1fr)] gap-2.5 py-1" key={key}>
              <span className="text-xs text-[var(--text-muted)]">{key}</span>
              <strong className="text-xs text-[var(--text-primary)] [overflow-wrap:anywhere]">{value}</strong>
            </div>
          ))}
        </div>
      )}
    </article>
  );
}

export default HealthCard;
