import { formatTime } from '../lib/dashboard';
import { EmptyState } from './Panels';

const sourceClass = 'shrink-0 rounded-full bg-[color-mix(in_srgb,var(--cool-steel)_22%,transparent)] px-2 py-1 text-[11px] font-extrabold text-[var(--text-secondary)]';

function AccessList({ events }) {
  if (!events.length) return <EmptyState title="No access denials recorded" />;

  return (
    <div className="flex flex-col gap-2">
      {events.map((event) => (
        <article className="min-w-0 rounded-md border border-[var(--border-light)] bg-[var(--surface)] p-3" key={event.id}>
          <div className="flex items-center justify-between gap-3">
            <strong className="text-[13px] font-extrabold text-[var(--text-primary)]">{event.decision || 'deny'}</strong>
            <span className="text-xs text-[var(--text-secondary)]">{formatTime(event.occurred_at)}</span>
          </div>
          <p className="mb-2.5 mt-2 text-xs font-bold leading-snug text-[var(--text-primary)]">{event.reason}</p>
          {event.source && <span className={sourceClass}>{event.source}</span>}
        </article>
      ))}
    </div>
  );
}

export default AccessList;
