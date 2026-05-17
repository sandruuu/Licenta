import { EmptyState } from './Panels';

const pillClass = 'shrink-0 rounded-full bg-[color-mix(in_srgb,var(--cool-steel)_22%,transparent)] px-2 py-1 text-[11px] font-extrabold text-[var(--text-secondary)]';

function SessionList({ sessions }) {
  if (!sessions.length) return <EmptyState title="No active resource sessions" />;

  return (
    <div className="flex flex-col gap-2">
      {sessions.map((session) => (
        <article className="flex min-w-0 items-center justify-between gap-3 rounded-md border border-[var(--border-light)] bg-[var(--surface)] p-3" key={session.id}>
          <div className="flex min-w-0 flex-col gap-1">
            <strong className="text-[13px] font-extrabold text-[var(--text-primary)]">{session.fqdn || session.resource_id || session.id}</strong>
            <span className="text-xs text-[var(--text-secondary)]">{session.protocol || 'tcp'}:{session.port || '-'}</span>
          </div>
          <span className={pillClass}>{session.state}</span>
        </article>
      ))}
    </div>
  );
}

export default SessionList;
