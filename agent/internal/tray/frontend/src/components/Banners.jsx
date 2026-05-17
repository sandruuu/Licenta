function ServiceInstallBanner() {
  return (
    <section className="mt-3.5 flex shrink-0 items-center justify-start gap-4 rounded-md border border-[color-mix(in_srgb,var(--info)_28%,transparent)] bg-[var(--info-muted)] px-4 py-3.5">
      <div>
        <h2 className="m-0 text-sm font-extrabold text-[var(--text-primary)]">Agent service unavailable</h2>
        <p className="mb-0 mt-1 text-[13px] font-bold leading-snug text-[var(--text-secondary)]">The LocalSystem service must be installed and running before dashboard data and enrollment are available.</p>
      </div>
    </section>
  );
}

function EnrollmentBanner({ state, enrolling, onStartEnrollment, canStart, notice, lastError }) {
  const failed = state === 'FAILED';
  const pending = state === 'PENDING';
  const message = failed
    ? 'Device enrollment did not complete. Start the enrollment flow again from this interface.'
    : pending
      ? 'Device enrollment is not complete yet. Continue the enrollment flow from this interface.'
      : 'This device is not enrolled. Start enrollment from this interface.';
  const buttonLabel = failed ? 'Retry enrollment' : pending ? 'Continue enrollment' : 'Start enrollment';

  return (
    <section className={`mt-3.5 flex shrink-0 items-center justify-start gap-4 rounded-md border px-4 py-3.5 ${failed ? 'border-[color-mix(in_srgb,var(--danger)_30%,transparent)] bg-[var(--danger-muted)]' : 'border-[color-mix(in_srgb,var(--warning)_32%,transparent)] bg-[var(--warning-muted)]'}`}>
      <div>
        <h2 className="m-0 text-sm font-extrabold text-[var(--text-primary)]">{failed ? 'Device enrollment failed' : 'Device enrollment required'}</h2>
        <p className="mb-0 mt-1 text-[13px] font-bold leading-snug text-[var(--text-secondary)]">{message}</p>
        {canStart && (
          <button
            className="mt-2 grid h-8 cursor-pointer rounded-md border border-[var(--border)] bg-[var(--surface)] px-3 text-xs font-extrabold text-[var(--text-primary)] transition-colors duration-200 hover:border-[var(--accent)] hover:bg-[var(--surface-hover)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-55"
            onClick={onStartEnrollment}
            disabled={enrolling}
            type="button"
          >
            {enrolling ? 'Starting enrollment...' : buttonLabel}
          </button>
        )}
        {lastError && <span className="mt-2 inline-block text-xs font-extrabold text-[var(--danger)]">{lastError}</span>}
        {notice?.message && <span className={`mt-2 inline-block text-xs font-extrabold ${noticeToneClass(notice.tone)}`}>{notice.message}</span>}
      </div>
    </section>
  );
}

function noticeToneClass(tone) {
  if (tone === 'success') return 'text-[var(--success)]';
  if (tone === 'danger') return 'text-[var(--danger)]';
  return 'text-[var(--info)]';
}

export { EnrollmentBanner, ServiceInstallBanner };
