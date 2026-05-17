function Panel({ title, className = '', children }) {
  return (
    <section className={`min-h-0 min-w-0 animate-[cardFadeIn_0.25s_ease-out_both] rounded-md border border-[var(--border)] bg-[var(--surface-card)] p-4 ${className}`}>
      <h2 className="mb-3.5 mt-0 text-sm font-extrabold text-[var(--text-primary)]">{title}</h2>
      {children}
    </section>
  );
}

function KeyValue({ label, value }) {
  return (
    <div className="grid grid-cols-[132px_minmax(0,1fr)] gap-2.5 border-t border-[var(--border-light)] py-2 first:border-t-0 first:pt-0">
      <span className="text-xs font-extrabold text-[var(--text-muted)]">{label}</span>
      <strong className="min-w-0 overflow-hidden truncate text-xs font-extrabold text-[var(--text-primary)]" title={value || ''}>
        {value || 'Unavailable'}
      </strong>
    </div>
  );
}

function EmptyState({ title }) {
  return (
    <div className="grid min-h-24 place-items-center rounded-md border border-dashed border-[var(--border)] bg-[var(--surface)] text-[13px] font-extrabold text-[var(--text-muted)]">
      {title}
    </div>
  );
}

export { EmptyState, KeyValue, Panel };
