export default function StatusBadge({ enabled }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide ${
      enabled ? 'bg-success-muted text-success' : 'bg-danger-muted text-danger'
    }`}>
      {enabled ? 'Enabled' : 'Disabled'}
    </span>
  );
}
