export default function EmptyState({ icon: Icon, title, message, action, variant = 'card' }) {
  if (variant === 'inline') {
    return (
      <div className="py-8 text-center text-text-muted">
        {Icon && <Icon size={32} className="mx-auto mb-3 opacity-35" />}
        {title && <p className="text-sm font-semibold text-text-primary">{title}</p>}
        {message && <p className="mt-1 text-xs">{message}</p>}
        {action && <div className="mt-4">{action}</div>}
      </div>
    );
  }

  return (
    <div className="bg-surface-card rounded-md border border-border p-8 text-center text-text-muted shadow-surface">
      {Icon && <Icon size={48} className="mx-auto mb-3 opacity-40" />}
      {title && <p className="text-sm font-medium text-text-primary">{title}</p>}
      {message && <p className="text-xs mt-1">{message}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
