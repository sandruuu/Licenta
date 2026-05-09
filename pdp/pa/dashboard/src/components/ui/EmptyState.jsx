export default function EmptyState({ icon: Icon, title, message, action }) {
  return (
    <div className="bg-surface-card rounded-md border border-border p-8 text-center text-text-muted
                    shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
      {Icon && <Icon size={48} className="mx-auto mb-3 opacity-40" />}
      {title && <p className="text-sm font-medium text-text-primary">{title}</p>}
      {message && <p className="text-xs mt-1">{message}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
