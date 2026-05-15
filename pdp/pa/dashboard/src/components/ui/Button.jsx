const base = 'inline-flex items-center gap-1.5 px-4 py-2 rounded-md font-semibold text-xs transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed';

const styles = {
  primary:
    'bg-accent text-white-smoke hover:bg-accent-hover',
  secondary:
    'bg-transparent border border-border text-text-secondary hover:bg-surface-hover hover:text-text-primary',
  danger:
    'bg-transparent border border-border text-danger hover:bg-danger-muted',
  ghost:
    'bg-transparent text-text-secondary hover:text-text-primary hover:bg-surface-hover',
};

export default function Button({ variant = 'primary', children, className = '', ...props }) {
  return (
    <button {...props} className={`${base} ${styles[variant] || styles.primary} ${className}`}>
      {children}
    </button>
  );
}
