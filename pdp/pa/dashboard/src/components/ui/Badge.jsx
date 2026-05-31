const variants = {
  success: 'bg-success-muted text-success',
  warning: 'bg-warning-muted text-warning',
  danger:  'bg-danger-muted text-danger',
  info:    'bg-info-muted text-info',
  neutral: 'bg-surface-secondary text-text-muted',
  accent:  'bg-accent-muted text-accent',
  resourceWeb: 'bg-[#dceff1] text-[#1f6f78]',
  resourceSsh: 'bg-[#e7eaff] text-[#4353a3]',
  resourceRdp: 'bg-[#efe7f7] text-[#7550a8]',
};

export default function Badge({ variant = 'neutral', children, className = '' }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide ${variants[variant] || variants.neutral} ${className}`}>
      {children}
    </span>
  );
}
