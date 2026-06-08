const statusTextClasses = {
  success: 'text-[#638f67]',
  danger: 'text-[#b46a62]',
  warning: 'text-[#c7a23a]',
  neutral: 'text-text-muted',
};

export default function StatusText({ variant = 'neutral', children, className = '' }) {
  return (
    <span className={`inline-block text-xs font-bold uppercase leading-5 ${statusTextClasses[variant] || statusTextClasses.neutral} ${className}`}>
      {children}
    </span>
  );
}
