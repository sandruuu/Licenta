export default function FormField({ label, children, hint, htmlFor, className = '' }) {
  return (
    <div className={`mb-4 ${className}`}>
      {label && (
        <label htmlFor={htmlFor} className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">
          {label}
        </label>
      )}
      {children}
      {hint && <p className="text-[11px] text-text-muted mt-1">{hint}</p>}
    </div>
  );
}

export function FormInput({ className = '', ...props }) {
  return (
    <input
      {...props}
      className={`w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary
                  placeholder:text-text-muted
                  focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted
                  transition font-sans ${className}`}
    />
  );
}

export function FormSelect({ children, className = '', ...props }) {
  return (
    <select
      {...props}
      className={`w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary
                  focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted
                  transition font-sans ${className}`}
    >
      {children}
    </select>
  );
}

export function FormTextarea({ className = '', ...props }) {
  return (
    <textarea
      {...props}
      className={`w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary
                  placeholder:text-text-muted
                  focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted
                  transition resize-y min-h-[80px] font-sans ${className}`}
    />
  );
}

export function FormRow({ children, className = '' }) {
  return (
    <div className={`grid grid-cols-2 gap-4 ${className}`}>
      {children}
    </div>
  );
}

export function FormCheckbox({ id, label, className = '', ...props }) {
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <input
        type="checkbox"
        id={id}
        {...props}
        className="rounded border-border text-accent focus:ring-accent w-4 h-4"
      />
      <label htmlFor={id} className="text-[13px] text-text-secondary">{label}</label>
    </div>
  );
}
