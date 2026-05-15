import { Check } from 'lucide-react';
import SelectDropdown from './SelectDropdown';

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
    <SelectDropdown
      {...props}
      className={`w-full ${className}`}
      buttonClassName="min-h-10 rounded-md px-3 py-2 text-[13px]"
    >
      {children}
    </SelectDropdown>
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

export function FormCheckbox({ id, label, className = '', disabled = false, ...props }) {
  return (
    <label
      htmlFor={id}
      className={`inline-flex select-none items-center gap-2 text-[13px] font-medium text-text-secondary transition-colors ${
        disabled ? 'cursor-not-allowed opacity-55' : 'cursor-pointer hover:text-text-primary'
      } ${className}`}
    >
      <input
        type="checkbox"
        id={id}
        disabled={disabled}
        {...props}
        className="peer sr-only"
      />
      <span
        aria-hidden="true"
        className="grid h-5 w-5 shrink-0 place-items-center rounded-md border border-border bg-surface text-transparent shadow-sm transition-colors peer-checked:border-accent peer-checked:bg-accent peer-checked:text-white-smoke peer-focus-visible:ring-[3px] peer-focus-visible:ring-accent-muted peer-disabled:bg-surface-secondary"
      >
        <Check size={14} strokeWidth={3} />
      </span>
      <span>{label}</span>
    </label>
  );
}
