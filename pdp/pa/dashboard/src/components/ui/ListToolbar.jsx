import { Search } from 'lucide-react';
import SelectDropdown from './SelectDropdown';

export default function ListToolbar({
  query,
  onQueryChange,
  placeholder = 'Search...',
  summary,
  children,
}) {
  return (
    <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
      <div className="relative w-full lg:max-w-[420px]">
        <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-text-muted" />
        <input
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder={placeholder}
          className="h-11 w-full rounded-md border border-border bg-surface pl-10 pr-4 text-sm font-bold text-text-primary shadow-sm placeholder:text-text-muted transition-colors hover:border-text-muted focus:border-accent focus:outline-none focus:ring-[3px] focus:ring-accent-muted"
        />
      </div>
      {(summary || children) && (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-end">
          {summary && (
            <span className="text-xs font-bold uppercase tracking-[0.12em] text-text-muted">
              {summary}
            </span>
          )}
          {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
        </div>
      )}
    </div>
  );
}

export function ListToolbarSelect({ value, onChange, children, className = '' }) {
  return (
    <SelectDropdown
      value={value}
      onChange={(event) => onChange(event.target.value)}
      className={`w-full sm:w-[176px] ${className}`}
      buttonClassName="h-11 rounded-md px-4 text-sm"
    >
      {children}
    </SelectDropdown>
  );
}
