import { Search } from 'lucide-react';
import SelectDropdown from './SelectDropdown';

export default function ListToolbar({
  query,
  onQueryChange,
  placeholder = 'Search...',
  summary,
  children,
  className = '',
}) {
  return (
    <div className={`mb-4 grid gap-3 lg:grid-cols-[minmax(0,420px)_minmax(0,1fr)] lg:items-center ${className}`}>
      <div className="relative w-full">
        <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-text-muted" />
        <input
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder={placeholder}
          className="h-11 w-full rounded-md border border-border bg-surface pl-10 pr-4 text-sm font-bold text-text-primary shadow-sm placeholder:text-text-muted transition-colors hover:border-text-muted focus:border-accent focus:outline-none focus:ring-[3px] focus:ring-accent-muted"
        />
      </div>
      {(summary || children) && (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-end lg:min-w-0 lg:justify-self-end">
          {summary && (
            <span className="w-[16ch] shrink-0 text-right text-xs font-bold uppercase tabular-nums tracking-[0.12em] text-text-muted">
              {summary}
            </span>
          )}
          {children && <div className="flex flex-wrap items-center gap-2 sm:flex-nowrap sm:shrink-0">{children}</div>}
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
