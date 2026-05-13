import { Search } from 'lucide-react';

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
          className="h-11 w-full rounded-full border border-border bg-surface-secondary pl-10 pr-4 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition-colors"
        />
      </div>

      <div className="flex flex-wrap items-center justify-end gap-2">
        {children}
        {summary && (
          <span className="px-1 text-xs font-medium text-text-secondary whitespace-nowrap">
            {summary}
          </span>
        )}
      </div>
    </div>
  );
}

export function ListToolbarSelect({ value, onChange, children, className = '' }) {
  return (
    <select
      value={value}
      onChange={(event) => onChange(event.target.value)}
      className={`h-11 min-w-[140px] rounded-full border border-border bg-surface-card px-4 text-[12px] font-semibold text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition-colors ${className}`}
    >
      {children}
    </select>
  );
}
