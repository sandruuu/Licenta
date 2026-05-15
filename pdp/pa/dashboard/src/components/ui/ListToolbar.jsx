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
          className="h-11 w-full rounded-md border border-border bg-surface-secondary pl-10 pr-4 text-sm font-semibold text-text-primary placeholder:text-text-muted transition-colors focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent-muted"
        />
      </div>
    </div>
  );
}

export function ListToolbarSelect({ value, onChange, children, className = '' }) {
  return (
    <SelectDropdown
      value={value}
      onChange={(event) => onChange(event.target.value)}
      className={`min-w-[176px] ${className}`}
      buttonClassName="h-11 rounded-md px-4 text-sm"
    >
      {children}
    </SelectDropdown>
  );
}
