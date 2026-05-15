import { createElement } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import Badge from './Badge';
import EmptyState from './EmptyState';

export function DetailEmptyState({ icon, title, message }) {
  return <EmptyState variant="inline" icon={icon} title={title} message={message} />;
}

export const detailSectionTitleClass = 'text-[13px] font-bold uppercase tracking-[0.12em] text-text-muted';
export const detailSummaryItemClass = 'block w-full max-w-3xl px-4 py-3 text-left';

export function DetailDivider({ className = '' }) {
  return <div className={`border-t border-border ${className}`} />;
}

export function DetailSummaryItem({ children, onClick, className = '' }) {
  const itemClass = `${detailSummaryItemClass} ${onClick ? 'cursor-pointer' : ''} ${className}`;

  if (onClick) {
    return (
      <button type="button" onClick={onClick} className={itemClass}>
        {children}
      </button>
    );
  }

  return <div className={itemClass}>{children}</div>;
}

export function DetailDisclosure({ open, onClick, title, description }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-start justify-between gap-4 rounded-md border border-border-light bg-surface-card px-4 py-3 text-left transition-colors hover:border-accent hover:bg-accent-muted"
    >
      <span className="min-w-0">
        <span className="block text-sm font-bold text-text-primary">{title}</span>
        {description && <span className="mt-1 block text-xs font-medium text-text-secondary">{description}</span>}
      </span>
      {open ? <ChevronDown size={16} className="mt-0.5 shrink-0 text-text-muted" /> : <ChevronRight size={16} className="mt-0.5 shrink-0 text-text-muted" />}
    </button>
  );
}

export function DetailSection({ icon, title, subtitle, count, open, onToggle, actions, children }) {
  return (
    <section className="border-b border-border-light pb-5">
      <div className="flex items-start justify-between gap-4">
        <button
          type="button"
          onClick={onToggle}
          className="group flex min-w-0 flex-1 items-start gap-3 rounded-md bg-transparent px-0 py-0 text-left hover:text-text-primary"
        >
          <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-surface-secondary text-text-secondary group-hover:bg-accent-muted group-hover:text-accent">
            {createElement(icon, { size: 17 })}
          </span>
          <span className="min-w-0">
            <span className="flex flex-wrap items-center gap-2 text-base font-semibold text-text-primary">
              {title}
              {typeof count === 'number' && <Badge variant="neutral">{count}</Badge>}
              {open ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
            </span>
            {subtitle && <span className="mt-1 block text-xs text-text-muted">{subtitle}</span>}
          </span>
        </button>
        {actions && <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">{actions}</div>}
      </div>
      {open && <div className="mt-4">{children}</div>}
    </section>
  );
}

export function FieldLine({ label, value, mono = false }) {
  const displayValue = value === 0 || value === false ? String(value) : value || '-';
  return (
    <div className="min-w-0">
      <div className="text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">{label}</div>
      <div className={`mt-1 truncate text-sm font-medium text-text-primary ${mono ? 'text-mono' : ''}`}>{displayValue}</div>
    </div>
  );
}

export function DataRow({ children, className = '' }) {
  return (
    <div className={`grid items-center gap-4 rounded-md border border-border-light bg-surface-card px-4 py-3 ${className}`}>
      {children}
    </div>
  );
}

export function ClickRow({ icon, label, value, hint, children, onClick, className = '' }) {
  if (children) {
    return (
      <button
        type="button"
        onClick={onClick}
        className={`grid w-full items-center gap-4 rounded-md border border-border-light bg-surface-card px-4 py-3 text-left transition-colors hover:border-accent hover:bg-accent-muted active:bg-accent-muted ${className}`}
      >
        {children}
      </button>
    );
  }

  const displayValue = value === 0 || value === false ? String(value) : value || '-';
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-center justify-between gap-4 rounded-md border border-border-light bg-surface-card px-4 py-3 text-left transition-colors hover:border-accent hover:bg-accent-muted active:bg-accent-muted"
    >
      <span className="flex min-w-0 items-center gap-3">
        {icon && (
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-surface-secondary text-text-secondary">
            {createElement(icon, { size: 16 })}
          </span>
        )}
        <span className="min-w-0">
          <span className="block truncate text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">{label}</span>
          <span className="mt-1 block truncate text-sm font-semibold text-text-primary">{displayValue}</span>
          {hint && <span className="block truncate text-xs text-text-muted">{hint}</span>}
        </span>
      </span>
      <ChevronRight size={16} className="shrink-0 text-text-muted" />
    </button>
  );
}

export function BackIconButton({ title = 'Back', onClick, children, compact = false }) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      className={`flex h-8 shrink-0 items-center ${compact ? 'w-4 justify-start' : 'w-8 justify-center'}`}
    >
      {children}
    </button>
  );
}

export function InlineBackButton({ onClick, children }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-2 rounded-md bg-transparent px-0 py-0 text-sm font-semibold text-text-secondary hover:text-accent"
    >
      {children}
    </button>
  );
}
