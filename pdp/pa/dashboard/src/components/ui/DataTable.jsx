import { createElement } from 'react';
import { Database } from 'lucide-react';

const DEFAULT_ROW_COUNT = 0;
const TABLE_HEADER_HEIGHT = 64;
const TABLE_ROW_HEIGHT = 84;

export function TableActions({ children, className = '' }) {
  return (
    <div className={`flex items-center justify-center gap-2 ${className}`}>
      {children}
    </div>
  );
}

export function TableIconButton({ icon, label, danger = false, className = '', onClick, ...props }) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      className={`grid h-8 w-8 place-items-center rounded-md text-text-muted transition-colors hover:bg-surface-secondary ${
        danger ? 'hover:text-danger' : 'hover:text-accent'
      } ${className}`}
      onClick={(event) => {
        event.stopPropagation();
        onClick?.(event);
      }}
      {...props}
    >
      {createElement(icon, { size: 16 })}
    </button>
  );
}

export default function DataTable({
  columns,
  data,
  loading,
  minRows = DEFAULT_ROW_COUNT,
  emptyIcon = Database,
  emptyTitle = 'No data',
  emptyMessage,
  rowClassName,
  onRowClick,
  getRowKey = (row, index) => row.id || index,
}) {
  const fixedTableStyle = minRows ? { minHeight: `${TABLE_HEADER_HEIGHT + (minRows * TABLE_ROW_HEIGHT)}px` } : undefined;

  if (loading) {
    return (
      <div className="overflow-hidden rounded-md border border-border bg-surface-card shadow-surface" style={fixedTableStyle}>
        <div className="flex h-full items-center justify-center gap-2 p-12 text-center text-sm font-semibold text-text-muted" style={fixedTableStyle}>
          <span className="spinner" />
          Loading...
        </div>
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="overflow-hidden rounded-md border border-border bg-surface-card shadow-surface" style={fixedTableStyle}>
        <div className="flex h-full flex-col items-center justify-center p-12 text-center text-text-muted" style={fixedTableStyle}>
          {createElement(emptyIcon, { size: 48, className: 'mx-auto mb-3 opacity-40' })}
          <p className="text-sm font-bold text-text-primary">{emptyTitle}</p>
          {emptyMessage && <p className="mt-1 text-xs font-medium">{emptyMessage}</p>}
        </div>
      </div>
    );
  }

  const placeholderRows = Math.max(minRows - data.length, 0);

  return (
    <div className="relative rounded-md" style={fixedTableStyle}>
      <div className="overflow-x-auto px-4">
        <table className="w-full min-w-[820px] border-separate border-spacing-y-3">
          <thead>
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  className={`relative whitespace-nowrap px-6 py-4 text-center text-[11px] font-bold uppercase tracking-[0.14em] text-text-muted before:absolute before:bottom-0 before:left-0 before:right-0 before:h-[2px] before:bg-border before:content-[''] after:absolute after:bottom-0 after:right-0 after:h-5 after:w-[2px] after:bg-border after:content-[''] first:before:left-4 last:before:right-4 last:after:hidden ${col.className || ''}`}
                  style={col.width ? { width: col.width } : undefined}
                >
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, i) => (
              <tr
                key={getRowKey(row, i)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={`group h-[72px] shadow-surface transition-colors ${
                  onRowClick ? 'cursor-pointer' : ''
                } ${typeof rowClassName === 'function' ? rowClassName(row) : rowClassName || ''}`}
              >
                {columns.map((col) => (
                  <td
                    key={col.key}
                    className={`bg-surface-card px-6 py-5 text-center align-middle text-sm font-semibold text-text-secondary transition-colors first:rounded-l-md last:rounded-r-md ${onRowClick ? 'group-hover:bg-surface-hover/60' : ''} ${col.cellClassName || ''}`}
                  >
                    {col.render ? col.render(row[col.key], row) : row[col.key]}
                  </td>
                ))}
              </tr>
            ))}
            {Array.from({ length: placeholderRows }, (_, index) => (
              <tr key={`placeholder-${index}`} aria-hidden="true" className="h-[72px]">
                <td colSpan={columns.length} className="px-6 py-5">
                  &nbsp;
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
