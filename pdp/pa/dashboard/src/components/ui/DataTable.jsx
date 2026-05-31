import { createElement } from 'react';
import { Database } from 'lucide-react';

const DEFAULT_ROW_COUNT = 0;
const TABLE_HEADER_HEIGHT = 64;
const TABLE_ROW_HEIGHT = 84;
const SKELETON_ROW_COUNT = 3;

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

function TableSkeletonRows({ columns, gridTemplateColumns }) {
  return Array.from({ length: SKELETON_ROW_COUNT }, (_, rowIndex) => (
    <div
      key={`skeleton-${rowIndex}`}
      aria-hidden="true"
      className="grid min-h-[72px] rounded-md bg-surface-hover"
      style={{ gridTemplateColumns }}
    >
      {columns.map((col, colIndex) => (
        <div
          key={`${col.key}-skeleton`}
          className={`flex min-w-0 items-center px-6 py-5 ${col.key === 'actions' ? 'justify-center' : 'justify-center'}`}
        >
          <div
            className={`h-4 animate-pulse rounded bg-border-light ${
              colIndex % 3 === 0 ? 'w-24' : colIndex % 3 === 1 ? 'w-32' : 'w-16'
            }`}
          />
        </div>
      ))}
    </div>
  ));
}

export default function DataTable({
  columns,
  data,
  loading,
  minRows = DEFAULT_ROW_COUNT,
  emptyIcon = Database,
  emptyTitle = 'No data',
  emptyMessage,
  emptyVariant = 'plain',
  rowClassName,
  onRowClick,
  getRowKey = (row, index) => row.id || index,
}) {
  const fixedTableStyle = minRows ? { minHeight: `${TABLE_HEADER_HEIGHT + (minRows * TABLE_ROW_HEIGHT)}px` } : undefined;
  const rows = Array.isArray(data) ? data : [];
  const placeholderRows = Math.max(minRows - rows.length, 0);
  const gridTemplateColumns = columns
    .map((col) => {
      if (!col.width) return 'minmax(0, 1fr)';
      return typeof col.width === 'number' ? `${col.width}px` : col.width;
    })
    .join(' ');
  const alignClass = (align) => {
    if (align === 'left') return 'justify-start text-left';
    if (align === 'right') return 'justify-end text-right';
    return 'justify-center text-center';
  };
  const emptyState = emptyVariant === 'card' ? (
    <div className="py-12 text-center text-text-muted">
      {createElement(emptyIcon, { size: 40, className: 'mx-auto mb-3 opacity-35' })}
      <p className="text-sm font-bold text-text-muted">{emptyTitle}</p>
      {emptyMessage && <p className="mt-1 text-xs font-medium">{emptyMessage}</p>}
    </div>
  ) : (
    <div className="py-12 text-center">
      <p className="text-sm font-bold text-text-muted">{emptyTitle}</p>
      {emptyMessage && <p className="mt-1 text-xs font-medium text-text-muted">{emptyMessage}</p>}
    </div>
  );

  return (
    <div className="relative rounded-md" style={fixedTableStyle}>
      <div className="overflow-x-auto px-4">
        <div className="min-w-[820px]">
          <div className="grid" style={{ gridTemplateColumns }}>
            {columns.map((col) => (
              <div
                key={col.key}
                className={`relative flex min-w-0 items-center px-6 py-4 text-center text-[11px] font-bold uppercase tracking-[0.14em] text-text-muted before:absolute before:bottom-0 before:left-0 before:right-0 before:h-[2px] before:bg-border before:content-[''] after:absolute after:bottom-0 after:right-0 after:h-5 after:w-[2px] after:bg-border after:content-[''] first:before:left-4 last:before:right-4 last:after:hidden ${alignClass(col.headerAlign || 'center')} ${col.className || ''}`}
              >
                {col.label}
              </div>
            ))}
          </div>

          <div className="space-y-3 pt-3">
            {loading ? (
              <TableSkeletonRows columns={columns} gridTemplateColumns={gridTemplateColumns} />
            ) : rows.length === 0 ? (
              emptyState
            ) : rows.map((row, i) => (
              <div
                key={getRowKey(row, i)}
                role={onRowClick ? 'button' : undefined}
                tabIndex={onRowClick ? 0 : undefined}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                onKeyDown={onRowClick ? (event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    onRowClick(row);
                  }
                } : undefined}
                className={`group grid min-h-[72px] rounded-md bg-surface-hover ring-1 ring-transparent transition-colors hover:ring-accent ${
                  onRowClick ? 'cursor-pointer' : ''
                } ${typeof rowClassName === 'function' ? rowClassName(row) : rowClassName || ''}`}
                style={{ gridTemplateColumns }}
              >
                {columns.map((col) => (
                  <div
                    key={col.key}
                    className={`flex min-w-0 items-center px-6 py-5 text-sm font-semibold text-text-secondary ${alignClass(col.key === 'actions' ? 'center' : col.align)} ${col.cellClassName || ''}`}
                  >
                    {col.render ? col.render(row[col.key], row) : row[col.key]}
                  </div>
                ))}
              </div>
            ))}
            {!loading && rows.length > 0 && Array.from({ length: placeholderRows }, (_, index) => (
              <div key={`placeholder-${index}`} aria-hidden="true" className="h-[72px]" />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
