import { createElement } from 'react';
import { Database } from 'lucide-react';

const DEFAULT_ROW_COUNT = 0;
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

function tableRowVariantClass(rowVariant) {
  if (rowVariant === 'default') {
    return 'min-h-[72px] rounded-md bg-surface-hover ring-1 ring-transparent transition-colors hover:ring-accent';
  }
  return 'min-h-[72px] rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] shadow-[0_8px_16px_rgba(42,42,42,0.12)] transition-[border-color,background-color,box-shadow] duration-150 hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.14)]';
}

function TableSkeletonRows({ columns, gridTemplateColumns, rowVariant, skeletonRowClassName = '' }) {
  return Array.from({ length: SKELETON_ROW_COUNT }, (_, rowIndex) => (
    <div
      key={`skeleton-${rowIndex}`}
      aria-hidden="true"
      className={`grid ${tableRowVariantClass(rowVariant)} ${skeletonRowClassName}`}
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
  rowVariant = 'agent-resource-card',
  rowClassName,
  skeletonRowClassName,
  fillHeight = false,
  className = '',
  onRowClick,
  getRowKey = (row, index) => row.id || index,
}) {
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
  const rowVariantClass = tableRowVariantClass(rowVariant);
  const staticRowClassName = typeof rowClassName === 'string' ? rowClassName : '';
  const loadingRowClassName = skeletonRowClassName || staticRowClassName;
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

  const scrollAreaClass = fillHeight
    ? 'min-h-0 flex-1 overflow-y-scroll px-3 pr-4'
    : 'max-h-[calc(100vh-220px)] min-h-[220px] overflow-y-scroll px-3 pr-4';

  return (
    <div className={`relative min-h-0 rounded-md ${fillHeight ? 'flex h-full flex-col' : ''} ${className}`}>
      <div className={`overflow-x-auto px-4 ${fillHeight ? 'flex min-h-0 flex-1 flex-col' : ''}`}>
        <div className={`min-w-[820px] ${fillHeight ? 'flex min-h-0 flex-1 flex-col' : ''}`}>
          <div className="relative px-3 pr-[34px]">
            <div aria-hidden="true" className="pointer-events-none absolute bottom-0 left-7 right-10 h-[2px] bg-border" />
            <div className="grid" style={{ gridTemplateColumns }}>
              {columns.map((col) => (
                <div
                  key={col.key}
                  className={`relative flex min-w-0 items-center px-6 py-4 text-center text-[11px] font-bold uppercase tracking-[0.14em] text-text-muted after:absolute after:bottom-0 after:right-0 after:h-5 after:w-[2px] after:bg-border after:content-[''] last:after:hidden ${alignClass(col.headerAlign || 'center')} ${col.className || ''}`}
                >
                  {col.label}
                </div>
              ))}
            </div>
          </div>

          <div className={scrollAreaClass}>
            <div className="space-y-3 py-3">
              {loading ? (
                <TableSkeletonRows
                  columns={columns}
                  gridTemplateColumns={gridTemplateColumns}
                  rowVariant={rowVariant}
                  skeletonRowClassName={loadingRowClassName}
                />
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
                  className={`group grid ${rowVariantClass} ${
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
                <div key={`placeholder-${index}`} aria-hidden="true" className={staticRowClassName || 'h-[72px]'} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
