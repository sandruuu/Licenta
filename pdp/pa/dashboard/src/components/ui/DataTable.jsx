import { Database } from 'lucide-react';

export default function DataTable({ columns, data, loading, emptyIcon: EmptyIcon = Database, emptyTitle = 'No data', emptyMessage }) {
  if (loading) {
    return (
      <div className="bg-surface-card rounded-md border border-border overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
        <div className="p-8 text-center text-text-muted flex items-center justify-center gap-2">
          <span className="spinner" />
          Loading...
        </div>
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="bg-surface-card rounded-md border border-border overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
        <div className="p-8 text-center text-text-muted">
          <EmptyIcon size={48} className="mx-auto mb-3 opacity-40" />
          <p className="text-sm font-medium text-text-primary">{emptyTitle}</p>
          {emptyMessage && <p className="text-xs mt-1">{emptyMessage}</p>}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-surface-card rounded-md border border-border overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border bg-surface-secondary">
              {columns.map((col) => (
                <th key={col.key}
                    className={`text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px] whitespace-nowrap ${col.align === 'right' ? 'text-right' : ''} ${col.className || ''}`}>
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {data.map((row, i) => (
              <tr key={row.id || i} className="hover:bg-surface-hover transition-colors">
                {columns.map((col) => (
                  <td key={col.key}
                      className={`px-6 py-4 text-xs text-text-secondary font-medium ${col.align === 'right' ? 'text-right' : ''} ${col.cellClassName || ''}`}>
                    {col.render ? col.render(row[col.key], row) : row[col.key]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
