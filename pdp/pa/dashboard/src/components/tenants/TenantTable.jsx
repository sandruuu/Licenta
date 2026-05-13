import { ArrowRight, Building2, Globe, Shield, Trash2 } from 'lucide-react';
import StatusBadge from './StatusBadge';

export default function TenantTable({
  loading,
  tenants,
  onOpen,
  onDelete,
  emptyTitle = 'No organizations yet',
  emptyMessage = 'Create the first organization to start managing gateways and resources.',
}) {
  return (
    <div className="bg-surface-card rounded-md border border-border p-4 shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
      {loading ? (
        <div className="p-8 text-center text-text-muted">Loading organizations...</div>
      ) : tenants.length === 0 ? (
        <div className="p-8 text-center text-text-muted">
          <Building2 size={48} className="mx-auto mb-3 opacity-40" />
          <p className="text-sm font-medium text-text-primary">{emptyTitle}</p>
          <p className="text-xs mt-1">{emptyMessage}</p>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-[1.8fr_1.2fr_1fr_0.8fr_0.45fr] gap-4 border-b border-border pb-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">
            <div>Name</div>
            <div>Primary domain</div>
            <div>IdP</div>
            <div>Status</div>
            <div className="text-right">Delete</div>
          </div>

          <div className="mt-3 space-y-2">
            {tenants.map((tenant) => (
              <div
                key={tenant.id}
                className="grid grid-cols-[1.8fr_1.2fr_1fr_0.8fr_0.45fr] items-center gap-4 rounded-md border border-border px-4 py-3 cursor-pointer transition-colors hover:bg-[rgba(255,95,31,0.09)] hover:border-accent-orange active:bg-[rgba(255,95,31,0.16)] active:border-accent-orange"
                onClick={() => onOpen?.(tenant)}
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-md bg-accent-muted flex items-center justify-center flex-shrink-0">
                      <Building2 size={16} className="text-accent" />
                    </div>
                    <div className="min-w-0">
                      <p className="font-medium text-text-primary text-xs inline-flex items-center gap-1.5">
                        {tenant.name}
                        <ArrowRight size={12} className="text-text-muted" />
                      </p>
                      {tenant.description && <p className="text-[11px] text-text-muted mt-0.5 truncate">{tenant.description}</p>}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 min-w-0">
                  <Globe size={14} className="text-text-muted flex-shrink-0" />
                  <span className="text-xs text-text-secondary font-mono truncate">{tenant.domain || '-'}</span>
                </div>

                <div className="text-xs text-text-muted">
                  {tenant.default_idp_id ? (
                    <span className="inline-flex items-center gap-1 text-accent font-semibold">
                      <Shield size={12} /> Configured
                    </span>
                  ) : '-'}
                </div>

                <div><StatusBadge enabled={tenant.enabled} /></div>

                <div className="text-right">
                  <button
                    onClick={(event) => { event.stopPropagation(); onDelete(tenant.id); }}
                    className="p-1.5 text-danger hover:bg-danger-muted rounded-md transition-colors"
                    title="Delete organization"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

