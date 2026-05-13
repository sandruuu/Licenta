import { Building2, Edit, Globe, Router, Shield, Trash2 } from 'lucide-react';
import StatusBadge from './StatusBadge';

export default function TenantTable({ loading, tenants, onManageIdPs, onCreateGateway, onEdit, onDelete }) {
  return (
      <div className="bg-surface-card rounded-md border border-border overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
        {loading ? (
          <div className="p-8 text-center text-text-muted">Loading tenants...</div>
        ) : tenants.length === 0 ? (
          <div className="p-8 text-center text-text-muted">
            <Building2 size={48} className="mx-auto mb-3 opacity-40" />
            <p className="text-sm font-medium text-text-primary">No tenants yet</p>
            <p className="text-xs mt-1">Create the first organization to start managing gateways and resources.</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-surface-secondary">
                <th className="text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">Name</th>
                <th className="text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">Primary domain</th>
                <th className="text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">IdP</th>
                <th className="text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">Status</th>
                <th className="text-right px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {tenants.map((t) => (
                <tr key={t.id} className="hover:bg-surface-hover transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-md bg-accent-muted flex items-center justify-center">
                        <Building2 size={16} className="text-accent" />
                      </div>
                      <div>
                        <p className="font-medium text-text-primary text-xs">{t.name}</p>
                        {t.description && <p className="text-[11px] text-text-muted mt-0.5">{t.description}</p>}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-1.5">
                      <Globe size={14} className="text-text-muted" />
                      <span className="text-xs text-text-secondary font-mono">{t.domain || '—'}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-xs text-text-muted">
                      {t.default_idp_id ? (
                        <span className="inline-flex items-center gap-1 text-accent font-semibold">
                          <Shield size={12} /> Configured
                        </span>
                      ) : '—'}
                    </span>
                  </td>
                  <td className="px-6 py-4"><StatusBadge enabled={t.enabled} /></td>
                  <td className="px-6 py-4">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => onManageIdPs(t)}
                        className="p-1.5 text-accent hover:bg-accent-muted rounded-md transition-colors"
                        title="Manage Identity Providers"
                      >
                        <Shield size={16} />
                      </button>
                      <button
                        onClick={() => onCreateGateway(t)}
                        className="p-1.5 text-text-secondary hover:bg-surface-hover rounded-md transition-colors"
                        title="Create Gateway for this tenant"
                      >
                        <Router size={16} />
                      </button>
                      <button
                        onClick={() => onEdit(t)}
                        className="p-1.5 text-text-secondary hover:bg-surface-hover rounded-md transition-colors"
                        title="Edit tenant"
                      >
                        <Edit size={16} />
                      </button>
                      <button
                        onClick={() => onDelete(t.id)}
                        className="p-1.5 text-danger hover:bg-danger-muted rounded-md transition-colors"
                        title="Delete tenant"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
  );
}
