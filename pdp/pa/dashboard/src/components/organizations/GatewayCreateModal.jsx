import { Router, X } from 'lucide-react';
import { FormSelect } from '../ui/FormField';

export default function GatewayCreateModal({
  organization,
  organizations = [],
  onOrganizationChange,
  form,
  setForm,
  error,
  saving,
  onClose,
  onCreate,
}) {
  if (!organization) return null;

  const gatewayName = (form.name || '').trim();
  const gatewayFQDN = (form.fqdn || '').trim();
  const canCreate = Boolean(organization?.id && gatewayName && gatewayFQDN);

  return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-graphite/45 backdrop-blur-sm p-4">
          <div className="bg-surface-card rounded-md border border-border shadow-2xl w-[min(560px,calc(100vw-32px))] overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border">
              <div>
                <h2 className="text-base font-semibold text-text-primary">Create Gateway</h2>
                <p className="text-[11px] text-text-muted mt-0.5">{organization?.name || 'Organization'}</p>
              </div>
              <button onClick={onClose} className="p-1 text-text-muted hover:text-text-primary rounded-md">
                <X size={20} />
              </button>
            </div>

            <div className="p-6 space-y-4">
              {error && (
                <div className="bg-danger-muted border border-danger rounded-md p-3 text-xs text-danger">{error}</div>
              )}

              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Organization</label>
                {onOrganizationChange && organizations.length ? (
                  <FormSelect
                    value={organization?.id || ''}
                    onChange={(event) => onOrganizationChange(event.target.value)}
                    className="mb-0"
                  >
                    {organizations.map((item) => (
                      <option key={item.id} value={item.id}>{item.name}</option>
                    ))}
                  </FormSelect>
                ) : (
                  <input type="text" value={organization?.name || ''} readOnly
                    className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-md text-[13px] text-text-primary font-sans" />
                )}
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Gateway name *</label>
                <input type="text" value={form.name || ''} onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition font-sans"
                  placeholder="e.g. hq-gateway" />
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">FQDN *</label>
                <input
                  type="text"
                  value={form.fqdn || ''}
                  onChange={(event) => setForm({ ...form, fqdn: event.target.value })}
                  placeholder="e.g. gateway.example.com"
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md font-mono text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition" />
              </div>
            </div>

            <div className="flex justify-end gap-2 px-6 py-4 border-t border-border bg-surface-secondary">
              <button onClick={onClose}
                className="px-4 py-2 text-xs font-semibold text-text-secondary hover:text-text-primary">Cancel</button>
              <button onClick={onCreate}
                disabled={saving || !canCreate}
                className="px-4 py-2 text-xs font-semibold bg-accent text-white-smoke rounded-md hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors inline-flex items-center gap-1.5">
                <Router size={14} /> {saving ? 'Creating...' : 'Create Gateway'}
              </button>
            </div>
          </div>
        </div>
  );
}
