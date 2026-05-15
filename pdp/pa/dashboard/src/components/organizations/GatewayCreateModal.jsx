import { Copy, Router, X } from 'lucide-react';
import { copyText, gatewayFQDN, gatewayLabelFromName, organizationDomain } from './organizationUtils';
import { formatDateTime } from '../../utils/format';

export default function GatewayCreateModal({ organization, form, setForm, error, enrollment, saving, onClose, onCreate }) {
  if (!organization) return null;

  const gatewayDomain = organizationDomain(organization);
  const gatewayDNSLabel = gatewayLabelFromName(form.name);
  const gatewayGeneratedFQDN = gatewayFQDN(form.name, organization);

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
                <input type="text" value={organization?.name || ''} readOnly
                  className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-md text-[13px] text-text-primary font-sans" />
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Gateway name *</label>
                <input type="text" value={form.name || ''} onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition font-sans"
                  placeholder="e.g. hq-gateway" />
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">FQDN</label>
                <div className="flex">
                  <input type="text" value={gatewayDNSLabel} readOnly
                    className="min-w-0 flex-1 px-3 py-2 bg-surface-secondary border border-border rounded-l-md text-[13px] text-text-primary font-mono" />
                  <span className="inline-flex items-center max-w-[55%] px-3 py-2 bg-surface-secondary border border-l-0 border-border rounded-r-md text-[13px] text-text-secondary font-mono truncate">
                    {gatewayDomain ? `.${gatewayDomain}` : '.organization-domain'}
                  </span>
                </div>
                <input type="text" value={gatewayGeneratedFQDN || ''} readOnly className="sr-only" aria-label="Generated gateway FQDN" />
              </div>

              {enrollment?.token ? (
                <div className="p-3 border border-warning/30 rounded-md bg-warning-muted">
                  <div className="text-xs font-semibold text-text-primary mb-2">Gateway Enrollment</div>
                  <div className="grid gap-2 md:grid-cols-2">
                    <div>
                      <div className="text-[10px] font-semibold uppercase text-text-muted">Gateway ID</div>
                      <code className="text-mono [overflow-wrap:anywhere] text-text-primary">{enrollment.gateway_id || '-'}</code>
                    </div>
                    <div>
                      <div className="text-[10px] font-semibold uppercase text-text-muted">Expires</div>
                      <code className="text-mono text-text-primary">{formatDateTime(enrollment.expires_at)}</code>
                    </div>
                  </div>
                  <div className="mt-2">
                    <div className="text-[10px] font-semibold uppercase text-text-muted">FQDN</div>
                    <code className="text-mono [overflow-wrap:anywhere] text-text-primary">{enrollment.fqdn || '-'}</code>
                  </div>
                  <div className="mt-3 flex gap-2 items-center">
                    <code className="text-mono flex-1 [overflow-wrap:anywhere] text-text-primary">{enrollment.token}</code>
                    <button onClick={() => copyText(enrollment.token)}
                      className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-semibold border border-border rounded text-text-secondary hover:bg-surface-hover transition-colors">
                      <Copy size={12} /> Copy
                    </button>
                  </div>
                </div>
              ) : null}
            </div>

            <div className="flex justify-end gap-2 px-6 py-4 border-t border-border bg-surface-secondary">
              <button onClick={onClose}
                className="px-4 py-2 text-xs font-semibold text-text-secondary hover:text-text-primary">Cancel</button>
              <button onClick={onCreate}
                disabled={saving || !organization?.id || !gatewayDomain || !gatewayDNSLabel}
                className="px-4 py-2 text-xs font-semibold bg-accent text-white-smoke rounded-md hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors inline-flex items-center gap-1.5">
                <Router size={14} /> {saving ? 'Creating...' : 'Create Gateway'}
              </button>
            </div>
          </div>
        </div>
  );
}
