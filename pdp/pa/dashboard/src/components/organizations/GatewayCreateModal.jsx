import { Copy, Router, X } from 'lucide-react';
import { copyText, gatewayFQDNFromLabel, gatewayLabelFromName, organizationDomain } from './organizationUtils';
import { FormSelect } from '../ui/FormField';
import { formatDateTime } from '../../utils/format';

export default function GatewayCreateModal({
  organization,
  organizations = [],
  onOrganizationChange,
  form,
  setForm,
  error,
  enrollment,
  saving,
  onClose,
  onCreate,
}) {
  if (!organization) return null;

  const gatewayDomain = organizationDomain(organization);
  const gatewayDNSLabel = gatewayLabelFromName(form.fqdn_label);
  const gatewayGeneratedFQDN = gatewayFQDNFromLabel(gatewayDNSLabel, organization);

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
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">FQDN</label>
                <div className="flex overflow-hidden rounded-md border border-border bg-surface-secondary shadow-sm transition-colors focus-within:border-accent focus-within:ring-[3px] focus-within:ring-accent-muted">
                  <input
                    type="text"
                    value={form.fqdn_label || ''}
                    onChange={(event) => setForm({ ...form, fqdn_label: gatewayLabelFromName(event.target.value) })}
                    placeholder="e.g. edge-01"
                    className="min-w-0 flex-1 border-0 bg-transparent px-3 py-2 font-mono text-[13px] text-text-primary focus:outline-none" />
                  <span className="inline-flex max-w-[55%] items-center border-l border-border px-3 py-2 font-mono text-[13px] text-text-secondary">
                    {gatewayDomain ? `.${gatewayDomain}` : '.organization-domain'}
                  </span>
                </div>
                <input type="text" value={gatewayGeneratedFQDN || ''} readOnly className="sr-only" aria-label="Generated gateway FQDN" />
              </div>

              {enrollment?.token ? (
                <div className="rounded-md border border-warning/30 bg-warning-muted p-3">
                  <div className="mb-3 text-xs font-bold text-text-primary">Enrollment token</div>
                  <div>
                    <div className="flex items-center gap-2">
                      <code className="text-mono min-w-0 flex-1 [overflow-wrap:anywhere] text-text-primary">{enrollment.token}</code>
                      <button
                        type="button"
                        onClick={() => copyText(enrollment.token)}
                        title="Copy enrollment token"
                        aria-label="Copy enrollment token"
                        className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-transparent text-text-secondary transition-colors hover:bg-warning/10 hover:text-accent"
                      >
                        <Copy size={14} />
                      </button>
                    </div>
                  </div>
                  <p className="mt-4 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-muted">
                    Expires
                    <span className="mt-1 block text-mono normal-case tracking-normal text-text-secondary">{formatDateTime(enrollment.expires_at)}</span>
                  </p>
                </div>
              ) : null}
            </div>

            <div className="flex justify-end gap-2 px-6 py-4 border-t border-border bg-surface-secondary">
              {enrollment?.token ? (
                <button onClick={onClose}
                  className="px-4 py-2 text-xs font-semibold bg-accent text-white-smoke rounded-md hover:bg-accent-hover transition-colors">
                  Done
                </button>
              ) : (
                <>
                  <button onClick={onClose}
                    className="px-4 py-2 text-xs font-semibold text-text-secondary hover:text-text-primary">Cancel</button>
                  <button onClick={onCreate}
                    disabled={saving || !organization?.id || !gatewayDomain || !gatewayDNSLabel}
                    className="px-4 py-2 text-xs font-semibold bg-accent text-white-smoke rounded-md hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors inline-flex items-center gap-1.5">
                    <Router size={14} /> {saving ? 'Creating...' : 'Create Gateway'}
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
  );
}
