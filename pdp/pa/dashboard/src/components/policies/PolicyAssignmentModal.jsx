import { Link2, Trash2 } from 'lucide-react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import FormField, { FormCheckbox, FormSelect } from '../ui/FormField';
import { assignmentScopeLabel, assignmentScopeVariant, scopeOptions } from './policyHelpers';

export default function PolicyAssignmentModal({
  policy,
  assignments,
  form,
  setForm,
  tenants,
  gateways,
  resources,
  tenantByID,
  gatewayByID,
  resourceByID,
  saving,
  onSave,
  onDelete,
}) {
  const scope = form.scope || 'tenant';
  const gatewaysForTenant = gateways.filter((gateway) => !form.tenant_id || gateway.tenant_id === form.tenant_id);
  const resourcesForTenant = resources.filter((resource) => !form.tenant_id || resource.tenant_id === form.tenant_id);
  const resourcesForGateway = resourcesForTenant.filter((resource) => !form.gateway_id || resource.gateway_id === form.gateway_id);

  const selectScope = (nextScope) => {
    setForm({
      ...form,
      scope: nextScope,
      gateway_id: nextScope === 'gateway' || nextScope === 'resource' ? form.gateway_id : '',
      resource_id: nextScope === 'resource' ? form.resource_id : '',
    });
  };

  const selectTenant = (tenantID) => {
    setForm({
      ...form,
      tenant_id: tenantID,
      gateway_id: '',
      resource_id: '',
    });
  };

  const selectGateway = (gatewayID) => {
    const gateway = gatewayByID.get(gatewayID);
    setForm({
      ...form,
      tenant_id: gateway?.tenant_id || form.tenant_id,
      gateway_id: gatewayID,
      resource_id: '',
    });
  };

  const selectResource = (resourceID) => {
    const resource = resourceByID.get(resourceID);
    setForm({
      ...form,
      tenant_id: resource?.tenant_id || form.tenant_id,
      gateway_id: resource?.gateway_id || form.gateway_id,
      resource_id: resourceID,
    });
  };

  const assignmentTarget = (assignment) => {
    if (assignment.resource_id) return resourceByID.get(assignment.resource_id)?.name || assignment.resource_id;
    if (assignment.gateway_id) return gatewayByID.get(assignment.gateway_id)?.name || assignment.gateway_id;
    return tenantByID.get(assignment.tenant_id)?.name || assignment.tenant_id || '-';
  };

  const ready = form.tenant_id
    && (scope !== 'gateway' || form.gateway_id)
    && (scope !== 'resource' || form.resource_id);

  return (
    <div className="space-y-5">
      <div className="rounded-md border border-border-light bg-surface-secondary px-4 py-3">
        <div className="text-xs font-semibold text-text-primary">{policy?.name}</div>
        {policy?.description && <div className="mt-1 text-xs text-text-muted">{policy.description}</div>}
      </div>

      <section>
        <div className="mb-3 flex items-center justify-between gap-3">
          <h4 className="text-[13px] font-semibold uppercase tracking-[0.05em] text-text-muted">Current assignments</h4>
          <Badge variant={assignments.length ? 'success' : 'neutral'}>{assignments.length || 'Unassigned'}</Badge>
        </div>
        {assignments.length === 0 ? (
          <div className="rounded-md border border-dashed border-border p-5 text-center text-sm text-text-muted">
            This policy is not applied anywhere yet.
          </div>
        ) : (
          <div className="space-y-2">
            {assignments.map((assignment) => (
              <div key={assignment.id} className="flex items-center justify-between gap-4 rounded-md border border-border bg-surface-card px-4 py-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={assignmentScopeVariant(assignment)}>{assignmentScopeLabel(assignment)}</Badge>
                    <Badge variant={assignment.enabled !== false ? 'success' : 'warning'}>{assignment.enabled !== false ? 'Active' : 'Disabled'}</Badge>
                  </div>
                  <div className="mt-1 truncate text-sm font-semibold text-text-primary">{assignmentTarget(assignment)}</div>
                </div>
                <Button variant="ghost" className="!p-1.5 !shadow-none !text-danger hover:!bg-danger-muted" onClick={() => onDelete(assignment.id)} title="Remove assignment">
                  <Trash2 size={14} />
                </Button>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="border-t border-border-light pt-4">
        <h4 className="mb-3 text-[13px] font-semibold uppercase tracking-[0.05em] text-text-muted">Add assignment</h4>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
          <FormField label="Scope" className="mb-0">
            <FormSelect value={scope} onChange={(event) => selectScope(event.target.value)}>
              {scopeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </FormSelect>
          </FormField>
          <FormField label="Organization" className="mb-0">
            <FormSelect value={form.tenant_id || ''} onChange={(event) => selectTenant(event.target.value)}>
              <option value="">Select organization</option>
              {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
            </FormSelect>
          </FormField>
          {(scope === 'gateway' || scope === 'resource') && (
            <FormField label="Gateway" className="mb-0">
              <FormSelect value={form.gateway_id || ''} onChange={(event) => selectGateway(event.target.value)}>
                <option value="">Select gateway</option>
                {gatewaysForTenant.map((gateway) => <option key={gateway.id} value={gateway.id}>{gateway.name}</option>)}
              </FormSelect>
            </FormField>
          )}
          {scope === 'resource' && (
            <FormField label="Resource" className="mb-0">
              <FormSelect value={form.resource_id || ''} onChange={(event) => selectResource(event.target.value)}>
                <option value="">Select resource</option>
                {resourcesForGateway.map((resource) => <option key={resource.id} value={resource.id}>{resource.name}</option>)}
              </FormSelect>
            </FormField>
          )}
        </div>
        <div className="mt-4 flex items-center justify-between gap-3">
          <FormCheckbox id="assignment-enabled" checked={form.enabled !== false} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} label="Enabled" />
          <Button onClick={onSave} disabled={saving || !ready}>
            <Link2 size={14} />
            {saving ? 'Assigning...' : 'Assign Policy'}
          </Button>
        </div>
      </section>
    </div>
  );
}
