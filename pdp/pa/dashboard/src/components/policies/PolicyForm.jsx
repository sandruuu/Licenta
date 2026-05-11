import FormField, { FormCheckbox, FormInput, FormSelect } from '../ui/FormField';
import { scopeOptions } from './policyHelpers';

export default function PolicyForm({
  form,
  setForm,
  tenants,
  gateways,
  resources,
  onScopeChange,
  onTenantChange,
  onGatewayChange,
  onResourceChange,
  onConditionChange,
}) {
  const scopeMode = form.scope_mode || 'tenant';

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-x-4 gap-y-3">
        <FormField label="Scope" className="mb-0">
          <FormSelect value={scopeMode} onChange={(e) => onScopeChange(e.target.value)}>
            {scopeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </FormSelect>
        </FormField>
        {scopeMode !== 'global' && (
          <FormField label="Tenant" className="mb-0">
            <FormSelect value={form.tenant_id || ''} onChange={(e) => onTenantChange(e.target.value)}>
              <option value="">Select tenant</option>
              {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
            </FormSelect>
          </FormField>
        )}
        {(scopeMode === 'gateway' || scopeMode === 'resource') && (
          <FormField label="Gateway" className="mb-0">
            <FormSelect value={form.gateway_id || ''} onChange={(e) => onGatewayChange(e.target.value)}>
              <option value="">Select gateway</option>
              {gateways.map((gateway) => <option key={gateway.id} value={gateway.id}>{gateway.name}</option>)}
            </FormSelect>
          </FormField>
        )}
        {scopeMode === 'resource' && (
          <FormField label="Resource" className="mb-0">
            <FormSelect value={form.resource_id || ''} onChange={(e) => onResourceChange(e.target.value)}>
              <option value="">Select resource</option>
              {resources.map((resource) => <option key={resource.id} value={resource.id}>{resource.name}</option>)}
            </FormSelect>
          </FormField>
        )}

        <FormField label="Name" className="mb-0 md:col-span-2">
          <FormInput value={form.name || ''} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Allow finance RDP" />
        </FormField>
        <FormField label="Priority" className="mb-0">
          <FormInput type="number" value={form.priority ?? 100} onChange={(e) => setForm({ ...form, priority: e.target.value })} />
        </FormField>
        <FormField label="Action" className="mb-0">
          <FormSelect value={form.action || 'allow'} onChange={(e) => setForm({ ...form, action: e.target.value })}>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="mfa_required">Require MFA</option>
            <option value="restrict">Restrict</option>
          </FormSelect>
        </FormField>
        <FormField label="Description" className="mb-0 md:col-span-3">
          <FormInput value={form.description || ''} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </FormField>
        <div className="flex items-end pb-2">
          <FormCheckbox id="policy-enabled" checked={form.enabled !== false} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} label="Enabled" />
        </div>
      </div>

      <h4 className="mt-6 mb-3 text-[13px] text-text-muted uppercase tracking-[0.05em] font-semibold">Conditions</h4>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-x-4 gap-y-3">
        <FormField label="Min Health Score" className="mb-0">
          <FormInput type="number" min="0" max="100" value={form.conditions?.min_health_score ?? 0} onChange={(e) => onConditionChange('min_health_score', e.target.value)} />
        </FormField>
        <FormField label="Max Risk Score" className="mb-0">
          <FormInput type="number" min="0" max="100" value={form.conditions?.max_risk_score ?? 100} onChange={(e) => onConditionChange('max_risk_score', e.target.value)} />
        </FormField>
        <FormField label="Allowed Time Start" className="mb-0">
          <FormInput value={form.conditions?.allowed_time_start || ''} onChange={(e) => onConditionChange('allowed_time_start', e.target.value)} placeholder="08:00" />
        </FormField>
        <FormField label="Allowed Time End" className="mb-0">
          <FormInput value={form.conditions?.allowed_time_end || ''} onChange={(e) => onConditionChange('allowed_time_end', e.target.value)} placeholder="18:00" />
        </FormField>
        <FormField label="Allowed Roles" className="mb-0 md:col-span-2">
          <FormInput value={form.conditions?.allowed_roles || ''} onChange={(e) => onConditionChange('allowed_roles', e.target.value)} placeholder="admin, user" />
        </FormField>
        <FormField label="Allowed IPs" className="mb-0 md:col-span-2">
          <FormInput value={form.conditions?.allowed_ips || ''} onChange={(e) => onConditionChange('allowed_ips', e.target.value)} placeholder="10.0.0.0/8, 192.168.1.0/24" />
        </FormField>
        <FormField label="Allowed Days" className="mb-0 md:col-span-2">
          <FormInput value={form.conditions?.allowed_days || ''} onChange={(e) => onConditionChange('allowed_days', e.target.value)} placeholder="Monday, Tuesday, Wednesday" />
        </FormField>
        <FormField label="Required Health Checks" className="mb-0 md:col-span-2">
          <FormInput value={form.conditions?.required_checks || ''} onChange={(e) => onConditionChange('required_checks', e.target.value)} placeholder="firewall, antivirus, disk_encryption" />
        </FormField>
        <FormField label="Target Ports" className="mb-0 md:col-span-2">
          <FormInput value={form.conditions?.target_ports || ''} onChange={(e) => onConditionChange('target_ports', e.target.value)} placeholder="22, 443, 3389" />
        </FormField>
        {scopeMode !== 'resource' && (
          <FormField label="Target Resources" className="mb-0 md:col-span-2">
            <FormInput value={form.conditions?.target_resources || ''} onChange={(e) => onConditionChange('target_resources', e.target.value)} placeholder="resource IDs, comma-separated" />
          </FormField>
        )}
      </div>
    </>
  );
}
