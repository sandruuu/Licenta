import Button from '../ui/Button';
import FormField, { FormInput, FormSelect } from '../ui/FormField';
import { assignmentFilterOptions } from './policyHelpers';

export default function PolicyFilters({
  filters,
  tenants,
  gateways,
  resources,
  resultCount,
  totalCount,
  onScopeChange,
  onTenantChange,
  onGatewayChange,
  onResourceChange,
  onSearchChange,
  onClear,
}) {
  return (
    <div className="bg-surface-card border border-border rounded-md shadow-[0_1px_3px_rgba(0,0,0,0.06)] p-4 mb-4">
      <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
        <FormField label="Assignment" className="mb-0 md:col-span-2">
          <FormSelect value={filters.scope} onChange={(e) => onScopeChange(e.target.value)}>
            {assignmentFilterOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </FormSelect>
        </FormField>
        <FormField label="Organization" className="mb-0 md:col-span-2">
          <FormSelect value={filters.tenant_id} onChange={(e) => onTenantChange(e.target.value)}>
            <option value="">All organizations</option>
            {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
          </FormSelect>
        </FormField>
        <FormField label="Gateway" className="mb-0 md:col-span-2">
          <FormSelect value={filters.gateway_id} onChange={(e) => onGatewayChange(e.target.value)}>
            <option value="">All gateways</option>
            {gateways.map((gateway) => <option key={gateway.id} value={gateway.id}>{gateway.name}</option>)}
          </FormSelect>
        </FormField>
        <FormField label="Resource" className="mb-0 md:col-span-2">
          <FormSelect value={filters.resource_id} onChange={(e) => onResourceChange(e.target.value)}>
            <option value="">All resources</option>
            {resources.map((resource) => <option key={resource.id} value={resource.id}>{resource.name}</option>)}
          </FormSelect>
        </FormField>
        <FormField label="Search" className="mb-0 md:col-span-3">
          <FormInput value={filters.q} onChange={(e) => onSearchChange(e.target.value)} placeholder="policy, organization, gateway, resource" />
        </FormField>
        <div className="md:col-span-1">
          <Button variant="secondary" className="w-full justify-center" onClick={onClear}>Clear</Button>
        </div>
      </div>
      <div className="mt-3 text-[11px] text-text-muted">
        {resultCount} of {totalCount} policies
      </div>
    </div>
  );
}
