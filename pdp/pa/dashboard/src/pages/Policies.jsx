import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { X } from 'lucide-react';
import { createRule, deleteRule, getGateways, getResources, getRules, getTenants, updateRule } from '../api';
import PageHeader from '../components/ui/PageHeader';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';
import PolicyFilters from '../components/policies/PolicyFilters';
import PolicyForm from '../components/policies/PolicyForm';
import PolicyTable from '../components/policies/PolicyTable';
import {
  conditionsToForm,
  createBlankConditions,
  includesText,
  ruleScopeMode,
  scopeOptions,
  splitIntList,
  splitList,
} from '../components/policies/policyHelpers';

export default function Policies() {
  const [searchParams] = useSearchParams();
  const [rules, setRules] = useState([]);
  const [tenants, setTenants] = useState([]);
  const [gateways, setGateways] = useState([]);
  const [resources, setResources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [filters, setFilters] = useState(() => {
    const scope = searchParams.get('scope');
    return {
      scope: scopeOptions.some((option) => option.value === scope) ? scope : 'all',
      tenant_id: searchParams.get('tenant_id') || '',
      gateway_id: searchParams.get('gateway_id') || '',
      resource_id: searchParams.get('resource_id') || '',
      q: '',
    };
  });

  const tenantByID = useMemo(() => new Map(tenants.map((tenant) => [tenant.id, tenant])), [tenants]);
  const gatewayByID = useMemo(() => new Map(gateways.map((gateway) => [gateway.id, gateway])), [gateways]);
  const resourceByID = useMemo(() => new Map(resources.map((resource) => [resource.id, resource])), [resources]);

  const gatewaysForTenant = (tenantID) => gateways.filter((gateway) => !tenantID || gateway.tenant_id === tenantID);
  const resourcesForTenant = (tenantID) => resources.filter((resource) => !tenantID || resource.tenant_id === tenantID);
  const resourcesForGateway = (tenantID, gatewayID) => resourcesForTenant(tenantID).filter((resource) => !gatewayID || resource.gateway_id === gatewayID);

  const filterGateways = gatewaysForTenant(filters.tenant_id);
  const filterResources = resourcesForGateway(filters.tenant_id, filters.gateway_id);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [ruleData, tenantData, gatewayData, resourceData] = await Promise.all([
        getRules(),
        getTenants(),
        getGateways(),
        getResources(),
      ]);
      setRules(Array.isArray(ruleData) ? ruleData : []);
      setTenants(Array.isArray(tenantData) ? tenantData : []);
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
      setResources(Array.isArray(resourceData) ? resourceData : []);
    } catch (e) {
      setError(e.message || 'Failed to load policy data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const openCreate = () => {
    const filteredScope = filters.scope !== 'all' ? filters.scope : 'tenant';
    const scopeMode = scopeOptions.some((option) => option.value === filteredScope) ? filteredScope : 'tenant';
    const tenantID = scopeMode === 'global' ? '' : filters.tenant_id || tenants[0]?.id || '';
    const gatewayID = scopeMode === 'gateway' || scopeMode === 'resource'
      ? filters.gateway_id || gatewaysForTenant(tenantID)[0]?.id || ''
      : '';
    const resourceID = scopeMode === 'resource'
      ? filters.resource_id || resourcesForGateway(tenantID, gatewayID)[0]?.id || ''
      : '';
    const selectedResource = resourceByID.get(resourceID);

    setForm({
      name: '',
      description: '',
      tenant_id: tenantID,
      scope_mode: scopeMode,
      scope: scopeMode === 'gateway' || scopeMode === 'resource' ? scopeMode : 'global',
      gateway_id: gatewayID,
      resource_id: resourceID,
      action: 'allow',
      priority: 100,
      enabled: true,
      conditions: createBlankConditions({
        target_resources: resourceID,
        target_ports: selectedResource?.port ? String(selectedResource.port) : '',
      }),
    });
    setModal('create');
  };

  const openEdit = (rule) => {
    setForm({
      ...rule,
      scope_mode: ruleScopeMode(rule),
      scope: rule.scope || 'global',
      conditions: conditionsToForm(rule.conditions),
    });
    setModal('edit');
  };

  const updateCondition = (key, value) => {
    setForm({ ...form, conditions: { ...form.conditions, [key]: value } });
  };

  const setFilterTenant = (tenantID) => {
    setFilters({ ...filters, tenant_id: tenantID, gateway_id: '', resource_id: '' });
  };

  const setFilterGateway = (gatewayID) => {
    const gateway = gatewayByID.get(gatewayID);
    setFilters({
      ...filters,
      tenant_id: gateway?.tenant_id || filters.tenant_id,
      gateway_id: gatewayID,
      resource_id: '',
    });
  };

  const setFilterResource = (resourceID) => {
    const resource = resourceByID.get(resourceID);
    setFilters({
      ...filters,
      tenant_id: resource?.tenant_id || filters.tenant_id,
      gateway_id: resource?.gateway_id || filters.gateway_id,
      resource_id: resourceID,
    });
  };

  const resetFilters = () => {
    setFilters({ scope: 'all', tenant_id: '', gateway_id: '', resource_id: '', q: '' });
  };

  const selectScopeMode = (scopeMode) => {
    if (scopeMode === 'global') {
      setForm({ ...form, scope_mode: scopeMode, tenant_id: '', gateway_id: '', resource_id: '' });
      return;
    }

    const tenantID = form.tenant_id || tenants[0]?.id || '';
    const gatewayID = scopeMode === 'gateway' || scopeMode === 'resource'
      ? form.gateway_id || gatewaysForTenant(tenantID)[0]?.id || ''
      : '';
    const resourceID = scopeMode === 'resource'
      ? form.resource_id || resourcesForGateway(tenantID, gatewayID)[0]?.id || ''
      : '';

    setForm({
      ...form,
      scope_mode: scopeMode,
      tenant_id: tenantID,
      gateway_id: gatewayID,
      resource_id: resourceID,
    });
  };

  const selectTenant = (tenantID) => {
    const scopeMode = form.scope_mode || 'tenant';
    const gatewayID = scopeMode === 'gateway' || scopeMode === 'resource'
      ? gatewaysForTenant(tenantID)[0]?.id || ''
      : '';
    const resourceID = scopeMode === 'resource' && gatewayID
      ? resourcesForGateway(tenantID, gatewayID)[0]?.id || ''
      : '';
    setForm({ ...form, tenant_id: tenantID, gateway_id: gatewayID, resource_id: resourceID });
  };

  const selectGateway = (gatewayID) => {
    const gateway = gatewayByID.get(gatewayID);
    const tenantID = gateway?.tenant_id || form.tenant_id || '';
    const resourceID = form.scope_mode === 'resource' && gatewayID
      ? resourcesForGateway(tenantID, gatewayID)[0]?.id || ''
      : '';
    setForm({ ...form, tenant_id: tenantID, gateway_id: gatewayID, resource_id: resourceID });
  };

  const selectResource = (resourceID) => {
    const resource = resourceByID.get(resourceID);
    setForm({
      ...form,
      tenant_id: resource?.tenant_id || form.tenant_id || '',
      gateway_id: resource?.gateway_id || form.gateway_id || '',
      resource_id: resourceID,
      conditions: {
        ...form.conditions,
        target_resources: resourceID,
        target_ports: resource?.port ? String(resource.port) : form.conditions?.target_ports || '',
      },
    });
  };

  const formIsReady = () => {
    if (!form.name?.trim()) return false;
    switch (form.scope_mode) {
      case 'global':
        return true;
      case 'tenant':
        return !!form.tenant_id;
      case 'gateway':
        return !!form.tenant_id && !!form.gateway_id;
      case 'resource':
        return !!form.tenant_id && !!form.gateway_id && !!form.resource_id;
      default:
        return false;
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');

    const scopeMode = form.scope_mode || 'tenant';
    const backendScope = scopeMode === 'gateway' || scopeMode === 'resource' ? scopeMode : 'global';
    const selectedResource = resourceByID.get(form.resource_id);
    const targetResources = scopeMode === 'resource' && form.resource_id
      ? [form.resource_id]
      : splitList(form.conditions?.target_resources);

    const data = {
      id: form.id,
      name: form.name?.trim(),
      description: form.description?.trim(),
      tenant_id: scopeMode === 'global' ? '' : form.tenant_id || '',
      scope: backendScope,
      gateway_id: scopeMode === 'gateway' || scopeMode === 'resource'
        ? form.gateway_id || selectedResource?.gateway_id || ''
        : '',
      resource_id: scopeMode === 'resource' ? form.resource_id || '' : '',
      action: form.action || 'allow',
      priority: parseInt(form.priority, 10) || 100,
      enabled: form.enabled !== false,
      conditions: {
        min_health_score: parseInt(form.conditions?.min_health_score, 10) || 0,
        required_checks: splitList(form.conditions?.required_checks),
        allowed_roles: splitList(form.conditions?.allowed_roles),
        allowed_ips: splitList(form.conditions?.allowed_ips),
        allowed_time_start: form.conditions?.allowed_time_start || '',
        allowed_time_end: form.conditions?.allowed_time_end || '',
        allowed_days: splitList(form.conditions?.allowed_days),
        target_resources: targetResources,
        target_ports: splitIntList(form.conditions?.target_ports),
        max_risk_score: parseInt(form.conditions?.max_risk_score, 10) || 100,
      },
    };

    try {
      if (modal === 'create') {
        await createRule(data);
      } else {
        await updateRule(form.id, data);
      }
      setModal(null);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to save rule');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this policy rule?')) return;
    setError('');
    try {
      await deleteRule(id);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to delete rule');
    }
  };

  const filteredRules = useMemo(() => {
    const query = filters.q.trim().toLowerCase();
    const selectedResource = filters.resource_id ? resourceByID.get(filters.resource_id) : null;
    const selectedGateway = filters.gateway_id
      ? gatewayByID.get(filters.gateway_id)
      : selectedResource ? gatewayByID.get(selectedResource.gateway_id) : null;
    const selectedTenantID = filters.tenant_id || selectedResource?.tenant_id || selectedGateway?.tenant_id || '';

    return rules.filter((rule) => {
      const mode = ruleScopeMode(rule);
      const resource = resourceByID.get(rule.resource_id);
      const gateway = gatewayByID.get(rule.gateway_id || resource?.gateway_id);
      const tenant = tenantByID.get(rule.tenant_id || resource?.tenant_id || gateway?.tenant_id);
      const effectiveTenantID = rule.tenant_id || resource?.tenant_id || gateway?.tenant_id || '';
      const effectiveGatewayID = rule.gateway_id || resource?.gateway_id || '';

      if (filters.scope !== 'all' && mode !== filters.scope) return false;

      if (filters.resource_id) {
        if (mode === 'resource' && rule.resource_id !== filters.resource_id) return false;
        if (mode === 'gateway' && effectiveGatewayID !== selectedResource?.gateway_id) return false;
        if (mode === 'tenant' && effectiveTenantID !== selectedResource?.tenant_id) return false;
      } else if (filters.gateway_id) {
        if (mode === 'resource' && resource?.gateway_id !== filters.gateway_id) return false;
        if (mode === 'gateway' && effectiveGatewayID !== filters.gateway_id) return false;
        if (mode === 'tenant' && effectiveTenantID !== selectedGateway?.tenant_id) return false;
      } else if (selectedTenantID) {
        if (mode !== 'global' && effectiveTenantID !== selectedTenantID) return false;
      }

      if (!query) return true;

      return [
        rule.name,
        rule.description,
        rule.action,
        mode,
        tenant?.name,
        tenant?.domain,
        tenant?.id,
        gateway?.name,
        gateway?.fqdn,
        gateway?.id,
        resource?.name,
        resource?.host,
        resource?.id,
      ].some((value) => includesText(value, query));
    });
  }, [rules, filters, tenantByID, gatewayByID, resourceByID]);

  return (
    <>
      <PageHeader title="Policies" subtitle="Scope access rules globally or per tenant, gateway, and resource" createLabel="Add Rule" onCreate={openCreate} />

      {error && (
        <div className="flex items-center justify-between px-4 py-3 mb-4 bg-danger-muted border border-danger rounded-md text-danger text-sm">
          <span>{error}</span>
          <Button variant="ghost" className="!p-1 !shadow-none" onClick={() => setError('')}><X size={14} /></Button>
        </div>
      )}

      <PolicyFilters
        filters={filters}
        tenants={tenants}
        gateways={filterGateways}
        resources={filterResources}
        resultCount={filteredRules.length}
        totalCount={rules.length}
        onScopeChange={(scope) => setFilters({ ...filters, scope })}
        onTenantChange={setFilterTenant}
        onGatewayChange={setFilterGateway}
        onResourceChange={setFilterResource}
        onSearchChange={(q) => setFilters({ ...filters, q })}
        onClear={resetFilters}
      />

      <PolicyTable
        policies={filteredRules}
        loading={loading}
        tenantByID={tenantByID}
        gatewayByID={gatewayByID}
        resourceByID={resourceByID}
        onEdit={openEdit}
        onDelete={handleDelete}
      />

      <Modal
        open={!!modal}
        onClose={() => setModal(null)}
        title={modal === 'create' ? 'Add Policy Rule' : 'Edit Policy Rule'}
        size="3xl"
        footer={
          <>
            <Button variant="secondary" onClick={() => setModal(null)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving || !formIsReady()}>
              {saving ? 'Saving...' : modal === 'create' ? 'Create Rule' : 'Save Changes'}
            </Button>
          </>
        }
      >
        <PolicyForm
          form={form}
          setForm={setForm}
          tenants={tenants}
          gateways={gatewaysForTenant(form.tenant_id)}
          resources={resourcesForGateway(form.tenant_id, form.gateway_id)}
          onScopeChange={selectScopeMode}
          onTenantChange={selectTenant}
          onGatewayChange={selectGateway}
          onResourceChange={selectResource}
          onConditionChange={updateCondition}
        />
      </Modal>
    </>
  );
}
