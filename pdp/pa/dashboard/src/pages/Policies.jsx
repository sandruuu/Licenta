import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { X } from 'lucide-react';
import {
  createPolicyAssignment,
  createRule,
  deletePolicyAssignment,
  deleteRule,
  getDirectoryGroups,
  getDirectoryUsers,
  getGateways,
  getPolicyAssignments,
  getResources,
  getRules,
  getTenants,
  updateRule,
} from '../api';
import PageHeader from '../components/ui/PageHeader';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';
import PolicyFilters from '../components/policies/PolicyFilters';
import PolicyForm from '../components/policies/PolicyForm';
import PolicyTable from '../components/policies/PolicyTable';
import PolicyAssignmentModal from '../components/policies/PolicyAssignmentModal';
import {
  assignmentFilterOptions,
  assignmentScopeMode,
  conditionsToForm,
  createBlankConditions,
  includesText,
  splitIntList,
  splitList,
} from '../components/policies/policyHelpers';

export default function Policies() {
  const [searchParams] = useSearchParams();
  const [rules, setRules] = useState([]);
  const [assignments, setAssignments] = useState([]);
  const [tenants, setTenants] = useState([]);
  const [gateways, setGateways] = useState([]);
  const [resources, setResources] = useState([]);
  const [directoryUsers, setDirectoryUsers] = useState([]);
  const [directoryGroups, setDirectoryGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [assignmentPolicy, setAssignmentPolicy] = useState(null);
  const [assignmentForm, setAssignmentForm] = useState({});
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [assignmentSaving, setAssignmentSaving] = useState(false);
  const [error, setError] = useState('');
  const [filters, setFilters] = useState(() => {
    const scope = searchParams.get('scope');
    return {
      scope: assignmentFilterOptions.some((option) => option.value === scope) ? scope : 'all',
      tenant_id: searchParams.get('tenant_id') || '',
      gateway_id: searchParams.get('gateway_id') || '',
      resource_id: searchParams.get('resource_id') || '',
      q: '',
    };
  });

  const tenantByID = useMemo(() => new Map(tenants.map((tenant) => [tenant.id, tenant])), [tenants]);
  const gatewayByID = useMemo(() => new Map(gateways.map((gateway) => [gateway.id, gateway])), [gateways]);
  const resourceByID = useMemo(() => new Map(resources.map((resource) => [resource.id, resource])), [resources]);
  const assignmentsByPolicy = useMemo(() => {
    const map = new Map();
    assignments.forEach((assignment) => {
      if (!map.has(assignment.policy_id)) map.set(assignment.policy_id, []);
      map.get(assignment.policy_id).push(assignment);
    });
    return map;
  }, [assignments]);

  const gatewaysForTenant = (tenantID) => gateways.filter((gateway) => !tenantID || gateway.tenant_id === tenantID);
  const resourcesForTenant = (tenantID) => resources.filter((resource) => !tenantID || resource.tenant_id === tenantID);
  const resourcesForGateway = (tenantID, gatewayID) => resourcesForTenant(tenantID).filter((resource) => !gatewayID || resource.gateway_id === gatewayID);

  const filterGateways = gatewaysForTenant(filters.tenant_id);
  const filterResources = resourcesForGateway(filters.tenant_id, filters.gateway_id);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [ruleData, assignmentData, tenantData, gatewayData, resourceData, directoryUserData, directoryGroupData] = await Promise.all([
        getRules(),
        getPolicyAssignments(),
        getTenants(),
        getGateways(),
        getResources(),
        getDirectoryUsers(),
        getDirectoryGroups(),
      ]);
      setRules(Array.isArray(ruleData) ? ruleData : []);
      setAssignments(Array.isArray(assignmentData) ? assignmentData : []);
      setTenants(Array.isArray(tenantData) ? tenantData : []);
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
      setResources(Array.isArray(resourceData) ? resourceData : []);
      setDirectoryUsers(Array.isArray(directoryUserData) ? directoryUserData : []);
      setDirectoryGroups(Array.isArray(directoryGroupData) ? directoryGroupData : []);
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
    setForm({
      name: '',
      description: '',
      action: 'allow',
      priority: 100,
      enabled: true,
      conditions: createBlankConditions(),
    });
    setModal('create');
  };

  const openEdit = (rule) => {
    setForm({
      ...rule,
      tenant_id: '',
      gateway_id: '',
      resource_id: '',
      scope: 'global',
      conditions: conditionsToForm(rule.conditions),
    });
    setModal('edit');
  };

  const updateCondition = (key, value) => {
    setForm({ ...form, conditions: { ...form.conditions, [key]: value } });
  };

  const resetFilters = () => {
    setFilters({ scope: 'all', tenant_id: '', gateway_id: '', resource_id: '', q: '' });
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

  const formIsReady = () => !!form.name?.trim();

  const handleSave = async () => {
    setSaving(true);
    setError('');

    const data = {
      id: form.id,
      name: form.name?.trim(),
      description: form.description?.trim(),
      tenant_id: '',
      scope: 'global',
      gateway_id: '',
      resource_id: '',
      action: form.action || 'allow',
      priority: parseInt(form.priority, 10) || 100,
      enabled: form.enabled !== false,
      conditions: {
        min_health_score: parseInt(form.conditions?.min_health_score, 10) || 0,
        required_checks: splitList(form.conditions?.required_checks),
        allowed_roles: splitList(form.conditions?.allowed_roles),
        allowed_users: splitList(form.conditions?.allowed_users),
        allowed_groups: splitList(form.conditions?.allowed_groups),
        allowed_ips: splitList(form.conditions?.allowed_ips),
        allowed_time_start: form.conditions?.allowed_time_start || '',
        allowed_time_end: form.conditions?.allowed_time_end || '',
        allowed_days: splitList(form.conditions?.allowed_days),
        target_resources: splitList(form.conditions?.target_resources),
        target_ports: splitIntList(form.conditions?.target_ports),
        max_risk_score: parseInt(form.conditions?.max_risk_score, 10) || 100,
      },
    };

    try {
      if (modal === 'create') {
        const created = await createRule(data);
        setModal(null);
        await load();
        const createdID = created?.id || data.id;
        const createdPolicy = createdID ? { ...data, id: createdID } : null;
        if (createdPolicy) openAssign(createdPolicy);
      } else {
        await updateRule(form.id, data);
        setModal(null);
        await load();
      }
    } catch (e) {
      setError(e.message || 'Failed to save policy');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this policy and all of its assignments?')) return;
    setError('');
    try {
      await deleteRule(id);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to delete policy');
    }
  };

  const defaultAssignmentForm = (policy) => {
    const selectedResource = filters.resource_id ? resourceByID.get(filters.resource_id) : null;
    const selectedGateway = filters.gateway_id ? gatewayByID.get(filters.gateway_id) : null;
    const scope = selectedResource ? 'resource' : selectedGateway ? 'gateway' : 'tenant';
    const tenantID = selectedResource?.tenant_id || selectedGateway?.tenant_id || filters.tenant_id || tenants[0]?.id || '';
    const gatewayID = scope === 'resource'
      ? selectedResource?.gateway_id || ''
      : scope === 'gateway'
        ? selectedGateway?.id || gatewaysForTenant(tenantID)[0]?.id || ''
        : '';
    const resourceID = scope === 'resource' ? selectedResource?.id || '' : '';

    return {
      policy_id: policy?.id || '',
      scope,
      tenant_id: tenantID,
      gateway_id: gatewayID,
      resource_id: resourceID,
      enabled: true,
    };
  };

  const openAssign = (policy) => {
    setAssignmentPolicy(policy);
    setAssignmentForm(defaultAssignmentForm(policy));
  };

  const saveAssignment = async () => {
    if (!assignmentPolicy) return;
    setAssignmentSaving(true);
    setError('');
    try {
      await createPolicyAssignment({
        policy_id: assignmentPolicy.id,
        tenant_id: assignmentForm.tenant_id || '',
        gateway_id: assignmentForm.scope === 'gateway' || assignmentForm.scope === 'resource' ? assignmentForm.gateway_id || '' : '',
        resource_id: assignmentForm.scope === 'resource' ? assignmentForm.resource_id || '' : '',
        enabled: assignmentForm.enabled !== false,
      });
      await load();
      setAssignmentForm(defaultAssignmentForm(assignmentPolicy));
    } catch (e) {
      setError(e.message || 'Failed to assign policy');
    } finally {
      setAssignmentSaving(false);
    }
  };

  const removeAssignment = async (assignmentID) => {
    if (!confirm('Remove this policy assignment?')) return;
    setError('');
    try {
      await deletePolicyAssignment(assignmentID);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to remove policy assignment');
    }
  };

  const assignmentMatchesTarget = (assignment) => {
    if (!assignment) return false;
    if (filters.scope !== 'all' && filters.scope !== 'unassigned' && assignmentScopeMode(assignment) !== filters.scope) {
      return false;
    }

    const selectedResource = filters.resource_id ? resourceByID.get(filters.resource_id) : null;
    const selectedGateway = filters.gateway_id
      ? gatewayByID.get(filters.gateway_id)
      : selectedResource ? gatewayByID.get(selectedResource.gateway_id) : null;
    const selectedTenantID = filters.tenant_id || selectedResource?.tenant_id || selectedGateway?.tenant_id || '';

    if (filters.resource_id) {
      if (assignment.resource_id) return assignment.resource_id === filters.resource_id;
      if (assignment.gateway_id) return assignment.gateway_id === selectedResource?.gateway_id;
      return assignment.tenant_id === selectedResource?.tenant_id;
    }
    if (filters.gateway_id) {
      if (assignment.resource_id) return resourceByID.get(assignment.resource_id)?.gateway_id === filters.gateway_id;
      if (assignment.gateway_id) return assignment.gateway_id === filters.gateway_id;
      return assignment.tenant_id === selectedGateway?.tenant_id;
    }
    if (selectedTenantID) {
      if (assignment.resource_id) return resourceByID.get(assignment.resource_id)?.tenant_id === selectedTenantID;
      if (assignment.gateway_id) return gatewayByID.get(assignment.gateway_id)?.tenant_id === selectedTenantID;
      return assignment.tenant_id === selectedTenantID;
    }
    return true;
  };

  const assignmentSearchText = (assignment) => {
    const tenant = tenantByID.get(assignment.tenant_id);
    const gateway = gatewayByID.get(assignment.gateway_id);
    const resource = resourceByID.get(assignment.resource_id);
    return [
      assignmentScopeMode(assignment),
      tenant?.name,
      tenant?.domain,
      tenant?.id,
      gateway?.name,
      gateway?.fqdn,
      gateway?.id,
      resource?.name,
      resource?.host,
      resource?.id,
    ];
  };

  const filteredRules = useMemo(() => {
    const query = filters.q.trim().toLowerCase();
    const hasAssignmentFilters = filters.scope !== 'all' || filters.tenant_id || filters.gateway_id || filters.resource_id;

    return rules.filter((rule) => {
      const ruleAssignments = assignmentsByPolicy.get(rule.id) || [];
      if (filters.scope === 'unassigned' && ruleAssignments.length > 0) return false;
      if (filters.scope !== 'unassigned' && hasAssignmentFilters && !ruleAssignments.some(assignmentMatchesTarget)) return false;

      if (!query) return true;
      return [
        rule.name,
        rule.description,
        rule.action,
        ...(rule.conditions?.allowed_users || []),
        ...(rule.conditions?.allowed_groups || []),
        ...ruleAssignments.flatMap(assignmentSearchText),
      ].some((value) => includesText(value, query));
    });
  }, [rules, filters, assignmentsByPolicy, tenantByID, gatewayByID, resourceByID]);

  return (
    <>
      <PageHeader title="Policies" subtitle="Define reusable access rules, then assign them to organizations, gateways, or resources" createLabel="Create Policy" onCreate={openCreate} />

      {error && (
        <div className="mb-4 flex items-center justify-between rounded-md border border-danger bg-danger-muted px-4 py-3 text-sm text-danger">
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
        assignmentsByPolicy={assignmentsByPolicy}
        onEdit={openEdit}
        onAssign={openAssign}
        onDelete={handleDelete}
      />

      <Modal
        open={!!modal}
        onClose={() => setModal(null)}
        title={modal === 'create' ? 'Create Policy' : 'Edit Policy'}
        size="3xl"
        footer={(
          <>
            <Button variant="secondary" onClick={() => setModal(null)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving || !formIsReady()}>
              {saving ? 'Saving...' : modal === 'create' ? 'Create Policy' : 'Save Changes'}
            </Button>
          </>
        )}
      >
        <PolicyForm
          form={form}
          setForm={setForm}
          directoryUsers={directoryUsers}
          directoryGroups={directoryGroups}
          onConditionChange={updateCondition}
        />
      </Modal>

      <Modal
        open={!!assignmentPolicy}
        onClose={() => setAssignmentPolicy(null)}
        title="Assign Policy"
        size="3xl"
      >
        <PolicyAssignmentModal
          policy={assignmentPolicy}
          assignments={assignmentPolicy ? assignmentsByPolicy.get(assignmentPolicy.id) || [] : []}
          form={assignmentForm}
          setForm={setAssignmentForm}
          tenants={tenants}
          gateways={gateways}
          resources={resources}
          tenantByID={tenantByID}
          gatewayByID={gatewayByID}
          resourceByID={resourceByID}
          saving={assignmentSaving}
          onSave={saveAssignment}
          onDelete={removeAssignment}
        />
      </Modal>
    </>
  );
}
