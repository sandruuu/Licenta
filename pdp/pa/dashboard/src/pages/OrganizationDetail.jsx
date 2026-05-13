import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Building2,
  ChevronDown,
  ChevronRight,
  Edit,
  Globe,
  Key,
  Layers3,
  ListChecks,
  Loader2,
  Plus,
  Network,
  Router,
  Server,
  Shield,
  Users,
} from 'lucide-react';
import {
  getDirectoryGroups,
  getDirectoryUsers,
  getGateways,
  getIdPs,
  getPolicyAssignments,
  getResources,
  getRules,
  getTenants,
  createIdP,
  discoverIdP,
  updateTenant,
} from '../api';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Modal from '../components/ui/Modal';
import FormField, { FormCheckbox, FormInput } from '../components/ui/FormField';
import OrganizationHierarchyFlow from '../components/organization/OrganizationHierarchyFlow';
import TenantFormModal from '../components/tenants/TenantFormModal';
import GatewayCreateModal from '../components/tenants/GatewayCreateModal';
import StatusBadge from '../components/tenants/StatusBadge';
import useGatewayCreate from '../components/tenants/useGatewayCreate';
import { actionVariant, ruleScopeMode } from '../components/policies/policyHelpers';
import { usePublicConfig } from '../config/publicConfig';

function formatDate(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString('ro-RO', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function policyMode(policy) {
  if (!policy) return 'global';
  if (policy.scope === 'resource' || policy.resource_id) return 'resource';
  if (policy.scope === 'gateway' || policy.gateway_id) return 'gateway';
  return ruleScopeMode(policy);
}

function materializePolicy(policy, assignment) {
  if (!policy || !assignment) return policy;
  return {
    ...policy,
    tenant_id: assignment.tenant_id,
    gateway_id: assignment.gateway_id || '',
    resource_id: assignment.resource_id || '',
    scope: assignment.resource_id ? 'resource' : assignment.gateway_id ? 'gateway' : 'global',
  };
}

function modeLabel(mode) {
  if (mode === 'resource') return 'Resource';
  if (mode === 'gateway') return 'Gateway';
  if (mode === 'tenant') return 'Organization';
  return 'Global';
}

function modeVariant(mode) {
  if (mode === 'resource') return 'info';
  if (mode === 'gateway') return 'accent';
  if (mode === 'tenant') return 'success';
  return 'neutral';
}

function EmptyState({ icon: Icon, title, message }) {
  return (
    <div className="py-8 text-center text-text-muted">
      <Icon size={32} className="mx-auto mb-3 opacity-35" />
      <p className="text-sm font-semibold text-text-primary">{title}</p>
      {message && <p className="mt-1 text-xs">{message}</p>}
    </div>
  );
}

function CollapsibleSection({ icon: Icon, title, subtitle, count, open, onToggle, actions, children }) {
  return (
    <section className="border-b border-border-light pb-5">
      <div className="flex items-start justify-between gap-4">
        <button
          type="button"
          onClick={onToggle}
          className="group flex min-w-0 flex-1 items-start gap-3 rounded-md bg-transparent px-0 py-0 text-left hover:text-text-primary"
        >
          <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-surface-secondary text-text-secondary group-hover:bg-[rgba(255,95,31,0.12)] group-hover:text-accent-orange">
            <Icon size={17} />
          </span>
          <span className="min-w-0">
            <span className="flex flex-wrap items-center gap-2 text-base font-semibold text-text-primary">
              {title}
              {typeof count === 'number' && <Badge variant="neutral">{count}</Badge>}
              {open ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
            </span>
            {subtitle && <span className="mt-1 block text-xs text-text-muted">{subtitle}</span>}
          </span>
        </button>
        {actions && <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">{actions}</div>}
      </div>
      {open && <div className="mt-4">{children}</div>}
    </section>
  );
}

function FieldLine({ label, value, mono = false }) {
  const displayValue = value === 0 || value === false ? String(value) : value || '-';
  return (
    <div className="min-w-0">
      <div className="text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">{label}</div>
      <div className={`mt-1 truncate text-sm font-medium text-text-primary ${mono ? 'text-mono' : ''}`}>{displayValue}</div>
    </div>
  );
}

function ClickRow({ children, onClick, className = '' }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`grid w-full items-center gap-4 rounded-md border border-border-light bg-surface-card px-4 py-3 text-left transition-colors hover:border-accent-orange hover:bg-[rgba(255,95,31,0.08)] active:bg-[rgba(255,95,31,0.14)] ${className}`}
    >
      {children}
    </button>
  );
}

function PolicyList({ policies, gatewayByID, resourceByID, emptyMessage }) {
  if (!policies.length) {
    return <EmptyState icon={Shield} title="No policies" message={emptyMessage} />;
  }

  return (
    <div className="space-y-2">
      {policies.map((policy) => {
        const mode = policyMode(policy);
        const resource = resourceByID.get(policy.resource_id);
        const gateway = gatewayByID.get(policy.gateway_id || resource?.gateway_id);
        const target = mode === 'resource'
          ? resource?.name || policy.resource_id || '-'
          : mode === 'gateway'
            ? gateway?.name || policy.gateway_id || '-'
            : 'Organization-wide';

        return (
          <div
            key={policy.id}
            className="grid gap-3 rounded-md border border-border-light bg-surface-card px-4 py-3 md:grid-cols-[1.6fr_0.8fr_1fr]"
          >
            <div className="min-w-0">
              <div className="font-semibold text-text-primary">{policy.name || '-'}</div>
              {policy.description && <div className="mt-1 text-xs text-text-muted">{policy.description}</div>}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={actionVariant(policy.action)}>{policy.action || '-'}</Badge>
              <Badge variant={modeVariant(mode)}>{modeLabel(mode)}</Badge>
            </div>
            <div className="min-w-0 text-xs text-text-muted">
              <span className="block text-[10px] font-semibold uppercase tracking-[0.08em]">Target</span>
              <span className="mt-1 block truncate font-medium text-text-secondary">{target}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default function OrganizationDetail() {
  const { organizationId = '' } = useParams();
  const organizationID = decodeURIComponent(organizationId);
  const navigate = useNavigate();
  const publicConfig = usePublicConfig();

  const [organization, setOrganization] = useState(null);
  const [gateways, setGateways] = useState([]);
  const [resources, setResources] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [policyAssignments, setPolicyAssignments] = useState([]);
  const [directoryUsers, setDirectoryUsers] = useState([]);
  const [directoryGroups, setDirectoryGroups] = useState([]);
  const [idps, setIdPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editForm, setEditForm] = useState({});
  const [editOpen, setEditOpen] = useState(false);
  const [editSaving, setEditSaving] = useState(false);
  const [idpOpen, setIdPOpen] = useState(false);
  const [idpForm, setIdPForm] = useState({});
  const [idpSaving, setIdPSaving] = useState(false);
  const [idpError, setIdPError] = useState('');
  const [idpTesting, setIdPTesting] = useState(false);
  const [idpTestResult, setIdPTestResult] = useState(null);
  const [openSections, setOpenSections] = useState({
    idp: true,
    hierarchy: true,
    gateways: false,
    resources: false,
    policies: true,
  });

  const toggleSection = (key) => {
    setOpenSections((current) => ({ ...current, [key]: !current[key] }));
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [tenantData, gatewayData, resourceData, policyData, assignmentData, userData, groupData, idpData] = await Promise.all([
        getTenants(),
        getGateways(),
        getResources(),
        getRules(),
        getPolicyAssignments(),
        getDirectoryUsers(organizationID),
        getDirectoryGroups(organizationID),
        getIdPs(organizationID),
      ]);
      const tenants = Array.isArray(tenantData) ? tenantData : [];
      setOrganization(tenants.find((tenant) => tenant.id === organizationID) || null);
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
      setResources(Array.isArray(resourceData) ? resourceData : []);
      setPolicies(Array.isArray(policyData) ? policyData : []);
      setPolicyAssignments(Array.isArray(assignmentData) ? assignmentData : []);
      setDirectoryUsers(Array.isArray(userData) ? userData : []);
      setDirectoryGroups(Array.isArray(groupData) ? groupData : []);
      setIdPs(Array.isArray(idpData) ? idpData : []);
    } catch (e) {
      setError(e.message || 'Failed to load organization data');
    } finally {
      setLoading(false);
    }
  }, [organizationID]);

  const gatewayCreate = useGatewayCreate(load);

  useEffect(() => {
    load();
  }, [load]);

  const organizationGateways = useMemo(
    () => gateways.filter((gateway) => gateway.tenant_id === organizationID || gateway.tenant_ids?.includes?.(organizationID)),
    [gateways, organizationID],
  );

  const organizationResources = useMemo(() => {
    const gatewayIDs = new Set(organizationGateways.map((gateway) => gateway.id));
    return resources.filter((resource) => resource.tenant_id === organizationID || gatewayIDs.has(resource.gateway_id));
  }, [resources, organizationID, organizationGateways]);

  const gatewayByID = useMemo(() => new Map(organizationGateways.map((gateway) => [gateway.id, gateway])), [organizationGateways]);
  const resourceByID = useMemo(() => new Map(organizationResources.map((resource) => [resource.id, resource])), [organizationResources]);
  const policyByID = useMemo(() => new Map(policies.map((policy) => [policy.id, policy])), [policies]);

  const resourcesByGatewayID = useMemo(() => {
    const map = new Map(organizationGateways.map((gateway) => [gateway.id, []]));
    organizationResources.forEach((resource) => {
      if (!map.has(resource.gateway_id)) map.set(resource.gateway_id || 'unassigned', []);
      map.get(resource.gateway_id || 'unassigned').push(resource);
    });
    return map;
  }, [organizationGateways, organizationResources]);

  const organizationPolicies = useMemo(
    () => policyAssignments
      .filter((assignment) => assignment.tenant_id === organizationID && !assignment.gateway_id && !assignment.resource_id)
      .map((assignment) => materializePolicy(policyByID.get(assignment.policy_id), assignment))
      .filter(Boolean),
    [policyAssignments, policyByID, organizationID],
  );

  const gatewayPolicyCount = useMemo(() => {
    const gatewayIDs = new Set(organizationGateways.map((gateway) => gateway.id));
    return policyAssignments.filter((assignment) => assignment.gateway_id && !assignment.resource_id && gatewayIDs.has(assignment.gateway_id)).length;
  }, [policyAssignments, organizationGateways]);

  const resourcePolicyCount = useMemo(() => {
    const resourceIDs = new Set(organizationResources.map((resource) => resource.id));
    return policyAssignments.filter((assignment) => assignment.resource_id && resourceIDs.has(assignment.resource_id)).length;
  }, [policyAssignments, organizationResources]);

  const openEdit = () => {
    setEditForm({
      ...organization,
      domains: Array.isArray(organization?.domains) ? organization.domains : [],
    });
    setEditOpen(true);
  };

  const openAddIdP = () => {
    const claimDefaults = publicConfig.oidc_default_claim_mapping || {};
    setIdPForm({
      name: '',
      type: 'oidc',
      issuer: '',
      client_id: '',
      client_secret: '',
      scim_token: '',
      scopes: publicConfig.oidc_default_scopes || 'openid profile email groups',
      enabled: true,
      auto_discovery: true,
      claim_username: claimDefaults.username || '',
      claim_email: claimDefaults.email || '',
      claim_groups: claimDefaults.groups || '',
      is_default: idps.length === 0,
    });
    setIdPError('');
    setIdPTestResult(null);
    setIdPOpen(true);
  };

  const saveIdP = async () => {
    const claimDefaults = publicConfig.oidc_default_claim_mapping || {};
    setIdPError('');
    if (!idpForm.name?.trim() || !idpForm.issuer?.trim() || !idpForm.client_id?.trim()) {
      setIdPError('Provider name, Issuer URL, and OIDC client ID are required');
      return;
    }

    setIdPSaving(true);
    try {
      await createIdP(organizationID, {
        name: idpForm.name.trim(),
        type: idpForm.type || 'oidc',
        issuer: idpForm.issuer.trim(),
        client_id: idpForm.client_id.trim(),
        client_secret: idpForm.client_secret || undefined,
        scim_token: idpForm.scim_token || undefined,
        scopes: (idpForm.scopes || '').trim(),
        enabled: idpForm.enabled !== false,
        auto_discovery: idpForm.auto_discovery !== false,
        claim_mapping: {
          username: (idpForm.claim_username || '').trim() || claimDefaults.username || '',
          email: (idpForm.claim_email || '').trim() || claimDefaults.email || '',
          groups: (idpForm.claim_groups || '').trim() || claimDefaults.groups || '',
        },
        group_role_mapping: [],
        is_default: idpForm.enabled !== false && idpForm.is_default === true,
      });
      setIdPOpen(false);
      await load();
    } catch (e) {
      setIdPError(e.message || 'Failed to add IdP');
    } finally {
      setIdPSaving(false);
    }
  };

  const testIdPDiscovery = async () => {
    setIdPError('');
    setIdPTestResult(null);
    setIdPTesting(true);
    try {
      const result = await discoverIdP((idpForm.issuer || '').trim());
      setIdPTestResult(result);
    } catch (e) {
      setIdPTestResult({ ok: false, error: e.message || 'Discovery probe failed' });
    } finally {
      setIdPTesting(false);
    }
  };

  const saveEdit = async () => {
    setEditSaving(true);
    setError('');
    try {
      await updateTenant(organizationID, {
        ...editForm,
        domains: Array.isArray(editForm.domains) ? editForm.domains : [],
      });
      setEditOpen(false);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to save organization');
    } finally {
      setEditSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="py-16 text-center text-text-muted">
        <span className="spinner mr-2" />
        Loading organization...
      </div>
    );
  }

  if (!organization) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" className="!shadow-none !px-0" onClick={() => navigate('/dashboard/organizations')}>
          <ArrowLeft size={14} />
          Organizations
        </Button>
        <EmptyState icon={Building2} title="Organization not found" message={error || 'The selected organization no longer exists.'} />
      </div>
    );
  }

  return (
    <div className="space-y-7">
      {error && (
        <div className="rounded-md border border-danger bg-danger-muted p-3 text-sm text-danger">
          {error}
        </div>
      )}

      <header className="flex flex-col gap-4 border-b border-border-light pb-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex items-start gap-3">
            <button
              type="button"
              title="Back to organizations"
              onClick={() => navigate('/dashboard/organizations')}
              className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-surface-card text-text-secondary shadow-sm transition-colors hover:border-accent-orange hover:bg-[rgba(255,95,31,0.08)] hover:text-accent-orange"
            >
              <ArrowLeft size={16} />
            </button>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-3">
                <h1 className="text-2xl font-bold leading-tight text-text-primary">{organization.name}</h1>
                <StatusBadge enabled={organization.enabled} />
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
                <span className="inline-flex items-center gap-1">
                  <Globe size={13} />
                  {organization.domain || 'No primary domain'}
                </span>
                <span className="text-mono">{organization.id}</span>
              </div>
              {organization.description && <p className="mt-4 max-w-3xl text-sm text-text-secondary">{organization.description}</p>}
            </div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 lg:justify-end">
          <Button variant="secondary" className="!shadow-none" onClick={openEdit}>
            <Edit size={14} />
            Edit Organization
          </Button>
          <Button className="!shadow-none" onClick={() => gatewayCreate.openGatewayCreate(organization)}>
            <Router size={14} />
            Create Gateway
          </Button>
        </div>
      </header>

      <CollapsibleSection
        icon={Key}
        title="IdP"
        subtitle="Identity providers and SCIM directory data for this organization"
        count={idps.length}
        open={openSections.idp}
        onToggle={() => toggleSection('idp')}
        actions={(
          <Button variant="ghost" className="!shadow-none" onClick={openAddIdP}>
            <Plus size={14} />
            Add IdP
          </Button>
        )}
      >
        {idps.length === 0 ? (
          <EmptyState icon={Key} title="No identity providers" message="Add an OIDC provider, then enable SCIM provisioning if the IdP supports it." />
        ) : (
          <div className="space-y-2">
            {idps.map((idp) => (
              <ClickRow
                key={idp.id}
                className="md:grid-cols-[1.4fr_1.8fr_0.8fr_0.8fr]"
                onClick={() => navigate(`/dashboard/organizations/${encodeURIComponent(organization.id)}/idps/${encodeURIComponent(idp.id)}`)}
              >
                <FieldLine label="Provider" value={idp.name || idp.id} />
                <FieldLine label="Issuer" value={idp.issuer} mono />
                <div className="flex items-center gap-2">
                  <Badge variant={idp.enabled === false ? 'danger' : 'success'}>{idp.enabled === false ? 'Disabled' : 'Enabled'}</Badge>
                  {idp.is_default && <Badge variant="info">Default</Badge>}
                </div>
                <FieldLine label="SCIM" value={idp.has_scim_token ? 'Enabled' : 'No token'} />
              </ClickRow>
            ))}
            <div className="pt-2 text-xs text-text-muted">
              SCIM data: {directoryUsers.length} users and {directoryGroups.length} groups synced for this organization.
            </div>
          </div>
        )}
      </CollapsibleSection>

      <CollapsibleSection
        icon={Network}
        title="Hierarchy"
        subtitle="Interactive organization map. Select any node to open its configuration page."
        count={organizationGateways.length}
        open={openSections.hierarchy}
        onToggle={() => toggleSection('hierarchy')}
      >
        <OrganizationHierarchyFlow
          organization={organization}
          gateways={organizationGateways}
          resources={organizationResources}
        />
      </CollapsibleSection>

      <CollapsibleSection
        icon={Router}
        title="Gateways"
        subtitle={`${gatewayPolicyCount} gateway-scoped policies are visible on the matching gateway detail pages.`}
        count={organizationGateways.length}
        open={openSections.gateways}
        onToggle={() => toggleSection('gateways')}
        actions={(
          <Button variant="ghost" className="!shadow-none" onClick={() => gatewayCreate.openGatewayCreate(organization)}>
            <Router size={14} />
            New Gateway
          </Button>
        )}
      >
        {organizationGateways.length === 0 ? (
          <EmptyState icon={Router} title="No gateways" message="Create the first gateway for this organization." />
        ) : (
          <div className="space-y-2">
            {organizationGateways.map((gateway) => (
              <ClickRow
                key={gateway.id}
                className="md:grid-cols-[1.4fr_1.4fr_0.8fr_0.8fr]"
                onClick={() => navigate(`/dashboard/gateways/${encodeURIComponent(gateway.id)}`)}
              >
                <FieldLine label="Gateway" value={gateway.name || gateway.id} />
                <FieldLine label="FQDN" value={gateway.fqdn} mono />
                <FieldLine label="Resources" value={(resourcesByGatewayID.get(gateway.id) || []).length} />
                <Badge variant={gateway.status === 'revoked' ? 'danger' : gateway.status === 'pending' ? 'warning' : 'success'}>
                  {gateway.status || 'active'}
                </Badge>
              </ClickRow>
            ))}
          </div>
        )}
      </CollapsibleSection>

      <CollapsibleSection
        icon={Server}
        title="Resources"
        subtitle={`${resourcePolicyCount} resource-scoped policies are visible on the matching resource detail pages.`}
        count={organizationResources.length}
        open={openSections.resources}
        onToggle={() => toggleSection('resources')}
      >
        {organizationResources.length === 0 ? (
          <EmptyState icon={Server} title="No resources" message="Attach WEB, SSH, or RDP resources after a gateway is enrolled." />
        ) : (
          <div className="space-y-2">
            {organizationResources.map((resource) => (
              <ClickRow
                key={resource.id}
                className="md:grid-cols-[1.3fr_0.7fr_1.1fr_0.8fr]"
                onClick={() => navigate(`/dashboard/resources/${encodeURIComponent(resource.id)}`)}
              >
                <FieldLine label="Resource" value={resource.name || resource.id} />
                <Badge variant="info">{(resource.type || '-').toUpperCase()}</Badge>
                <FieldLine label="Gateway" value={gatewayByID.get(resource.gateway_id)?.name || resource.gateway_id} />
                <Badge variant={resource.enabled ? 'success' : 'danger'}>{resource.enabled ? 'Enabled' : 'Disabled'}</Badge>
              </ClickRow>
            ))}
          </div>
        )}
      </CollapsibleSection>

      <CollapsibleSection
        icon={ListChecks}
        title="Policies"
        subtitle="Only organization-scoped policies are shown here. Gateway and resource policies appear on their own detail pages."
        count={organizationPolicies.length}
        open={openSections.policies}
        onToggle={() => toggleSection('policies')}
        actions={(
          <Button variant="ghost" className="!shadow-none" onClick={() => navigate(`/dashboard/policies?tenant_id=${encodeURIComponent(organization.id)}`)}>
            <Layers3 size={14} />
            Open Policies
          </Button>
        )}
      >
        <PolicyList
          policies={organizationPolicies}
          gatewayByID={gatewayByID}
          resourceByID={resourceByID}
          emptyMessage="Create organization-scoped rules from the Policies page."
        />
      </CollapsibleSection>

      <TenantFormModal
        mode={editOpen ? 'edit' : null}
        form={editForm}
        setForm={setEditForm}
        saving={editSaving}
        onClose={() => setEditOpen(false)}
        onSave={saveEdit}
      />

      {gatewayCreate.open ? (
        <GatewayCreateModal
          tenant={gatewayCreate.tenant}
          form={gatewayCreate.form}
          setForm={gatewayCreate.setForm}
          error={gatewayCreate.error}
          enrollment={gatewayCreate.enrollment}
          saving={gatewayCreate.saving}
          onClose={gatewayCreate.closeGatewayCreate}
          onCreate={gatewayCreate.handleGatewayCreate}
        />
      ) : null}

      <Modal
        open={idpOpen}
        onClose={() => setIdPOpen(false)}
        title={`Add IdP - ${organization.name}`}
        size="2xl"
        footer={(
          <>
            <Button variant="secondary" onClick={() => setIdPOpen(false)}>Cancel</Button>
            <Button onClick={saveIdP} disabled={idpSaving || !idpForm.name || !idpForm.issuer || !idpForm.client_id}>
              {idpSaving ? 'Saving...' : 'Add IdP'}
            </Button>
          </>
        )}
      >
        {idpError && <div className="rounded-md border border-danger bg-danger-muted p-3 text-xs text-danger">{idpError}</div>}

        <div className="grid gap-x-4 gap-y-1 md:grid-cols-2">
          <FormField label="Provider name" className="mb-3">
            <FormInput value={idpForm.name || ''} onChange={(event) => setIdPForm({ ...idpForm, name: event.target.value })} placeholder="Keycloak" />
          </FormField>
          <FormField label="OIDC client ID" className="mb-3">
            <FormInput value={idpForm.client_id || ''} onChange={(event) => setIdPForm({ ...idpForm, client_id: event.target.value })} placeholder="ztna-pdp" className="font-mono" />
          </FormField>
          <FormField label="Issuer URL" className="mb-3 md:col-span-2">
            <FormInput value={idpForm.issuer || ''} onChange={(event) => setIdPForm({ ...idpForm, issuer: event.target.value })} placeholder="http://keycloak.ztna.local:8080/realms/ztna-lab" className="font-mono" />
          </FormField>
          <FormField label="OIDC client secret" className="mb-3">
            <FormInput type="password" value={idpForm.client_secret || ''} onChange={(event) => setIdPForm({ ...idpForm, client_secret: event.target.value })} placeholder="Required for confidential clients" />
          </FormField>
          <FormField label="SCIM provisioning token" className="mb-3">
            <FormInput type="password" value={idpForm.scim_token || ''} onChange={(event) => setIdPForm({ ...idpForm, scim_token: event.target.value })} placeholder="Bearer token configured in the IdP" />
          </FormField>
          <FormField label="Scopes" className="mb-3 md:col-span-2">
            <FormInput value={idpForm.scopes || ''} onChange={(event) => setIdPForm({ ...idpForm, scopes: event.target.value })} className="font-mono" />
          </FormField>
        </div>

        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-y border-border-light py-3">
          <FormCheckbox id="idp-enabled" checked={idpForm.enabled !== false} onChange={(event) => setIdPForm({ ...idpForm, enabled: event.target.checked, is_default: event.target.checked ? idpForm.is_default : false })} label="Enabled" />
          <FormCheckbox id="idp-default" checked={idpForm.is_default === true} disabled={idpForm.enabled === false || idps.length === 0} onChange={(event) => setIdPForm({ ...idpForm, is_default: event.target.checked })} label="Default for organization" />
          <FormCheckbox id="idp-discovery" checked={idpForm.auto_discovery !== false} onChange={(event) => setIdPForm({ ...idpForm, auto_discovery: event.target.checked })} label="Auto-discovery" />
        </div>

        <div className="grid gap-x-4 gap-y-1 md:grid-cols-3">
          <FormField label="Username claim" className="mb-3">
            <FormInput value={idpForm.claim_username || ''} onChange={(event) => setIdPForm({ ...idpForm, claim_username: event.target.value })} className="font-mono" />
          </FormField>
          <FormField label="Email claim" className="mb-3">
            <FormInput value={idpForm.claim_email || ''} onChange={(event) => setIdPForm({ ...idpForm, claim_email: event.target.value })} className="font-mono" />
          </FormField>
          <FormField label="Groups claim" className="mb-3">
            <FormInput value={idpForm.claim_groups || ''} onChange={(event) => setIdPForm({ ...idpForm, claim_groups: event.target.value })} className="font-mono" />
          </FormField>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button variant="secondary" onClick={testIdPDiscovery} disabled={idpTesting || !idpForm.issuer?.trim()}>
            {idpTesting ? <Loader2 size={14} className="spinner-icon" /> : <Shield size={14} />}
            {idpTesting ? 'Testing...' : 'Test Discovery'}
          </Button>
          {idpTestResult && (
            <div className={`rounded-md border px-3 py-2 text-xs ${idpTestResult.ok ? 'border-success bg-success-muted text-success' : 'border-danger bg-danger-muted text-danger'}`}>
              {idpTestResult.ok ? `OK - ${idpTestResult.authorization_endpoint || 'discovery document found'}` : idpTestResult.error}
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}
