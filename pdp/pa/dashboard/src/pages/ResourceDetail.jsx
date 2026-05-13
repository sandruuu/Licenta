import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Building2,
  ChevronDown,
  ChevronRight,
  Layers3,
  ListChecks,
  Router,
  Server,
  Shield,
} from 'lucide-react';
import { getGateways, getPolicyAssignments, getResources, getRules, getTenants } from '../api';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import { actionVariant, ruleScopeMode } from '../components/policies/policyHelpers';

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

function CollapsibleSection({ icon: Icon, title, subtitle, count, open, onToggle, children }) {
  return (
    <section className="border-b border-border-light pb-5">
      <button type="button" onClick={onToggle} className="group flex w-full items-start gap-3 bg-transparent p-0 text-left">
        <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-surface-secondary text-text-secondary group-hover:bg-[rgba(255,95,31,0.12)] group-hover:text-accent-orange">
          <Icon size={17} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2 text-base font-semibold text-text-primary">
            {title}
            {typeof count === 'number' && <Badge variant="neutral">{count}</Badge>}
            {open ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
          </span>
          {subtitle && <span className="mt-1 block text-xs text-text-muted">{subtitle}</span>}
        </span>
      </button>
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

function ClickRow({ icon: Icon, label, value, hint, onClick }) {
  const displayValue = value === 0 || value === false ? String(value) : value || '-';
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-center justify-between gap-4 rounded-md border border-border-light bg-surface-card px-4 py-3 text-left transition-colors hover:border-accent-orange hover:bg-[rgba(255,95,31,0.08)] active:bg-[rgba(255,95,31,0.14)]"
    >
      <span className="flex min-w-0 items-center gap-3">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-surface-secondary text-text-secondary">
          <Icon size={16} />
        </span>
        <span className="min-w-0">
          <span className="block truncate text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">{label}</span>
          <span className="mt-1 block truncate text-sm font-semibold text-text-primary">{displayValue}</span>
          {hint && <span className="block truncate text-xs text-text-muted">{hint}</span>}
        </span>
      </span>
      <ChevronRight size={16} className="shrink-0 text-text-muted" />
    </button>
  );
}

function PolicyList({ policies, organization, gateway, resource }) {
  if (!policies.length) {
    return <EmptyState icon={Shield} title="No effective policies" message="Organization, gateway, and resource policies will appear here." />;
  }

  return (
    <div className="space-y-2">
      {policies.map((policy) => {
        const mode = policyMode(policy);
        const target = mode === 'resource'
          ? resource?.name || policy.resource_id
          : mode === 'gateway'
            ? gateway?.name || policy.gateway_id
            : organization?.name || 'Organization-wide';
        return (
          <div key={policy.id} className="grid gap-3 rounded-md border border-border-light bg-surface-card px-4 py-3 md:grid-cols-[1.6fr_0.8fr_1fr]">
            <div className="min-w-0">
              <div className="font-semibold text-text-primary">{policy.name || '-'}</div>
              {policy.description && <div className="mt-1 text-xs text-text-muted">{policy.description}</div>}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={actionVariant(policy.action)}>{policy.action || '-'}</Badge>
              <Badge variant={modeVariant(mode)}>{modeLabel(mode)}</Badge>
            </div>
            <FieldLine label="Applies to" value={target} />
          </div>
        );
      })}
    </div>
  );
}

export default function ResourceDetail() {
  const { resourceId = '' } = useParams();
  const resourceID = decodeURIComponent(resourceId);
  const navigate = useNavigate();

  const [resource, setResource] = useState(null);
  const [gateway, setGateway] = useState(null);
  const [organization, setOrganization] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [policyAssignments, setPolicyAssignments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [openSections, setOpenSections] = useState({ config: true, placement: true, policies: true });

  const toggleSection = (key) => {
    setOpenSections((current) => ({ ...current, [key]: !current[key] }));
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [resourceData, gatewayData, tenantData, policyData, assignmentData] = await Promise.all([
        getResources(),
        getGateways(),
        getTenants(),
        getRules(),
        getPolicyAssignments(),
      ]);
      const resourceList = Array.isArray(resourceData) ? resourceData : [];
      const gatewayList = Array.isArray(gatewayData) ? gatewayData : [];
      const tenants = Array.isArray(tenantData) ? tenantData : [];
      const policyList = Array.isArray(policyData) ? policyData : [];
      const selectedResource = resourceList.find((item) => item.id === resourceID) || null;
      const selectedGateway = gatewayList.find((item) => item.id === selectedResource?.gateway_id) || null;
      const organizationID = selectedResource?.tenant_id || selectedGateway?.tenant_id || selectedGateway?.tenant_ids?.[0] || '';

      setResource(selectedResource);
      setGateway(selectedGateway);
      setOrganization(tenants.find((tenant) => tenant.id === organizationID) || null);
      setPolicies(policyList);
      setPolicyAssignments(Array.isArray(assignmentData) ? assignmentData : []);
    } catch (e) {
      setError(e.message || 'Failed to load resource data');
    } finally {
      setLoading(false);
    }
  }, [resourceID]);

  useEffect(() => {
    load();
  }, [load]);

  const effectivePolicies = useMemo(() => {
    if (!resource) return [];
    const policyByID = new Map(policies.map((policy) => [policy.id, policy]));
    const organizationID = resource.tenant_id || gateway?.tenant_id || gateway?.tenant_ids?.[0] || '';
    return policyAssignments
      .filter((assignment) => (
        (assignment.tenant_id === organizationID && !assignment.gateway_id && !assignment.resource_id)
        || (assignment.gateway_id === resource.gateway_id && !assignment.resource_id)
        || assignment.resource_id === resource.id
      ))
      .map((assignment) => materializePolicy(policyByID.get(assignment.policy_id), assignment))
      .filter(Boolean);
  }, [policies, policyAssignments, resource, gateway]);

  const backTarget = gateway?.id
    ? `/dashboard/gateways/${encodeURIComponent(gateway.id)}`
    : organization?.id
      ? `/dashboard/organizations/${encodeURIComponent(organization.id)}`
      : '/dashboard/resources';

  if (loading) {
    return (
      <div className="py-16 text-center text-text-muted">
        <span className="spinner mr-2" />
        Loading resource...
      </div>
    );
  }

  if (!resource) {
    return (
      <div className="space-y-4">
        <button
          type="button"
          onClick={() => navigate('/dashboard/resources')}
          className="inline-flex items-center gap-2 rounded-md bg-transparent px-0 py-0 text-sm font-semibold text-text-secondary hover:text-accent-orange"
        >
          <ArrowLeft size={15} />
          Resources
        </button>
        <EmptyState icon={Server} title="Resource not found" message={error || 'The selected resource no longer exists.'} />
      </div>
    );
  }

  return (
    <div className="space-y-7">
      {error && <div className="rounded-md border border-danger bg-danger-muted p-3 text-sm text-danger">{error}</div>}

      <header className="flex flex-col gap-4 border-b border-border-light pb-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <button
            type="button"
            title="Back"
            onClick={() => navigate(backTarget)}
            className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-surface-card text-text-secondary shadow-sm transition-colors hover:border-accent-orange hover:bg-[rgba(255,95,31,0.08)] hover:text-accent-orange"
          >
            <ArrowLeft size={16} />
          </button>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-bold leading-tight text-text-primary">{resource.name || resource.id}</h1>
              <Badge variant="info">{(resource.type || '-').toUpperCase()}</Badge>
              <Badge variant={resource.enabled ? 'success' : 'danger'}>{resource.enabled ? 'Enabled' : 'Disabled'}</Badge>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
              <span className="inline-flex items-center gap-1">
                <Router size={13} />
                {gateway?.name || resource.gateway_id || 'No gateway'}
              </span>
              <span className="text-mono">{resource.id}</span>
            </div>
            {resource.description && <p className="mt-4 max-w-3xl text-sm text-text-secondary">{resource.description}</p>}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 lg:justify-end">
          {gateway?.id && (
            <Button variant="secondary" className="!shadow-none" onClick={() => navigate(`/dashboard/gateways/${encodeURIComponent(gateway.id)}`)}>
              <Router size={14} />
              Gateway
            </Button>
          )}
          {organization?.id && (
            <Button variant="secondary" className="!shadow-none" onClick={() => navigate(`/dashboard/organizations/${encodeURIComponent(organization.id)}`)}>
              <Building2 size={14} />
              Organization
            </Button>
          )}
        </div>
      </header>

      <CollapsibleSection
        icon={Server}
        title="Configuration"
        subtitle="Resource target, OIDC client identity, and certificate mode"
        open={openSections.config}
        onToggle={() => toggleSection('config')}
      >
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <FieldLine label="Target" value={`${resource.host || '-'}${resource.port ? `:${resource.port}` : ''}`} mono />
          <FieldLine label="External URL" value={resource.external_url} mono />
          <FieldLine label="Client ID" value={resource.client_id} mono />
          <FieldLine label="Certificate Mode" value={resource.cert_mode} />
          <FieldLine label="Certificate Domain" value={resource.cert_domain} mono />
          <FieldLine label="Certificate Expiry" value={formatDate(resource.cert_expiry)} />
        </div>
      </CollapsibleSection>

      <CollapsibleSection
        icon={Layers3}
        title="Hierarchy"
        subtitle="Where this resource sits in the organization model"
        open={openSections.placement}
        onToggle={() => toggleSection('placement')}
      >
        <div className="grid gap-3 lg:grid-cols-2">
          {organization?.id ? (
            <ClickRow
              icon={Building2}
              label="Organization"
              value={organization.name}
              hint={organization.domain || organization.id}
              onClick={() => navigate(`/dashboard/organizations/${encodeURIComponent(organization.id)}`)}
            />
          ) : (
            <div className="rounded-md border border-border-light bg-surface-card px-4 py-3 text-sm text-text-muted">No organization attached.</div>
          )}
          {gateway?.id ? (
            <ClickRow
              icon={Router}
              label="Gateway"
              value={gateway.name || gateway.id}
              hint={gateway.fqdn || gateway.id}
              onClick={() => navigate(`/dashboard/gateways/${encodeURIComponent(gateway.id)}`)}
            />
          ) : (
            <div className="rounded-md border border-border-light bg-surface-card px-4 py-3 text-sm text-text-muted">No gateway attached.</div>
          )}
        </div>
      </CollapsibleSection>

      <CollapsibleSection
        icon={ListChecks}
        title="Policies"
        subtitle="Effective policy layers: organization, gateway, and resource-scoped policies"
        count={effectivePolicies.length}
        open={openSections.policies}
        onToggle={() => toggleSection('policies')}
      >
        <PolicyList policies={effectivePolicies} organization={organization} gateway={gateway} resource={resource} />
      </CollapsibleSection>
    </div>
  );
}
