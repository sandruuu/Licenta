import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Building2,
  ChevronDown,
  ChevronRight,
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
  if (mode === 'gateway') return 'Gateway';
  if (mode === 'tenant') return 'Organization';
  if (mode === 'resource') return 'Resource';
  return 'Global';
}

function modeVariant(mode) {
  if (mode === 'gateway') return 'accent';
  if (mode === 'tenant') return 'success';
  if (mode === 'resource') return 'info';
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

function PolicyList({ policies, organization, gateway }) {
  if (!policies.length) {
    return <EmptyState icon={Shield} title="No effective policies" message="Organization and gateway-scoped policies will appear here." />;
  }

  return (
    <div className="space-y-2">
      {policies.map((policy) => {
        const mode = policyMode(policy);
        const target = mode === 'gateway' ? gateway?.name || policy.gateway_id : organization?.name || 'Organization-wide';
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

export default function GatewayDetail() {
  const { gatewayId = '' } = useParams();
  const gatewayID = decodeURIComponent(gatewayId);
  const navigate = useNavigate();

  const [gateway, setGateway] = useState(null);
  const [organization, setOrganization] = useState(null);
  const [resources, setResources] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [policyAssignments, setPolicyAssignments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [openSections, setOpenSections] = useState({ config: true, resources: true, policies: true });

  const toggleSection = (key) => {
    setOpenSections((current) => ({ ...current, [key]: !current[key] }));
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [gatewayData, resourceData, policyData, assignmentData, tenantData] = await Promise.all([
        getGateways(),
        getResources(),
        getRules(),
        getPolicyAssignments(),
        getTenants(),
      ]);
      const gatewayList = Array.isArray(gatewayData) ? gatewayData : [];
      const resourceList = Array.isArray(resourceData) ? resourceData : [];
      const policyList = Array.isArray(policyData) ? policyData : [];
      const tenants = Array.isArray(tenantData) ? tenantData : [];
      const selectedGateway = gatewayList.find((item) => item.id === gatewayID) || null;
      const organizationID = selectedGateway?.tenant_id || selectedGateway?.tenant_ids?.[0] || '';

      setGateway(selectedGateway);
      setOrganization(tenants.find((tenant) => tenant.id === organizationID) || null);
      setResources(resourceList.filter((resource) => resource.gateway_id === gatewayID));
      setPolicies(policyList);
      setPolicyAssignments(Array.isArray(assignmentData) ? assignmentData : []);
    } catch (e) {
      setError(e.message || 'Failed to load gateway data');
    } finally {
      setLoading(false);
    }
  }, [gatewayID]);

  useEffect(() => {
    load();
  }, [load]);

  const effectivePolicies = useMemo(() => {
    if (!gateway) return [];
    const policyByID = new Map(policies.map((policy) => [policy.id, policy]));
    const organizationID = gateway.tenant_id || gateway.tenant_ids?.[0] || '';
    return policyAssignments
      .filter((assignment) => (
        (assignment.tenant_id === organizationID && !assignment.gateway_id && !assignment.resource_id)
        || (assignment.gateway_id === gateway.id && !assignment.resource_id)
      ))
      .map((assignment) => materializePolicy(policyByID.get(assignment.policy_id), assignment))
      .filter(Boolean);
  }, [policies, policyAssignments, gateway]);

  const backTarget = organization?.id
    ? `/dashboard/organizations/${encodeURIComponent(organization.id)}`
    : '/dashboard/gateways';

  if (loading) {
    return (
      <div className="py-16 text-center text-text-muted">
        <span className="spinner mr-2" />
        Loading gateway...
      </div>
    );
  }

  if (!gateway) {
    return (
      <div className="space-y-4">
        <button
          type="button"
          onClick={() => navigate('/dashboard/gateways')}
          className="inline-flex items-center gap-2 rounded-md bg-transparent px-0 py-0 text-sm font-semibold text-text-secondary hover:text-accent-orange"
        >
          <ArrowLeft size={15} />
          Gateways
        </button>
        <EmptyState icon={Router} title="Gateway not found" message={error || 'The selected gateway no longer exists.'} />
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
              <h1 className="text-2xl font-bold leading-tight text-text-primary">{gateway.name || gateway.id}</h1>
              <Badge variant={gateway.status === 'revoked' ? 'danger' : gateway.status === 'pending' ? 'warning' : 'success'}>
                {gateway.status || 'active'}
              </Badge>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
              <span className="inline-flex items-center gap-1">
                <Building2 size={13} />
                {organization?.name || gateway.tenant_id || 'Unassigned'}
              </span>
              <span className="text-mono">{gateway.id}</span>
            </div>
          </div>
        </div>
        {organization?.id && (
          <Button variant="secondary" className="!shadow-none" onClick={() => navigate(`/dashboard/organizations/${encodeURIComponent(organization.id)}`)}>
            <Building2 size={14} />
            Organization
          </Button>
        )}
      </header>

      <CollapsibleSection
        icon={Router}
        title="Configuration"
        subtitle="Gateway enrollment, network identity, and runtime metadata"
        open={openSections.config}
        onToggle={() => toggleSection('config')}
      >
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <FieldLine label="FQDN" value={gateway.fqdn} mono />
          <FieldLine label="Public IP" value={gateway.public_ip} mono />
          <FieldLine label="Listen Address" value={gateway.listen_addr} mono />
          <FieldLine label="Auth Mode" value={gateway.auth_mode || 'tenant-idp'} />
          <FieldLine label="Certificate Expires" value={formatDate(gateway.cert_expires_at)} />
          <FieldLine label="Last Seen" value={formatDate(gateway.last_seen_at)} />
        </div>
      </CollapsibleSection>

      <CollapsibleSection
        icon={Server}
        title="Resources"
        subtitle="Protected targets attached to this gateway"
        count={resources.length}
        open={openSections.resources}
        onToggle={() => toggleSection('resources')}
      >
        {resources.length === 0 ? (
          <EmptyState icon={Server} title="No resources" message="Attach resources to this gateway from the Resources page." />
        ) : (
          <div className="space-y-2">
            {resources.map((resource) => (
              <ClickRow
                key={resource.id}
                className="md:grid-cols-[1.3fr_0.7fr_1.2fr_0.8fr]"
                onClick={() => navigate(`/dashboard/resources/${encodeURIComponent(resource.id)}`)}
              >
                <FieldLine label="Resource" value={resource.name || resource.id} />
                <Badge variant="info">{(resource.type || '-').toUpperCase()}</Badge>
                <FieldLine label="Target" value={`${resource.host || '-'}${resource.port ? `:${resource.port}` : ''}`} mono />
                <Badge variant={resource.enabled ? 'success' : 'danger'}>{resource.enabled ? 'Enabled' : 'Disabled'}</Badge>
              </ClickRow>
            ))}
          </div>
        )}
      </CollapsibleSection>

      <CollapsibleSection
        icon={ListChecks}
        title="Policies"
        subtitle="Effective policy layers: organization policies plus gateway-scoped policies"
        count={effectivePolicies.length}
        open={openSections.policies}
        onToggle={() => toggleSection('policies')}
      >
        <PolicyList policies={effectivePolicies} organization={organization} gateway={gateway} />
      </CollapsibleSection>
    </div>
  );
}
