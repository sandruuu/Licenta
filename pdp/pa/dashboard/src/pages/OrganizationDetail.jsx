import { useCallback, useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  AlertCircle,
  ArrowLeft,
  Ban,
  Building2,
  ChevronLeft,
  ChevronRight,
  Plus,
  Edit2,
} from 'lucide-react';
import {
  getGateways,
  getIdPs,
  getDirectoryGroups,
  getDirectoryUsers,
  getResources,
  getOrganizations,
  createIdP,
  createResource,
  discoverIdP,
  updateOrganization,
} from '../api';
import Button from '../components/ui/Button';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import PageLoading from '../components/ui/PageLoading';
import {
  DetailDisclosure,
  DetailEmptyState as EmptyState,
  InlineBackButton,
} from '../components/ui/Detail';
import Modal from '../components/ui/Modal';
import FormField, { FormCheckbox, FormInput, FormSelect } from '../components/ui/FormField';
import StatusText from '../components/ui/StatusText';
import ConfirmDialog from '../components/ui/ConfirmDialog';
import OrganizationHierarchyFlow from '../components/organization/OrganizationHierarchyFlow';
import OrganizationFormModal from '../components/organizations/OrganizationFormModal';
import GatewayCreateModal from '../components/organizations/GatewayCreateModal';
import GatewayTokenModal from '../components/organizations/GatewayTokenModal';
import StatusBadge from '../components/organizations/StatusBadge';
import useGatewayCreate from '../components/organizations/useGatewayCreate';
import { usePublicConfig } from '../config/publicConfig';
import { navigateBack, navigateWithReturn } from '../utils/navigation';

const detailPanelClass = 'rounded-md border border-border bg-transparent';
const summaryItemClass = 'block w-full rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-4 py-4 text-left shadow-[0_8px_16px_rgba(42,42,42,0.12)] transition-[border-color,background-color,box-shadow] duration-150 hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.14)]';
const relatedSectionTitleClass = 'text-[20px] font-bold leading-tight text-text-primary';
const relatedSectionCountClass = 'text-sm font-bold text-text-muted';
const resourceTypeOptions = [
  { value: 'web', label: 'WEB' },
  { value: 'ssh', label: 'SSH' },
  { value: 'rdp', label: 'RDP' },
];

function externalHost(resource) {
  return resource?.external_url || resource?.host || '';
}

function endpointLabel(host, port) {
  const base = host || '-';
  return port ? `${base}:${port}` : base;
}

function resourceExternalPort(resource) {
  return resource?.external_port || '';
}

function resourceInternalPort(resource) {
  return resource?.internal_port || '';
}

function resourceProtocolLabel(resource) {
  const type = String(resource?.type || 'resource').toUpperCase();
  return `${type} - ${endpointLabel(resource?.host, resourceInternalPort(resource))}`;
}

function resourceTargetLabel(resource) {
  return endpointLabel(externalHost(resource), resourceExternalPort(resource));
}

export default function OrganizationDetail() {
  const { organizationId = '' } = useParams();
  const organizationID = decodeURIComponent(organizationId);
  const navigate = useNavigate();
  const location = useLocation();
  const publicConfig = usePublicConfig();

  const [organization, setOrganization] = useState(null);
  const [gateways, setGateways] = useState([]);
  const [resources, setResources] = useState([]);
  const [idps, setIdPs] = useState([]);
  const [directoryUsers, setDirectoryUsers] = useState([]);
  const [directoryGroups, setDirectoryGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editForm, setEditForm] = useState({});
  const [editOpen, setEditOpen] = useState(false);
  const [editSaving, setEditSaving] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [idpOpen, setIdPOpen] = useState(false);
  const [idpForm, setIdPForm] = useState({});
  const [idpSaving, setIdPSaving] = useState(false);
  const [idpError, setIdPError] = useState('');
  const [idpTesting, setIdPTesting] = useState(false);
  const [idpTestResult, setIdPTestResult] = useState(null);
  const [idpAdvancedOpen, setIdPAdvancedOpen] = useState(false);
  const [idpScimOpen, setIdPScimOpen] = useState(false);
  const [scimTokenModal, setScimTokenModal] = useState(null);
  const [resourceOpen, setResourceOpen] = useState(false);
  const [resourceForm, setResourceForm] = useState({});
  const [resourceSaving, setResourceSaving] = useState(false);
  const [resourceError, setResourceError] = useState('');

  const load = useCallback(async ({ showLoading = true } = {}) => {
    if (showLoading) {
      setLoading(true);
    }
    setError('');
    try {
      const [organizationData, gatewayData, resourceData, idpData, directoryUserData, directoryGroupData] = await Promise.all([
        getOrganizations(),
        getGateways(),
        getResources(),
        getIdPs(organizationID),
        getDirectoryUsers(organizationID).catch(() => []),
        getDirectoryGroups(organizationID).catch(() => []),
      ]);
      const organizations = Array.isArray(organizationData) ? organizationData : [];
      setOrganization(organizations.find((item) => item.id === organizationID) || null);
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
      setResources(Array.isArray(resourceData) ? resourceData : []);
      setIdPs(Array.isArray(idpData) ? idpData : []);
      setDirectoryUsers(Array.isArray(directoryUserData) ? directoryUserData : []);
      setDirectoryGroups(Array.isArray(directoryGroupData) ? directoryGroupData : []);
    } catch (e) {
      setError(e.message || 'Failed to load organization data');
    } finally {
      if (showLoading) {
        setLoading(false);
      }
    }
  }, [organizationID]);

  const gatewayCreate = useGatewayCreate(load);

  useEffect(() => {
    load();
  }, [load]);

  const organizationGateways = useMemo(
    () => gateways.filter((gateway) => gateway.organization_id === organizationID || gateway.organization_ids?.includes?.(organizationID)),
    [gateways, organizationID],
  );

  const organizationResources = useMemo(() => {
    const gatewayIDs = new Set(organizationGateways.map((gateway) => gateway.id));
    return resources.filter((resource) => resource.organization_id === organizationID || gatewayIDs.has(resource.gateway_id));
  }, [resources, organizationID, organizationGateways]);

  const configuredIdP = idps[0] || null;
  const resourceTypes = useMemo(() => resourceTypeOptions.map((item) => ({
    ...item,
    defaultPort: publicConfig.resource_default_ports?.[item.value] || 0,
  })), [publicConfig.resource_default_ports]);

  const openEdit = () => {
    setEditForm({
      ...organization,
      domains: Array.isArray(organization?.domains) ? organization.domains : [],
    });
    setEditOpen(true);
  };

  const openAddIdP = () => {
    if (configuredIdP) {
      navigateWithReturn(navigate, `/organizations/${encodeURIComponent(organization.id)}/idps/${encodeURIComponent(configuredIdP.id)}`, location);
      return;
    }

    const claimDefaults = publicConfig.oidc_default_claim_mapping || {};
    setIdPForm({
      name: '',
      type: 'oidc',
      issuer: '',
      client_id: '',
      client_secret: '',
      scopes: publicConfig.oidc_default_scopes || 'openid profile email groups',
      enabled: true,
      auto_discovery: true,
      claim_username: claimDefaults.username || '',
      claim_email: claimDefaults.email || '',
      claim_groups: claimDefaults.groups || '',
      is_default: true,
    });
    setIdPError('');
    setIdPTestResult(null);
    setIdPAdvancedOpen(false);
    setIdPScimOpen(false);
    setIdPOpen(true);
  };

  const showSCIMToken = (token, providerName) => {
    setScimTokenModal({ token, providerName, organizationID });
  };

  const closeSCIMTokenModal = () => {
    setScimTokenModal(null);
    load({ showLoading: false });
  };

  const openResourceCreate = () => {
    const type = 'web';
    const option = resourceTypes.find((item) => item.value === type);
    const defaultPort = option?.defaultPort || publicConfig.resource_default_ports?.web || '';
    setResourceForm({
      name: '',
      description: '',
      type,
      organization_id: organizationID,
      gateway_id: organizationGateways[0]?.id || '',
      host: '',
      external_port: defaultPort,
      internal_port: defaultPort,
      external_url: '',
      enabled: true,
    });
    setResourceError('');
    setResourceOpen(true);
  };

  const selectResourceType = (type) => {
    const option = resourceTypes.find((item) => item.value === type);
    const defaultPort = option?.defaultPort || publicConfig.resource_default_ports?.[type] || publicConfig.resource_default_ports?.web || 0;
    setResourceForm({
      ...resourceForm,
      type,
      external_port: resourceForm.external_port || defaultPort,
      internal_port: resourceForm.internal_port || defaultPort,
    });
  };

  const saveResourceCreate = async () => {
    setResourceSaving(true);
    setResourceError('');
    try {
      await createResource({
        name: resourceForm.name?.trim(),
        description: resourceForm.description?.trim(),
        type: resourceForm.type,
        organization_id: organizationID,
        gateway_id: resourceForm.gateway_id,
        host: resourceForm.host?.trim(),
        external_port: parseInt(resourceForm.external_port, 10) || 0,
        internal_port: parseInt(resourceForm.internal_port, 10) || 0,
        external_url: resourceForm.external_url?.trim(),
        enabled: resourceForm.enabled !== false,
        metadata: {},
      });
      setResourceOpen(false);
      await load();
    } catch (e) {
      setResourceError(e.message || 'Failed to create resource');
    } finally {
      setResourceSaving(false);
    }
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
      const createdIdP = await createIdP(organizationID, {
        name: idpForm.name.trim(),
        type: idpForm.type || 'oidc',
        issuer: idpForm.issuer.trim(),
        client_id: idpForm.client_id.trim(),
        client_secret: idpForm.client_secret || undefined,
        scopes: (idpForm.scopes || '').trim(),
        enabled: idpForm.enabled !== false,
        auto_discovery: idpForm.auto_discovery !== false,
        claim_mapping: {
          username: (idpForm.claim_username || '').trim() || claimDefaults.username || '',
          email: (idpForm.claim_email || '').trim() || claimDefaults.email || '',
          groups: (idpForm.claim_groups || '').trim() || claimDefaults.groups || '',
        },
        group_role_mapping: [],
        is_default: idpForm.enabled !== false,
      });
      setIdPOpen(false);
      if (createdIdP?.scim_token) {
        showSCIMToken(createdIdP.scim_token, createdIdP.name || idpForm.name.trim());
        load({ showLoading: false });
      } else {
        await load();
      }
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
      await updateOrganization(organizationID, {
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

  const revokeOrganization = async () => {
    if (!organization?.id) return;
    setRevoking(true);
    setError('');
    try {
      await updateOrganization(organizationID, {
        ...organization,
        enabled: false,
        domains: Array.isArray(organization.domains) ? organization.domains : [],
      });
      setRevokeOpen(false);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to revoke organization');
    } finally {
      setRevoking(false);
    }
  };

  if (loading) {
    return <PageLoading />;
  }

  if (!organization) {
    return (
      <div className="space-y-4">
        <InlineBackButton onClick={() => navigateBack(navigate, '/organizations', location)}>
          <ArrowLeft size={14} />
          Organizations
        </InlineBackButton>
        <EmptyState icon={Building2} title="Organization not found" message={error || 'The selected organization no longer exists.'} />
      </div>
    );
  }

  const organizationListFilter = `organization_id=${encodeURIComponent(organization.id)}&q=${encodeURIComponent(organization.name || organization.id)}`;

  return (
    <div className="space-y-7">
      {error && (
        <div className="rounded-md border border-danger bg-danger-muted p-3 text-sm text-danger">
          {error}
        </div>
      )}

      <section className="space-y-5 pb-5 pr-3 pt-1">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                aria-label="Back to organizations"
                onClick={() => navigateBack(navigate, '/organizations', location)}
                className="-ml-2 inline-flex h-11 w-11 shrink-0 items-center justify-center text-text-primary transition-colors hover:text-accent focus-visible:text-accent active:text-accent-hover"
              >
                <ChevronLeft size={34} strokeWidth={3} />
              </button>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-3">
                  <h1 className="text-2xl font-bold leading-tight text-text-primary">{organization.name}</h1>
                  <StatusBadge enabled={organization.enabled} />
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
                  <span className="inline-flex items-center gap-1">
                    {organization.domain || 'No primary domain'}
                  </span>
                </div>
              </div>
            </div>
            {organization.description && <p className="mt-4 max-w-3xl text-sm text-text-secondary">{organization.description}</p>}
          </div>
          <div className="flex flex-wrap items-center gap-2 lg:justify-end">
            <Button
              variant="danger"
              onClick={() => setRevokeOpen(true)}
              disabled={organization.enabled === false || revoking}
            >
              <Ban size={14} />
              Revoke
            </Button>
            <Button onClick={openEdit}>
              <Edit2 size={14} />
              Edit
            </Button>
          </div>
        </div>

        <div className="border-t border-border" />

        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
          <section className={`${detailPanelClass} min-h-[460px] overflow-hidden`} aria-label="Organization infrastructure">
            <OrganizationHierarchyFlow
              organization={organization}
              gateways={organizationGateways}
              resources={organizationResources}
              className="h-full min-h-[460px]"
            />
          </section>

          <aside className={`${detailPanelClass} flex min-h-[460px] flex-col p-5`}>
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-bold leading-tight text-text-primary">Authentication source</h2>
              <StatusText variant={configuredIdP ? configuredIdP.enabled === false ? 'danger' : 'success' : 'neutral'}>
                {configuredIdP ? configuredIdP.enabled === false ? 'Disabled' : 'Enabled' : 'Not configured'}
              </StatusText>
            </div>

            <div className="mt-6 grid gap-5">
              <div className="min-w-0">
                <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-text-muted">Name</p>
                <p className="mt-2 truncate text-sm font-semibold text-text-primary">
                  {configuredIdP?.name || 'No identity provider configured'}
                </p>
              </div>
              <div className="min-w-0">
                <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-text-muted">Issuer</p>
                <p className="mt-2 break-words text-sm font-semibold text-text-primary">
                  {configuredIdP?.issuer || 'Add an OIDC provider to authenticate organization users.'}
                </p>
              </div>
              <div className="min-w-0">
                <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-text-muted">Client ID</p>
                <p className="mt-2 truncate text-sm font-semibold text-text-primary">{configuredIdP?.client_id || '-'}</p>
              </div>
              <div className="min-w-0">
                <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-text-muted">SCIM token</p>
                <p className={`mt-2 text-sm font-bold uppercase ${configuredIdP?.has_scim_token ? 'text-[#638f67]' : 'text-[#b46a62]'}`}>
                  {configuredIdP?.has_scim_token ? 'CONFIGURED' : 'NOT CONFIGURED'}
                </p>
              </div>
              <div className="grid w-full max-w-[240px] grid-cols-2 gap-x-12 gap-y-2">
                <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-text-muted">Groups</p>
                <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-text-muted">Users</p>
                <p className="text-sm font-semibold tabular-nums text-text-primary">{directoryGroups.length}</p>
                <p className="text-sm font-semibold tabular-nums text-text-primary">{directoryUsers.length}</p>
              </div>
            </div>

            <div className="mt-auto flex justify-end pt-6">
              <Button className="!shadow-none" onClick={openAddIdP}>
                <span>{configuredIdP ? 'View' : 'Add'}</span>
                <ChevronRight size={18} strokeWidth={3} />
              </Button>
            </div>
          </aside>
        </div>

        <div className="grid gap-5 xl:grid-cols-2">
          <section className={`${detailPanelClass} p-5`}>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <h2 className={relatedSectionTitleClass}>
                  Gateways <span className={relatedSectionCountClass}>({organizationGateways.length})</span>
                </h2>
              </div>
              <div className="flex w-fit flex-wrap items-center gap-2 self-start sm:self-center sm:justify-end">
                <Button variant="secondary" className="!px-2.5 !py-1.5 !shadow-none" onClick={() => navigate(`/gateways?${organizationListFilter}`)}>
                  View all
                </Button>
                <Button className="!px-2.5 !py-1.5 !shadow-none" onClick={() => gatewayCreate.openGatewayCreate(organization)}>
                  <Plus size={13} />
                  New
                </Button>
              </div>
            </div>

            {organizationGateways.length === 0 ? (
              <p className="mt-4 text-base font-semibold text-text-primary">No gateways configured</p>
            ) : (
              <div className="mt-4 grid gap-3">
                {organizationGateways.slice(0, 4).map((gateway) => (
                  <button
                    key={gateway.id}
                    type="button"
                    onClick={() => navigateWithReturn(navigate, `/gateways/${encodeURIComponent(gateway.id)}`, location)}
                    className={summaryItemClass}
                  >
                    <span className="flex min-w-0 items-start justify-between gap-3">
                      <span className="min-w-0">
                        <span className="block text-[11px] font-bold uppercase tracking-[0.08em] text-text-muted">
                          Gateway
                        </span>
                        <span className="mt-1 block truncate text-base font-semibold text-text-primary">
                          {gateway.name || gateway.id}
                        </span>
                        <span className="mt-1 block truncate text-xs text-text-secondary">
                          {gateway.fqdn || gateway.id}
                        </span>
                      </span>
                      <StatusText variant={gateway.status === 'revoked' ? 'danger' : gateway.status === 'pending' ? 'warning' : 'success'}>
                        {gateway.status || 'active'}
                      </StatusText>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </section>

          <section className={`${detailPanelClass} p-5`}>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <h2 className={relatedSectionTitleClass}>
                  Resources <span className={relatedSectionCountClass}>({organizationResources.length})</span>
                </h2>
              </div>
              <div className="flex w-fit flex-wrap items-center gap-2 self-start sm:self-center sm:justify-end">
                <Button variant="secondary" className="!px-2.5 !py-1.5 !shadow-none" onClick={() => navigate(`/resources?${organizationListFilter}`)}>
                  View all
                </Button>
                <Button className="!px-2.5 !py-1.5 !shadow-none" onClick={openResourceCreate}>
                  <Plus size={13} />
                  New
                </Button>
              </div>
            </div>

            {organizationResources.length === 0 ? (
              <p className="mt-4 text-base font-semibold text-text-primary">No resources configured</p>
            ) : (
              <div className="mt-4 grid gap-3">
                {organizationResources.slice(0, 4).map((resource) => (
                  <button
                    key={resource.id}
                    type="button"
                    onClick={() => navigateWithReturn(navigate, `/resources/${encodeURIComponent(resource.id)}`, location)}
                    className={summaryItemClass}
                  >
                    <span className="flex min-w-0 items-start justify-between gap-3">
                      <span className="min-w-0">
                        <span className="block text-[11px] font-bold uppercase tracking-[0.08em] text-text-muted">
                          {resourceProtocolLabel(resource)}
                        </span>
                        <span className="mt-1 block truncate text-base font-semibold text-text-primary">
                          {resource.name || resource.id}
                        </span>
                        <span className="mt-1 block truncate text-xs text-text-secondary">
                          {resourceTargetLabel(resource)}
                        </span>
                      </span>
                      <StatusText variant={resource.enabled === false ? 'danger' : 'success'}>
                        {resource.enabled === false ? 'disabled' : 'enabled'}
                      </StatusText>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </section>
        </div>
      </section>

      <OrganizationFormModal
        mode={editOpen ? 'edit' : null}
        form={editForm}
        setForm={setEditForm}
        saving={editSaving}
        onClose={() => setEditOpen(false)}
        onSave={saveEdit}
      />

      <ConfirmDialog
        open={revokeOpen}
        onClose={() => setRevokeOpen(false)}
        onConfirm={revokeOrganization}
        title="Revoke organization"
        message={`Revoke "${organization.name}"? New access through this organization will be disabled, while the organization record remains available for review.`}
        confirmLabel="Revoke organization"
        loadingLabel="Revoking..."
        loading={revoking}
      />

      {gatewayCreate.open ? (
        <GatewayCreateModal
          organization={gatewayCreate.organization}
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
        open={resourceOpen}
        onClose={() => setResourceOpen(false)}
        title={`Add Resource - ${organization.name}`}
        size="3xl"
        footer={(
          <>
            <Button variant="secondary" onClick={() => setResourceOpen(false)}>Cancel</Button>
            <Button
              onClick={saveResourceCreate}
              disabled={
                resourceSaving
                  || !resourceForm.gateway_id
                  || !resourceForm.name?.trim()
                  || !resourceForm.host?.trim()
                  || !resourceForm.external_url?.trim()
                  || !String(resourceForm.external_port || '').trim()
                  || !String(resourceForm.internal_port || '').trim()
              }
            >
              {resourceSaving ? 'Saving...' : 'Create Resource'}
            </Button>
          </>
        )}
      >
        <div className="mb-4 min-h-6">
          {resourceError ? (
            <div className="flex items-center gap-2 text-sm font-semibold text-danger">
              <AlertCircle size={17} />
              <span>{resourceError}</span>
            </div>
          ) : null}
        </div>

        <div className="grid grid-cols-1 gap-x-4 gap-y-3 md:grid-cols-4">
          <FormField label="Organization" className="mb-0 md:col-span-2">
            <FormInput value={organization.name || organization.id} disabled />
          </FormField>
          <FormField label="Gateway" className="mb-0 md:col-span-2">
            <FormSelect value={resourceForm.gateway_id || ''} onChange={(event) => setResourceForm({ ...resourceForm, gateway_id: event.target.value })}>
              <option value="">Select gateway</option>
              {organizationGateways.map((gateway) => (
                <option key={gateway.id} value={gateway.id}>{gateway.name}</option>
              ))}
            </FormSelect>
          </FormField>

          <FormField label="Type" className="mb-0">
            <FormSelect value={resourceForm.type || 'web'} onChange={(event) => selectResourceType(event.target.value)}>
              {resourceTypes.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </FormSelect>
          </FormField>
          <FormField label="External Port" className="mb-0">
            <FormInput type="number" value={resourceForm.external_port || ''} onChange={(event) => setResourceForm({ ...resourceForm, external_port: event.target.value })} />
          </FormField>
          <FormField label="Internal Port" className="mb-0">
            <FormInput type="number" value={resourceForm.internal_port || ''} onChange={(event) => setResourceForm({ ...resourceForm, internal_port: event.target.value })} />
          </FormField>
          <FormField label="Name" className="mb-0">
            <FormInput value={resourceForm.name || ''} onChange={(event) => setResourceForm({ ...resourceForm, name: event.target.value })} placeholder="Production Admin Portal" />
          </FormField>

          <FormField label="Internal Host" className="mb-0 md:col-span-2">
            <FormInput value={resourceForm.host || ''} onChange={(event) => setResourceForm({ ...resourceForm, host: event.target.value })} placeholder="10.0.0.5 or server.internal" />
          </FormField>
          <FormField label="External Host" className="mb-0 md:col-span-2">
            <FormInput value={resourceForm.external_url || ''} onChange={(event) => setResourceForm({ ...resourceForm, external_url: event.target.value })} placeholder="https://app.company.com or ssh.company.com" />
          </FormField>

          <div className="flex flex-wrap items-center gap-x-8 gap-y-3 pt-2 md:col-span-4">
            <FormCheckbox id="org-resource-enabled" checked={resourceForm.enabled !== false} onChange={(event) => setResourceForm({ ...resourceForm, enabled: event.target.checked })} label="Enabled" />
          </div>
        </div>
      </Modal>

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
            <FormInput value={idpForm.client_id || ''} onChange={(event) => setIdPForm({ ...idpForm, client_id: event.target.value })} placeholder="trustcloud" className="font-mono" />
          </FormField>
          <FormField label="Issuer URL" className="mb-3 md:col-span-2">
            <FormInput value={idpForm.issuer || ''} onChange={(event) => setIdPForm({ ...idpForm, issuer: event.target.value })} placeholder="https://idp.company.com/realms/company" className="font-mono" />
          </FormField>
          <FormField label="OIDC client secret" className="mb-3">
            <FormInput type="password" value={idpForm.client_secret || ''} onChange={(event) => setIdPForm({ ...idpForm, client_secret: event.target.value })} placeholder="Required for confidential clients" />
          </FormField>
          <FormField label="Scopes" className="mb-3 md:col-span-2">
            <FormInput value={idpForm.scopes || ''} onChange={(event) => setIdPForm({ ...idpForm, scopes: event.target.value })} className="font-mono" />
          </FormField>
        </div>

        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-y border-border-light py-3">
          <FormCheckbox id="idp-enabled" checked={idpForm.enabled !== false} onChange={(event) => setIdPForm({ ...idpForm, enabled: event.target.checked, is_default: event.target.checked ? idpForm.is_default : false })} label="Enabled" />
        </div>

        <div className="space-y-3">
          <DetailDisclosure
            open={idpScimOpen}
            onClick={() => setIdPScimOpen((open) => !open)}
            title="SCIM provisioning"
            description="PDP generates a token for syncing users and groups."
          />
          {idpScimOpen && (
            <div className="rounded-md border border-border bg-surface-secondary px-4 py-3 text-sm font-semibold text-text-secondary">
              A SCIM provisioning token will be generated automatically.
            </div>
          )}

          <DetailDisclosure
            open={idpAdvancedOpen}
            onClick={() => setIdPAdvancedOpen((open) => !open)}
            title="Advanced OIDC mapping"
            description="Use only when the provider does not send standard claims."
          />
          {idpAdvancedOpen && (
            <>
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
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
            </>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button variant="secondary" onClick={testIdPDiscovery} disabled={idpTesting || !idpForm.issuer?.trim()}>
            {idpTesting ? <LoadingSpinner size="sm" /> : null}
            {idpTesting ? 'Testing...' : 'Test Discovery'}
          </Button>
          {idpTestResult && (
            <div className={`rounded-md border px-3 py-2 text-xs ${idpTestResult.ok ? 'border-success bg-success-muted text-success' : 'border-danger bg-danger-muted text-danger'}`}>
              {idpTestResult.ok ? `OK - ${idpTestResult.authorization_endpoint || 'discovery document found'}` : idpTestResult.error}
            </div>
          )}
        </div>
      </Modal>

      <GatewayTokenModal
        open={!!scimTokenModal}
        tokenInfo={scimTokenModal}
        title="SCIM provisioning token"
        tokenLabel={scimTokenModal?.providerName ? `Token for ${scimTokenModal.providerName}` : 'SCIM token'}
        warningText="Use these values in the SCIM connector. The token will not be shown again."
        copyTitle="Copy SCIM token"
        fields={[
          {
            key: 'organization-id',
            label: 'Organization ID',
            value: scimTokenModal?.organizationID || organizationID,
            copyTitle: 'Copy organization ID',
          },
        ]}
        onClose={closeSCIMTokenModal}
      />
    </div>
  );
}
