import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Building2,
  Loader2,
  Plus,
  Shield,
  Edit2,
} from 'lucide-react';
import {
  getGateways,
  getIdPs,
  getResources,
  getOrganizations,
  createIdP,
  discoverIdP,
  updateOrganization,
} from '../api';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import {
  BackIconButton,
  DetailDisclosure,
  DetailEmptyState as EmptyState,
  InlineBackButton,
} from '../components/ui/Detail';
import Modal from '../components/ui/Modal';
import FormField, { FormCheckbox, FormInput } from '../components/ui/FormField';
import OrganizationHierarchyFlow from '../components/organization/OrganizationHierarchyFlow';
import OrganizationFormModal from '../components/organizations/OrganizationFormModal';
import GatewayCreateModal from '../components/organizations/GatewayCreateModal';
import StatusBadge from '../components/organizations/StatusBadge';
import useGatewayCreate from '../components/organizations/useGatewayCreate';
import { usePublicConfig } from '../config/publicConfig';
import { resourceTypeBadgeVariant } from '../utils/resourceTypes';

const summaryItemClass = 'block w-full max-w-3xl  px-4 py-3 text-left';

export default function OrganizationDetail() {
  const { organizationId = '' } = useParams();
  const organizationID = decodeURIComponent(organizationId);
  const navigate = useNavigate();
  const publicConfig = usePublicConfig();

  const [organization, setOrganization] = useState(null);
  const [gateways, setGateways] = useState([]);
  const [resources, setResources] = useState([]);
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
  const [idpAdvancedOpen, setIdPAdvancedOpen] = useState(false);
  const [idpScimOpen, setIdPScimOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [organizationData, gatewayData, resourceData, idpData] = await Promise.all([
        getOrganizations(),
        getGateways(),
        getResources(),
        getIdPs(organizationID),
      ]);
      const organizations = Array.isArray(organizationData) ? organizationData : [];
      setOrganization(organizations.find((item) => item.id === organizationID) || null);
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
      setResources(Array.isArray(resourceData) ? resourceData : []);
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
  const configuredIdP = idps[0] || null;

  const openEdit = () => {
    setEditForm({
      ...organization,
      domains: Array.isArray(organization?.domains) ? organization.domains : [],
    });
    setEditOpen(true);
  };

  const openAddIdP = () => {
    if (configuredIdP) {
      navigate(`/dashboard/organizations/${encodeURIComponent(organization.id)}/idps/${encodeURIComponent(configuredIdP.id)}`);
      return;
    }

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
      is_default: true,
    });
    setIdPError('');
    setIdPTestResult(null);
    setIdPAdvancedOpen(false);
    setIdPScimOpen(false);
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
        is_default: idpForm.enabled !== false,
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
        <InlineBackButton onClick={() => navigate('/dashboard/organizations')}>
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

      <section className="p-5">
        <div className="space-y-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-start gap-3">
                <BackIconButton compact onClick={() => navigate('/dashboard/organizations')}>
                  <ArrowLeft size={16} />
                </BackIconButton>
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
              <Button onClick={openEdit}>
                <Edit2 size={14} />
              </Button>
            </div>
          </div>

          <div className="border-t border-border" />

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="text-[13px] font-bold uppercase tracking-[0.12em] text-text-muted">Primary authentication</p>
              <button type="button" onClick={openAddIdP} className={`${summaryItemClass} mt-2`}>
                <span className="block truncate text-base font-semibold text-text-primary hover:text-accent">
                  {configuredIdP?.name || 'No identity provider configured'}
                </span>
                <span className="mt-1 block truncate text-xs text-text-secondary">
                  {configuredIdP?.issuer || 'Add an OIDC provider to authenticate organization users.'}
                </span>
              </button>
            </div>
            <Button variant="secondary" className="w-fit self-start !shadow-none sm:self-center" onClick={openAddIdP}>
              {configuredIdP ? 'View' : 'Add'}
            </Button>
          </div>

          <div className="border-t border-border" />

          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <p className="text-[13px] font-bold uppercase tracking-[0.12em] text-text-muted">
                Gateways ({organizationGateways.length})
              </p>
              {organizationGateways.length === 0 ? (
                <p className="mt-1 text-base font-semibold text-text-primary">No gateways configured</p>
              ) : (
                <div className="mt-2 space-y-2">
                  {organizationGateways.slice(0, 2).map((gateway) => (
                    <button
                      key={gateway.id}
                      type="button"
                      onClick={() => navigate(`/dashboard/gateways/${encodeURIComponent(gateway.id)}`)}
                      className={summaryItemClass}
                    >
                      <span className="flex min-w-0 flex-wrap items-center gap-2">
                        <span className="truncate text-base font-semibold text-text-primary hover:text-accent">
                          {gateway.name || gateway.id}
                        </span>
                        <Badge variant={gateway.status === 'revoked' ? 'danger' : gateway.status === 'pending' ? 'warning' : 'success'}>
                          {gateway.status || 'active'}
                        </Badge>
                      </span>
                      <span className="mt-1 flex flex-wrap items-center gap-2 text-xs text-text-secondary">
                        <span className="text-mono">{gateway.fqdn || gateway.id}</span>
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="flex w-fit flex-wrap items-center gap-2 self-start sm:justify-end">
              <Button variant="secondary" className="!px-2.5 !py-1.5 !shadow-none" onClick={() => navigate(`/dashboard/gateways?${organizationListFilter}`)}>
                View all
              </Button>
              <Button className="!px-2.5 !py-1.5 !shadow-none" onClick={() => gatewayCreate.openGatewayCreate(organization)}>
                <Plus size={13} />
                New
              </Button>
            </div>
          </div>

          <div className="border-t border-border" />

          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <p className="text-[13px] font-bold uppercase tracking-[0.12em] text-text-muted">
                Resources ({organizationResources.length})
              </p>
              {organizationResources.length === 0 ? (
                <p className="mt-1 text-base font-semibold text-text-primary">No resources configured</p>
              ) : (
                <div className="mt-2 space-y-2">
                  {organizationResources.slice(0, 2).map((resource) => (
                    <button
                      key={resource.id}
                      type="button"
                      onClick={() => navigate(`/dashboard/resources/${encodeURIComponent(resource.id)}`)}
                      className={summaryItemClass}
                    >
                      <span className="flex min-w-0 flex-wrap items-center gap-2">
                        <span className="truncate text-base font-semibold text-text-primary hover:text-accent">
                          {resource.name || resource.id}
                        </span>
                        <Badge variant={resourceTypeBadgeVariant(resource.type)}>{(resource.type || '-').toUpperCase()}</Badge>
                      </span>
                      <span className="mt-1 flex flex-wrap items-center gap-2 text-xs text-text-secondary">
                        <span>{gatewayByID.get(resource.gateway_id)?.name || resource.gateway_id || 'No gateway'}</span>
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="flex w-fit flex-wrap items-center gap-2 self-start sm:justify-end">
              <Button variant="secondary" className="!px-2.5 !py-1.5 !shadow-none" onClick={() => navigate(`/dashboard/resources?${organizationListFilter}`)}>
                View all
              </Button>
              <Button className="!px-2.5 !py-1.5 !shadow-none" onClick={() => navigate(`/dashboard/resources?${organizationListFilter}&create=1`)}>
                <Plus size={13} />
                New
              </Button>
            </div>
          </div>

          <div className="border-t border-border" />

          <div>
            <h2 className="text-[13px] font-bold uppercase tracking-[0.12em] text-text-muted">Organization Infrastructure</h2>
            <div className="mt-4">
              <OrganizationHierarchyFlow
                organization={organization}
                gateways={organizationGateways}
                resources={organizationResources}
              />
            </div>
          </div>
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
            <FormInput value={idpForm.issuer || ''} onChange={(event) => setIdPForm({ ...idpForm, issuer: event.target.value })} placeholder="http://keycloak:8080/realms/trustcloud-lab" className="font-mono" />
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
            description="Optional token used only for syncing users and groups."
          />
          {idpScimOpen && (
            <FormField label="SCIM provisioning token" className="mb-0">
              <FormInput type="password" value={idpForm.scim_token || ''} onChange={(event) => setIdPForm({ ...idpForm, scim_token: event.target.value })} placeholder="Bearer token configured in the IdP" />
            </FormField>
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
