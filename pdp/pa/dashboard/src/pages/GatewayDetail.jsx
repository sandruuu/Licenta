import { useCallback, useEffect, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Ban,
  ChevronLeft,
  Edit2,
  Building2,
  Plus,
  RotateCcw,
  Router,
} from 'lucide-react';
import { getGateways, getOrganizations, getResources, regenerateGatewayToken, revokeGateway, updateGateway } from '../api';
import Button from '../components/ui/Button';
import PageLoading from '../components/ui/PageLoading';
import Modal from '../components/ui/Modal';
import FormField, { FormInput } from '../components/ui/FormField';
import StatusText from '../components/ui/StatusText';
import ConfirmDialog from '../components/ui/ConfirmDialog';
import GatewayTokenModal from '../components/organizations/GatewayTokenModal';
import {
  DetailEmptyState as EmptyState,
  InlineBackButton,
} from '../components/ui/Detail';
import OrganizationHierarchyFlow from '../components/organization/OrganizationHierarchyFlow';
import { displayGatewayName, displayOrganizationName, displayResourceName } from '../utils/displayNames';
import { formatDateTime } from '../utils/format';
import { navigateBack, navigateWithReturn } from '../utils/navigation';

const detailPanelClass = 'rounded-md border border-border bg-transparent';
const summaryItemClass = 'block w-full rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-4 py-4 text-left shadow-[0_8px_16px_rgba(42,42,42,0.12)] transition-[border-color,background-color,box-shadow] duration-150 hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.14)]';
const relatedSectionTitleClass = 'text-[20px] font-bold leading-tight text-text-primary';
const relatedSectionCountClass = 'text-sm font-bold text-text-muted';

function gatewayStatusVariant(status) {
  if (status === 'revoked') return 'danger';
  if (status === 'pending') return 'warning';
  return 'success';
}

function isRevokedGateway(gateway) {
  return String(gateway?.status || '').toLowerCase() === 'revoked';
}

function isEnrolledGateway(gateway) {
  const status = String(gateway?.status || '').toLowerCase();
  return status === 'enrolled' || status === 'active';
}

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

function DetailField({ label, value, mono = false, children }) {
  return (
    <div className="min-w-0">
      <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-text-muted">{label}</p>
      {children || (
        <p className={`mt-2 truncate text-sm font-semibold text-text-primary ${mono ? 'text-mono' : ''}`}>
          {value === undefined || value === null || value === '' ? '-' : value}
        </p>
      )}
    </div>
  );
}

export default function GatewayDetail() {
  const { gatewayId = '' } = useParams();
  const gatewayID = decodeURIComponent(gatewayId);
  const navigate = useNavigate();
  const location = useLocation();

  const [gateway, setGateway] = useState(null);
  const [organization, setOrganization] = useState(null);
  const [resources, setResources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState({});
  const [editSaving, setEditSaving] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [regeneratingToken, setRegeneratingToken] = useState(false);
  const [gatewayTokenModal, setGatewayTokenModal] = useState(null);
  const [refreshAfterTokenModal, setRefreshAfterTokenModal] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [gatewayData, resourceData, organizationData] = await Promise.all([
        getGateways(),
        getResources(),
        getOrganizations(),
      ]);
      const gatewayList = Array.isArray(gatewayData) ? gatewayData : [];
      const resourceList = Array.isArray(resourceData) ? resourceData : [];
      const organizations = Array.isArray(organizationData) ? organizationData : [];
      const selectedGateway = gatewayList.find((item) => item.id === gatewayID) || null;
      const organizationID = selectedGateway?.organization_id || selectedGateway?.organization_ids?.[0] || '';

      setGateway(selectedGateway);
      setOrganization(organizations.find((item) => item.id === organizationID) || null);
      setResources(resourceList.filter((resource) => resource.gateway_id === gatewayID));
    } catch (e) {
      setError(e.message || 'Failed to load gateway data');
    } finally {
      setLoading(false);
    }
  }, [gatewayID]);

  useEffect(() => {
    load();
  }, [load]);

  const backTarget = organization?.id
    ? `/organizations/${encodeURIComponent(organization.id)}`
    : '/gateways';
  const handleBack = () => navigateBack(navigate, backTarget, location);

  const openEdit = () => {
    setEditForm({
      id: gateway.id,
      name: gateway.name || '',
      fqdn: gateway.fqdn || '',
      organization_id: gateway.organization_id || organization?.id || '',
    });
    setEditOpen(true);
  };

  const saveEdit = async () => {
    setEditSaving(true);
    setError('');
    try {
      await updateGateway(gateway.id, {
        name: editForm.name?.trim(),
        fqdn: editForm.fqdn?.trim(),
        organization_id: editForm.organization_id,
      });
      setEditOpen(false);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to update gateway');
    } finally {
      setEditSaving(false);
    }
  };

  const revokeSelectedGateway = async () => {
    if (!gateway) return;
    setRevoking(true);
    setError('');
    try {
      await revokeGateway(gateway.id);
      setRevokeOpen(false);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to revoke gateway');
    } finally {
      setRevoking(false);
    }
  };

  const regenerateToken = async () => {
    if (!gateway) return;
    if (isEnrolledGateway(gateway)) {
      setError('Gateway is already enrolled. Enrollment token regeneration is no longer available.');
      return;
    }
    setRegeneratingToken(true);
    setError('');
    setGatewayTokenModal({
      loading: true,
      name: gateway.name,
      fqdn: gateway.fqdn,
    });
    try {
      const result = await regenerateGatewayToken(gateway.id);
      setGatewayTokenModal({
        ...result,
        name: gateway.name,
        fqdn: gateway.fqdn,
      });
      setRefreshAfterTokenModal(true);
    } catch (e) {
      const message = e.message || 'Failed to regenerate gateway token';
      setError(message);
      setGatewayTokenModal({
        error: message,
        name: gateway.name,
        fqdn: gateway.fqdn,
      });
    } finally {
      setRegeneratingToken(false);
    }
  };

  const closeGatewayTokenModal = () => {
    setGatewayTokenModal(null);
    if (refreshAfterTokenModal) {
      setRefreshAfterTokenModal(false);
      load();
    }
  };

  if (loading) {
    return <PageLoading />;
  }

  if (!gateway) {
    return (
      <div className="space-y-4">
        <InlineBackButton onClick={() => navigateBack(navigate, '/gateways', location)}>
          <ArrowLeft size={15} />
          Gateways
        </InlineBackButton>
        <EmptyState icon={Router} title="Gateway not found" message={error || 'The selected gateway no longer exists.'} />
      </div>
    );
  }

  const gatewayLabel = displayGatewayName(gateway);
  const resourceListFilter = `organization_id=${encodeURIComponent(organization?.id || gateway.organization_id || '')}&gateway_id=${encodeURIComponent(gateway.id)}&q=${encodeURIComponent(gatewayLabel)}`;
  const gatewayRevoked = isRevokedGateway(gateway);
  const gatewayEnrolled = isEnrolledGateway(gateway);

  return (
    <div className="space-y-7">
      {error && <div className="rounded-md border border-danger bg-danger-muted p-3 text-sm text-danger">{error}</div>}

      <section className="space-y-5 pb-5 pr-3 pt-1">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                aria-label="Back"
                onClick={handleBack}
                className="-ml-2 inline-flex h-11 w-11 shrink-0 items-center justify-center text-text-primary transition-colors hover:text-accent focus-visible:text-accent active:text-accent-hover"
              >
                <ChevronLeft size={34} strokeWidth={3} />
              </button>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-3">
                  <h1 className="text-2xl font-bold leading-tight text-text-primary">{gatewayLabel}</h1>
                  <StatusText variant={gatewayStatusVariant(gateway.status)}>{gateway.status || 'active'}</StatusText>
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
                  <span>{gateway.fqdn || 'No FQDN configured'}</span>
                </div>
              </div>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 lg:justify-end">
            {!gatewayRevoked ? (
              <Button variant="danger" onClick={() => setRevokeOpen(true)} disabled={revoking}>
                <Ban size={14} />
                Revoke
              </Button>
            ) : null}
            {!gatewayEnrolled ? (
              <Button variant="secondary" onClick={regenerateToken} disabled={regeneratingToken}>
                <RotateCcw size={14} />
                Regenerate token
              </Button>
            ) : null}
            <Button onClick={openEdit}>
              <Edit2 size={14} />
              Edit
            </Button>
          </div>
        </div>

        <div className="border-t border-border" />

        <section className={`${detailPanelClass} p-5`}>
          <h2 className={relatedSectionTitleClass}>Gateway configuration</h2>
          <div className="mt-5 grid gap-x-8 gap-y-5 md:grid-cols-2 xl:grid-cols-3">
            <DetailField label="Name" value={gatewayLabel} />
            <DetailField label="Organization" value={displayOrganizationName(organization)} />
            <DetailField label="FQDN" value={gateway.fqdn} mono />
            <DetailField label="Status">
              <div className="mt-2">
                <StatusText variant={gatewayStatusVariant(gateway.status)}>{gateway.status || 'active'}</StatusText>
              </div>
            </DetailField>
            <DetailField
              label="Token expires"
              value={gatewayRevoked ? 'Invalidated' : formatDateTime(gateway.token_expires_at)}
              mono
            />
            <DetailField
              label="Cert expires"
              value={gatewayRevoked ? 'Invalidated' : formatDateTime(gateway.cert_expires_at)}
              mono
            />
          </div>
        </section>

        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
          <section className={`${detailPanelClass} min-h-[460px] overflow-hidden`} aria-label="Gateway infrastructure">
            {organization?.id ? (
              <OrganizationHierarchyFlow
                organization={organization}
                gateways={[gateway]}
                resources={resources}
                className="h-full min-h-[460px]"
              />
            ) : (
              <EmptyState icon={Building2} title="No organization" message="This gateway is not assigned to an organization." />
            )}
          </section>

          <aside className={`${detailPanelClass} min-h-[460px] p-5`}>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <h2 className={relatedSectionTitleClass}>
                  Resources <span className={relatedSectionCountClass}>({resources.length})</span>
                </h2>
              </div>
              <div className="flex w-fit flex-wrap items-center gap-2 self-start sm:self-center sm:justify-end">
                <Button variant="secondary" className="!px-2.5 !py-1.5 !shadow-none" onClick={() => navigate(`/resources?${resourceListFilter}`)}>
                  View all
                </Button>
                <Button className="!px-2.5 !py-1.5 !shadow-none" onClick={() => navigate(`/resources?${resourceListFilter}&create=1`)}>
                  <Plus size={13} />
                  New
                </Button>
              </div>
            </div>

            {resources.length === 0 ? (
              <p className="mt-4 text-base font-semibold text-text-primary">No resources configured</p>
            ) : (
              <div className="mt-4 grid gap-3">
                {resources.map((resource) => (
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
                          {displayResourceName(resource)}
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
          </aside>
        </div>
      </section>

      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title="Edit Gateway"
        size="lg"
        footer={(
          <>
            <Button variant="secondary" onClick={() => setEditOpen(false)}>Cancel</Button>
            <Button onClick={saveEdit} disabled={editSaving || !editForm.name?.trim() || !editForm.organization_id}>
              {editSaving ? 'Saving...' : 'Save Changes'}
            </Button>
          </>
        )}
      >
        <div className="grid gap-4">
          <FormField label="Gateway name" className="mb-0">
            <FormInput value={editForm.name || ''} onChange={(event) => setEditForm({ ...editForm, name: event.target.value })} />
          </FormField>
          <FormField label="FQDN" className="mb-0">
            <FormInput value={editForm.fqdn || ''} onChange={(event) => setEditForm({ ...editForm, fqdn: event.target.value })} />
          </FormField>
        </div>
      </Modal>

      <ConfirmDialog
        open={revokeOpen}
        onClose={() => setRevokeOpen(false)}
        onConfirm={revokeSelectedGateway}
        title="Revoke gateway"
        message={`Revoke "${gatewayLabel}" and terminate its active sessions?`}
        confirmLabel="Revoke gateway"
        loadingLabel="Revoking..."
        loading={revoking}
      />

      <GatewayTokenModal
        open={!!gatewayTokenModal}
        tokenInfo={gatewayTokenModal}
        title="Gateway enrollment token"
        onClose={closeGatewayTokenModal}
      />
    </div>
  );
}
