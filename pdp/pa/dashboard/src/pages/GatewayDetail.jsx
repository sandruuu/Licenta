import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Edit2,
  Building2,
  Plus,
  Router,
  Server,
} from 'lucide-react';
import { getGateways, getOrganizations, getResources, updateGateway } from '../api';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Modal from '../components/ui/Modal';
import FormField, { FormInput } from '../components/ui/FormField';
import {
  BackIconButton,
  DetailDivider,
  DetailEmptyState as EmptyState,
  DetailSummaryItem,
  detailSectionTitleClass,
  InlineBackButton,
} from '../components/ui/Detail';
import OrganizationHierarchyFlow from '../components/organization/OrganizationHierarchyFlow';
import { formatDateTime } from '../utils/format';

function gatewayStatusVariant(status) {
  if (status === 'revoked') return 'danger';
  if (status === 'pending') return 'warning';
  return 'success';
}

function DetailValue({ label, value, mono = false }) {
  return (
    <DetailSummaryItem>
      <span className="block text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">{label}</span>
      <span className={`mt-1 block truncate text-base font-semibold text-text-primary ${mono ? 'text-mono' : ''}`}>
        {value || '-'}
      </span>
    </DetailSummaryItem>
  );
}

export default function GatewayDetail() {
  const { gatewayId = '' } = useParams();
  const gatewayID = decodeURIComponent(gatewayId);
  const navigate = useNavigate();

  const [gateway, setGateway] = useState(null);
  const [organization, setOrganization] = useState(null);
  const [resources, setResources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState({});
  const [editSaving, setEditSaving] = useState(false);

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
      const organizationID = selectedGateway?.tenant_id || selectedGateway?.tenant_ids?.[0] || '';

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
    ? `/dashboard/organizations/${encodeURIComponent(organization.id)}`
    : '/dashboard/gateways';

  const openEdit = () => {
    setEditForm({
      id: gateway.id,
      name: gateway.name || '',
      fqdn: gateway.fqdn || '',
      tenant_id: gateway.tenant_id || organization?.id || '',
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
        tenant_id: editForm.tenant_id,
      });
      setEditOpen(false);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to update gateway');
    } finally {
      setEditSaving(false);
    }
  };

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
        <InlineBackButton onClick={() => navigate('/dashboard/gateways')}>
          <ArrowLeft size={15} />
          Gateways
        </InlineBackButton>
        <EmptyState icon={Router} title="Gateway not found" message={error || 'The selected gateway no longer exists.'} />
      </div>
    );
  }

  const resourceListFilter = `tenant_id=${encodeURIComponent(organization?.id || gateway.tenant_id || '')}&gateway_id=${encodeURIComponent(gateway.id)}&q=${encodeURIComponent(gateway.name || gateway.id)}`;

  return (
    <div className="space-y-7">
      {error && <div className="rounded-md border border-danger bg-danger-muted p-3 text-sm text-danger">{error}</div>}

      <section className="p-5">
        <div className="space-y-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-start gap-3">
                <BackIconButton compact title="Back" onClick={() => navigate(backTarget)}>
                  <ArrowLeft size={16} />
                </BackIconButton>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-3">
                    <h1 className="text-2xl font-bold leading-tight text-text-primary">{gateway.name || gateway.id}</h1>
                    <Badge variant={gatewayStatusVariant(gateway.status)}>{gateway.status || 'active'}</Badge>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
                    <span>{organization?.name || gateway.tenant_id || 'Unassigned'}</span>
                  </div>
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 lg:justify-end">
              <Button onClick={openEdit}>
                <Edit2 size={14} />
              </Button>
            </div>
          </div>

          <DetailDivider />

          <div>
            <p className={detailSectionTitleClass}>Gateway Configuration</p>
            <div className="mt-2 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              <DetailValue label="FQDN" value={gateway.fqdn} mono />
              <DetailValue label="Certificate Expires" value={formatDateTime(gateway.cert_expires_at)} />
            </div>
          </div>

          <DetailDivider />

          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <p className={detailSectionTitleClass}>Resources ({resources.length})</p>
              {resources.length === 0 ? (
                <p className="mt-1 text-base font-semibold text-text-primary">No resources configured</p>
              ) : (
                <div className="mt-2 space-y-2">
                  {resources.map((resource) => (
                    <DetailSummaryItem key={resource.id} onClick={() => navigate(`/dashboard/resources/${encodeURIComponent(resource.id)}`)}>
                      <span className="flex min-w-0 flex-wrap items-center gap-2">
                        <span className="truncate text-base font-semibold text-text-primary hover:text-accent">{resource.name || resource.id}</span>
                        <Badge variant="info">{(resource.type || '-').toUpperCase()}</Badge>
                        <Badge variant={resource.enabled ? 'success' : 'danger'}>{resource.enabled ? 'Enabled' : 'Disabled'}</Badge>
                      </span>
                      <span className="mt-1 block truncate text-xs text-text-secondary">
                        {`${resource.host || '-'}${resource.port ? `:${resource.port}` : ''}`}
                      </span>
                    </DetailSummaryItem>
                  ))}
                </div>
              )}
            </div>
            <div className="flex w-fit flex-wrap items-center gap-2 self-start sm:justify-end">
              <Button variant="secondary" className="!px-2.5 !py-1.5 !shadow-none" onClick={() => navigate(`/dashboard/resources?${resourceListFilter}`)}>
                View all
              </Button>
              <Button className="!px-2.5 !py-1.5 !shadow-none" onClick={() => navigate(`/dashboard/resources?${resourceListFilter}&create=1`)}>
                <Plus size={13} />
                New
              </Button>
            </div>
          </div>

          {organization?.id && (
            <>
              <DetailDivider />

              <div>
                <h2 className={detailSectionTitleClass}>Gateway Infrastructure</h2>
                <div className="mt-4">
                  <OrganizationHierarchyFlow
                    organization={organization}
                    gateways={[gateway]}
                    resources={resources}
                  />
                </div>
              </div>
            </>
          )}
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
            <Button onClick={saveEdit} disabled={editSaving || !editForm.name?.trim() || !editForm.tenant_id}>
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
    </div>
  );
}
