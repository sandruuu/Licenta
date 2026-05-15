import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Edit2,
  Server,
} from 'lucide-react';
import { getGateways, getOrganizations, getResources, updateResource } from '../api';
import Badge from '../components/ui/Badge';
import {
  BackIconButton,
  DetailDivider,
  DetailEmptyState as EmptyState,
  DetailSummaryItem,
  detailSectionTitleClass,
  InlineBackButton,
} from '../components/ui/Detail';
import Button from '../components/ui/Button';
import Modal from '../components/ui/Modal';
import FormField, { FormCheckbox, FormInput, FormSelect, FormTextarea } from '../components/ui/FormField';
import OrganizationHierarchyFlow from '../components/organization/OrganizationHierarchyFlow';
import { formatDateTime } from '../utils/format';

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

export default function ResourceDetail() {
  const { resourceId = '' } = useParams();
  const resourceID = decodeURIComponent(resourceId);
  const navigate = useNavigate();

  const [resource, setResource] = useState(null);
  const [gateway, setGateway] = useState(null);
  const [organization, setOrganization] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState({});
  const [editSaving, setEditSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [resourceData, gatewayData, organizationData] = await Promise.all([
        getResources(),
        getGateways(),
        getOrganizations(),
      ]);
      const resourceList = Array.isArray(resourceData) ? resourceData : [];
      const gatewayList = Array.isArray(gatewayData) ? gatewayData : [];
      const organizations = Array.isArray(organizationData) ? organizationData : [];
      const selectedResource = resourceList.find((item) => item.id === resourceID) || null;
      const selectedGateway = gatewayList.find((item) => item.id === selectedResource?.gateway_id) || null;
      const organizationID = selectedResource?.tenant_id || selectedGateway?.tenant_id || selectedGateway?.tenant_ids?.[0] || '';

      setResource(selectedResource);
      setGateway(selectedGateway);
      setOrganization(organizations.find((item) => item.id === organizationID) || null);
    } catch (e) {
      setError(e.message || 'Failed to load resource data');
    } finally {
      setLoading(false);
    }
  }, [resourceID]);

  useEffect(() => {
    load();
  }, [load]);

  const backTarget = gateway?.id
    ? `/dashboard/gateways/${encodeURIComponent(gateway.id)}`
    : organization?.id
      ? `/dashboard/organizations/${encodeURIComponent(organization.id)}`
      : '/dashboard/resources';

  const openEdit = () => {
    setEditForm({
      ...resource,
      external_fqdn: resource.metadata?.catalog_fqdn || resource.external_url || '',
    });
    setEditOpen(true);
  };

  const saveEdit = async () => {
    setEditSaving(true);
    setError('');
    const metadata = { ...(editForm.metadata || {}) };
    if (editForm.external_fqdn?.trim()) {
      metadata.catalog_fqdn = editForm.external_fqdn.trim();
    } else {
      delete metadata.catalog_fqdn;
    }

    try {
      await updateResource(resource.id, {
        name: editForm.name?.trim(),
        description: editForm.description?.trim(),
        type: editForm.type,
        tenant_id: editForm.tenant_id,
        gateway_id: editForm.gateway_id,
        host: editForm.host?.trim(),
        port: parseInt(editForm.port, 10) || 0,
        external_url: editForm.external_fqdn?.trim(),
        enabled: editForm.enabled !== false,
        metadata,
      });
      setEditOpen(false);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to update resource');
    } finally {
      setEditSaving(false);
    }
  };

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
        <InlineBackButton onClick={() => navigate('/dashboard/resources')}>
          <ArrowLeft size={15} />
          Resources
        </InlineBackButton>
        <EmptyState icon={Server} title="Resource not found" message={error || 'The selected resource no longer exists.'} />
      </div>
    );
  }

  const target = `${resource.host || '-'}${resource.port ? `:${resource.port}` : ''}`;
  const catalogFQDN = resource.metadata?.catalog_fqdn || resource.external_url || '';

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
                    <h1 className="text-2xl font-bold leading-tight text-text-primary">{resource.name || resource.id}</h1>
                    <Badge variant="info">{(resource.type || '-').toUpperCase()}</Badge>
                    <Badge variant={resource.enabled ? 'success' : 'danger'}>{resource.enabled ? 'Enabled' : 'Disabled'}</Badge>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
                    <span>{gateway?.name}</span>
                  </div>
                </div>
              </div>
              {resource.description && <p className="mt-4 max-w-3xl text-sm text-text-secondary">{resource.description}</p>}
            </div>
            <div className="flex flex-wrap items-center gap-2 lg:justify-end">
              <Button onClick={openEdit}>
                <Edit2 size={14} />
              </Button>
            </div>
          </div>
          <DetailDivider />

          <div>
            <p className={detailSectionTitleClass}>Resource Configuration</p>
            <div className="mt-2 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              <DetailValue label="Target" value={target} mono />
              <DetailValue label="External FQDN" value={catalogFQDN} mono />
              <DetailValue label="Certificate Mode" value={resource.cert_mode} />
              <DetailValue label="Certificate Domain" value={resource.cert_domain} mono />
              <DetailValue label="Certificate Expiry" value={formatDateTime(resource.cert_expiry)} />
            </div>
          </div>
          <DetailDivider />

              <div>
                <h2 className={detailSectionTitleClass}>Resource Infrastructure</h2>
                <div className="mt-4">
                  <OrganizationHierarchyFlow
                    organization={organization}
                    gateways={gateway ? [gateway] : []}
                    resources={[resource]}
                  />
                </div>
              </div>
        </div>
      </section>

      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title="Edit Resource"
        size="2xl"
        footer={(
          <>
            <Button variant="secondary" onClick={() => setEditOpen(false)}>Cancel</Button>
            <Button onClick={saveEdit} disabled={editSaving || !editForm.name?.trim() || !editForm.gateway_id}>
              {editSaving ? 'Saving...' : 'Save Changes'}
            </Button>
          </>
        )}
      >
        <div className="grid gap-x-4 gap-y-3 md:grid-cols-2">
          <FormField label="Name" className="mb-0">
            <FormInput value={editForm.name || ''} onChange={(event) => setEditForm({ ...editForm, name: event.target.value })} />
          </FormField>
          <FormField label="Type" className="mb-0">
            <FormSelect value={editForm.type || 'web'} onChange={(event) => setEditForm({ ...editForm, type: event.target.value })}>
              <option value="web">WEB</option>
              <option value="ssh">SSH</option>
              <option value="rdp">RDP</option>
            </FormSelect>
          </FormField>
          <FormField label="Description" className="mb-0 md:col-span-2">
            <FormTextarea value={editForm.description || ''} onChange={(event) => setEditForm({ ...editForm, description: event.target.value })} />
          </FormField>
          <FormField label="Internal Host" className="mb-0">
            <FormInput value={editForm.host || ''} onChange={(event) => setEditForm({ ...editForm, host: event.target.value })} />
          </FormField>
          <FormField label="Port" className="mb-0">
            <FormInput type="number" value={editForm.port || ''} onChange={(event) => setEditForm({ ...editForm, port: event.target.value })} />
          </FormField>
          <FormField label="External FQDN" className="mb-0 md:col-span-2">
            <FormInput value={editForm.external_fqdn || ''} onChange={(event) => setEditForm({ ...editForm, external_fqdn: event.target.value })} />
          </FormField>
          <div className="md:col-span-2">
            <FormCheckbox id="resource-detail-enabled" checked={editForm.enabled !== false} onChange={(event) => setEditForm({ ...editForm, enabled: event.target.checked })} label="Enabled" />
          </div>
        </div>
      </Modal>
    </div>
  );
}
