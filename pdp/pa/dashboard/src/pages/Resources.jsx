import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Edit2, Server, Trash2 } from 'lucide-react';
import {
  createResource,
  deleteResource,
  getGateways,
  getOrganizations,
  getResources,
  updateResource,
} from '../api';
import PageHeader from '../components/ui/PageHeader';
import Modal from '../components/ui/Modal';
import DataTable, { TableActions, TableIconButton } from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import FormField, { FormCheckbox, FormInput, FormSelect } from '../components/ui/FormField';
import Pagination from '../components/ui/Pagination';
import { usePaginatedTable } from '../components/ui/usePaginatedTable';
import { usePublicConfig } from '../config/publicConfig';

const typeMeta = [
  { value: 'web', label: 'WEB' },
  { value: 'ssh', label: 'SSH' },
  { value: 'rdp', label: 'RDP' },
];

function splitList(value) {
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

function typeVariant(type) {
  if (type === 'web') return 'info';
  if (type === 'ssh') return 'success';
  if (type === 'rdp') return 'accent';
  return 'neutral';
}

export default function Resources() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const publicConfig = usePublicConfig();
  const [resources, setResources] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [gateways, setGateways] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [openedCreateFromURL, setOpenedCreateFromURL] = useState(false);
  const [query, setQuery] = useState(() => searchParams.get('q') || '');
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [organizationFilter, setOrganizationFilter] = useState(() => searchParams.get('tenant_id') || 'all');

  const organizationByID = useMemo(() => new Map(organizations.map((organization) => [organization.id, organization])), [organizations]);
  const gatewayByID = useMemo(() => new Map(gateways.map((gateway) => [gateway.id, gateway])), [gateways]);
  const typeOptions = useMemo(() => typeMeta.map((item) => ({
    ...item,
    defaultPort: publicConfig.resource_default_ports?.[item.value] || 0,
  })), [publicConfig.resource_default_ports]);

  const gatewaysForOrganization = (organizationID) => gateways.filter((gateway) => gateway.tenant_id === organizationID);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [resourceData, organizationData, gatewayData] = await Promise.all([getResources(), getOrganizations(), getGateways()]);
      setResources(Array.isArray(resourceData) ? resourceData : []);
      setOrganizations(Array.isArray(organizationData) ? organizationData : []);
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
    } catch (e) {
      setError(e.message || 'Failed to load resources');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const defaultOrganizationID = () => searchParams.get('tenant_id') || organizations[0]?.id || '';
  const defaultGatewayID = (organizationID) => searchParams.get('gateway_id') || gatewaysForOrganization(organizationID)[0]?.id || '';

  const openCreate = (type = searchParams.get('type') || 'web') => {
    const normalizedType = typeOptions.some((item) => item.value === type) ? type : 'web';
    const organizationID = defaultOrganizationID();
    const option = typeOptions.find((item) => item.value === normalizedType);
    setForm({
      name: '',
      description: '',
      type: normalizedType,
      tenant_id: organizationID,
      gateway_id: defaultGatewayID(organizationID),
      host: '',
      port: option?.defaultPort || publicConfig.resource_default_ports?.web || '',
      external_url: '',
      catalog_fqdn: '',
      enabled: true,
      allowed_roles: '',
      require_mfa: false,
      tags: '',
    });
    setModal('create');
  };

  useEffect(() => {
    if (searchParams.get('create') !== '1') {
      setOpenedCreateFromURL(false);
      return;
    }

    if (loading || modal || openedCreateFromURL) return;

    const type = searchParams.get('type') || 'web';
    const normalizedType = typeOptions.some((item) => item.value === type) ? type : 'web';
    const organizationID = searchParams.get('tenant_id') || organizations[0]?.id || '';
    const option = typeOptions.find((item) => item.value === normalizedType);
    const gatewayID = searchParams.get('gateway_id') || gateways.find((gateway) => gateway.tenant_id === organizationID)?.id || '';

    setForm({
      name: '',
      description: '',
      type: normalizedType,
      tenant_id: organizationID,
      gateway_id: gatewayID,
      host: '',
      port: option?.defaultPort || publicConfig.resource_default_ports?.web || '',
      external_url: '',
      catalog_fqdn: '',
      enabled: true,
      allowed_roles: '',
      require_mfa: false,
      tags: '',
    });
    setModal('create');
    setOpenedCreateFromURL(true);
  }, [
    loading,
    searchParams,
    modal,
    openedCreateFromURL,
    typeOptions,
    organizations,
    gateways,
    publicConfig.resource_default_ports,
  ]);

  const openEdit = (resource) => {
    setForm({
      ...resource,
      catalog_fqdn: resource.metadata?.catalog_fqdn || '',
      allowed_roles: (resource.allowed_roles || []).join(', '),
      tags: (resource.tags || []).join(', '),
    });
    setModal('edit');
  };

  const selectOrganization = (organizationID) => {
    const firstGateway = gatewaysForOrganization(organizationID)[0]?.id || '';
    setForm({ ...form, tenant_id: organizationID, gateway_id: firstGateway });
  };

  const selectType = (type) => {
    const option = typeOptions.find((item) => item.value === type);
    setForm({ ...form, type, port: option?.defaultPort || form.port || 0 });
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    const metadata = { ...(form.metadata || {}) };
    if (form.catalog_fqdn?.trim()) {
      metadata.catalog_fqdn = form.catalog_fqdn.trim();
    } else {
      delete metadata.catalog_fqdn;
    }

    const data = {
      name: form.name?.trim(),
      description: form.description?.trim(),
      type: form.type,
      tenant_id: form.tenant_id,
      gateway_id: form.gateway_id,
      host: form.host?.trim(),
      port: parseInt(form.port, 10) || 0,
      external_url: form.external_url?.trim(),
      enabled: form.enabled !== false,
      metadata,
      allowed_roles: splitList(form.allowed_roles),
      tags: splitList(form.tags),
      require_mfa: !!form.require_mfa,
    };

    try {
      if (modal === 'create') {
        await createResource(data);
      } else {
        await updateResource(form.id, data);
      }
      setModal(null);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to save resource');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this resource?')) return;
    setError('');
    try {
      await deleteResource(id);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to delete resource');
    }
  };

  const columns = [
    {
      key: 'name',
      label: 'Resource',
      render: (_, row) => (
        <div>
          <span className="font-semibold text-text-primary text-xs">{row.name}</span>
        </div>
      ),
    },
    { key: 'type', label: 'Type', render: (value) => <Badge variant={typeVariant(value)}>{(value || '').toUpperCase()}</Badge> },
    { key: 'tenant_id', label: 'Organization', render: (value) => organizationByID.get(value)?.name || value || '-' },
    { key: 'gateway_id', label: 'Gateway', render: (value) => gatewayByID.get(value)?.name || value || '-' },
    { key: 'host', label: 'Internal Host', render: (value) => <span className="text-mono text-xs">{value || '-'}</span> },
    {
      key: 'metadata',
      label: 'External FQDN',
      render: (value, row) => <span className="text-mono text-xs">{value?.catalog_fqdn || row.external_url || '-'}</span>,
    },
    { key: 'port', label: 'Port', render: (value) => <span className="text-mono text-xs">{value || '-'}</span> },
    { key: 'enabled', label: 'Status', render: (value) => <Badge variant={value ? 'success' : 'danger'}>{value ? 'Enabled' : 'Disabled'}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      render: (_, row) => (
        <TableActions>
          <TableIconButton icon={Edit2} label="Edit resource" onClick={() => openEdit(row)} />
          <TableIconButton icon={Trash2} label="Delete resource" danger onClick={() => handleDelete(row.id)} />
        </TableActions>
      ),
    },
  ];
  const filteredResources = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return resources.filter((resource) => {
      if (typeFilter !== 'all' && resource.type !== typeFilter) return false;
      if (statusFilter === 'enabled' && resource.enabled === false) return false;
      if (statusFilter === 'disabled' && resource.enabled !== false) return false;
      if (organizationFilter !== 'all' && resource.tenant_id !== organizationFilter) return false;
      if (!needle) return true;
      const organization = organizationByID.get(resource.tenant_id);
      const gateway = gatewayByID.get(resource.gateway_id);
      return [
        resource.name,
        resource.description,
        resource.host,
        resource.external_url,
        resource.metadata?.catalog_fqdn,
        resource.id,
        organization?.name,
        organization?.domain,
        gateway?.name,
      ].some((value) => String(value || '').toLowerCase().includes(needle));
    });
  }, [resources, query, typeFilter, statusFilter, organizationFilter, organizationByID, gatewayByID]);
  const hasFilters = query.trim() || typeFilter !== 'all' || statusFilter !== 'all' || organizationFilter !== 'all';
  const resourcePagination = usePaginatedTable(filteredResources);

  const handleQueryChange = (value) => {
    setQuery(value);
    resourcePagination.resetPage();
  };

  const handleTypeFilterChange = (value) => {
    setTypeFilter(value);
    resourcePagination.resetPage();
  };

  const handleStatusFilterChange = (value) => {
    setStatusFilter(value);
    resourcePagination.resetPage();
  };

  const handleOrganizationFilterChange = (value) => {
    setOrganizationFilter(value);
    resourcePagination.resetPage();
  };

  return (
    <>
      <PageHeader title="Resources" subtitle="Attach WEB, SSH, and RDP resources to an organization gateway" createLabel="Add Resource" onCreate={() => openCreate()} />

      {error && (
        <div className="bg-danger-muted border border-danger rounded-md p-3 mb-4 text-sm text-danger">
          {error}
        </div>
      )}

      <ListToolbar
        query={query}
        onQueryChange={handleQueryChange}
        placeholder="Search resource, host, gateway, or organization"
        summary={`${filteredResources.length} of ${resources.length}`}
      >
        <ListToolbarSelect value={typeFilter} onChange={handleTypeFilterChange}>
          <option value="all">All types</option>
          {typeOptions.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </ListToolbarSelect>
        <ListToolbarSelect value={statusFilter} onChange={handleStatusFilterChange}>
          <option value="all">All statuses</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </ListToolbarSelect>
        <ListToolbarSelect value={organizationFilter} onChange={handleOrganizationFilterChange} className="min-w-[180px]">
          <option value="all">All organizations</option>
          {organizations.map((organization) => (
            <option key={organization.id} value={organization.id}>{organization.name}</option>
          ))}
        </ListToolbarSelect>
      </ListToolbar>

      <DataTable
        columns={columns}
        data={resourcePagination.pageItems}
        loading={loading}
        minRows={resourcePagination.pageSize}
        emptyIcon={Server}
        emptyTitle={hasFilters ? 'No resources match filters' : 'No resources configured'}
        emptyMessage={hasFilters ? 'Adjust search or filters to find resources.' : 'Create a gateway first, then attach protected resources to it.'}
        onRowClick={(row) => navigate(`/dashboard/resources/${encodeURIComponent(row.id)}`)}
      />

      {/* <div className="pt-6">
        <Pagination
          currentPage={resourcePagination.currentPage}
          totalPages={resourcePagination.totalPages}
          onPageChange={resourcePagination.setCurrentPage}
        />
      </div> */}

      <Modal
        open={!!modal}
        onClose={() => setModal(null)}
        title={modal === 'create' ? 'Add Resource' : 'Edit Resource'}
        size="3xl"
        footer={
          <>
            <Button variant="secondary" onClick={() => setModal(null)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving || !form.tenant_id || !form.gateway_id}>
              {saving ? 'Saving...' : modal === 'create' ? 'Create Resource' : 'Save Changes'}
            </Button>
          </>
        }
      >
        <div className="grid grid-cols-1 md:grid-cols-4 gap-x-4 gap-y-3">
          <FormField label="Organization" className="mb-0 md:col-span-2">
            <FormSelect value={form.tenant_id || ''} onChange={(e) => selectOrganization(e.target.value)}>
              <option value="">Select organization</option>
              {organizations.map((organization) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}
            </FormSelect>
          </FormField>
          <FormField label="Gateway" className="mb-0 md:col-span-2">
            <FormSelect value={form.gateway_id || ''} onChange={(e) => setForm({ ...form, gateway_id: e.target.value })}>
              <option value="">Select gateway</option>
              {gatewaysForOrganization(form.tenant_id).map((gateway) => (
                <option key={gateway.id} value={gateway.id}>{gateway.name}</option>
              ))}
            </FormSelect>
          </FormField>

          <FormField label="Type" className="mb-0">
            <FormSelect value={form.type || 'web'} onChange={(e) => selectType(e.target.value)}>
              {typeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </FormSelect>
          </FormField>
          <FormField label="Port" className="mb-0">
            <FormInput type="number" value={form.port || ''} onChange={(e) => setForm({ ...form, port: e.target.value })} />
          </FormField>
          <FormField label="Name" className="mb-0 md:col-span-2">
            <FormInput value={form.name || ''} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Production Admin Portal" />
          </FormField>

          <FormField label="Internal Host" className={`mb-0 ${form.type === 'web' ? 'md:col-span-2' : 'md:col-span-4'}`}>
            <FormInput value={form.host || ''} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="10.0.0.5 or server.internal" />
          </FormField>
          {form.type === 'web' && (
            <FormField label="External URL" className="mb-0 md:col-span-2">
              <FormInput value={form.external_url || ''} onChange={(e) => setForm({ ...form, external_url: e.target.value })} placeholder="https://app.example.com" />
            </FormField>
          )}

          <FormField label="Catalog FQDN" hint="The DNS name published to endpoint agents for this resource." className="mb-0 md:col-span-2">
            <FormInput value={form.catalog_fqdn || ''} onChange={(e) => setForm({ ...form, catalog_fqdn: e.target.value })} placeholder="app.ztna.example.com" />
          </FormField>
          <FormField label="Allowed Roles" className="mb-0">
            <FormInput value={form.allowed_roles || ''} onChange={(e) => setForm({ ...form, allowed_roles: e.target.value })} placeholder="admin, user" />
          </FormField>
          <FormField label="Tags" className="mb-0">
            <FormInput value={form.tags || ''} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="production, critical" />
          </FormField>

          <div className="md:col-span-4 flex flex-wrap items-center gap-x-8 gap-y-3 pt-2">
            <FormCheckbox id="res-enabled" checked={form.enabled !== false} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} label="Enabled" />
            <FormCheckbox id="res-mfa" checked={!!form.require_mfa} onChange={(e) => setForm({ ...form, require_mfa: e.target.checked })} label="Require MFA" />
          </div>
        </div>
      </Modal>
    </>
  );
}
