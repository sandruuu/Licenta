import { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { AlertCircle, Ban, Edit2, RotateCcw, Server } from 'lucide-react';
import {
  createResource,
  getGateways,
  getOrganizations,
  getResources,
  updateResource,
} from '../api';
import PageHeader from '../components/ui/PageHeader';
import Modal from '../components/ui/Modal';
import ConfirmDialog from '../components/ui/ConfirmDialog';
import DataTable, { TableActions, TableIconButton } from '../components/ui/DataTable';
import Button from '../components/ui/Button';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import FormField, { FormCheckbox, FormInput, FormSelect } from '../components/ui/FormField';
import Pagination from '../components/ui/Pagination';
import StatusText from '../components/ui/StatusText';
import ResourceTypeText from '../components/ui/ResourceTypeText';
import { usePaginatedTable } from '../components/ui/usePaginatedTable';
import { usePublicConfig } from '../config/publicConfig';
import { displayGatewayName, displayOrganizationName, displayResourceName } from '../utils/displayNames';
import { navigateWithReturn } from '../utils/navigation';

const typeMeta = [
  { value: 'web', label: 'WEB' },
  { value: 'ssh', label: 'SSH' },
  { value: 'rdp', label: 'RDP' },
];

function catalogHost(resource) {
  return resource?.external_url || resource?.host || '-';
}

function resourceExternalPort(resource) {
  return resource?.external_port || '';
}

function resourceInternalPort(resource) {
  return resource?.internal_port || '';
}

function isValidPort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function looksLikeIPv4(value) {
  return /^[0-9.]+$/.test(String(value || '').trim());
}

function isValidIPv4(value) {
  const parts = String(value || '').trim().split('.');
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;
    const number = Number(part);
    return number >= 0 && number <= 255 && String(number) === part;
  });
}

function isValidDNSName(value, requireDot = false) {
  const host = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host || host.length > 253) return false;
  if (requireDot && !host.includes('.')) return false;
  if (host.includes('..')) return false;
  return host.split('.').every((label) => (
    label.length > 0
      && label.length <= 63
      && !label.startsWith('-')
      && !label.endsWith('-')
      && /^[a-z0-9-]+$/.test(label)
  ));
}

function sanitizeInternalHost(value) {
  const host = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host) return { error: 'Internal Host is required.' };
  if (looksLikeIPv4(host)) {
    return isValidIPv4(host)
      ? { value: host }
      : { error: 'Internal Host must be a valid IPv4 address or DNS hostname.' };
  }
  if (!isValidDNSName(host)) {
    return { error: 'Internal Host must be a valid IPv4 address or DNS hostname.' };
  }
  return { value: host };
}

function sanitizeExternalAddress(value) {
  const raw = String(value || '').trim();
  if (!raw) return { error: 'External Host is required.' };

  let host = raw;
  if (raw.includes('://')) {
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      return { error: 'External Host must be a valid HTTP/HTTPS URL or DNS hostname.' };
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { error: 'External Host URL must use HTTP or HTTPS.' };
    }
    if (parsed.port) {
      return { error: 'External Host cannot include a port. Use External Port instead.' };
    }
    host = parsed.hostname;
  } else if (/[/:?#]/.test(raw)) {
    return { error: 'External Host must be a valid HTTP/HTTPS URL or DNS hostname.' };
  }

  host = host.trim().toLowerCase().replace(/\.$/, '');
  if (looksLikeIPv4(host) || !isValidDNSName(host, true)) {
    return { error: 'External Host must be a valid DNS hostname.' };
  }
  return { value: raw };
}

export default function Resources() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const publicConfig = usePublicConfig();
  const [resources, setResources] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [gateways, setGateways] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [reactivating, setReactivating] = useState(false);
  const [revokeResourceTarget, setRevokeResourceTarget] = useState(null);
  const [reactivateResourceTarget, setReactivateResourceTarget] = useState(null);
  const [modalError, setModalError] = useState('');
  const [openedCreateFromURL, setOpenedCreateFromURL] = useState(false);
  const [query, setQuery] = useState(() => searchParams.get('q') || '');
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [organizationFilter, setOrganizationFilter] = useState(() => searchParams.get('organization_id') || 'all');

  const organizationByID = useMemo(() => new Map(organizations.map((organization) => [organization.id, organization])), [organizations]);
  const gatewayByID = useMemo(() => new Map(gateways.map((gateway) => [gateway.id, gateway])), [gateways]);
  const typeOptions = useMemo(() => typeMeta.map((item) => ({
    ...item,
    defaultPort: publicConfig.resource_default_ports?.[item.value] || 0,
  })), [publicConfig.resource_default_ports]);

  const gatewaysForOrganization = (organizationID) => gateways.filter((gateway) => gateway.organization_id === organizationID);
  const defaultPortForType = (type) => {
    const option = typeOptions.find((item) => item.value === type);
    return option?.defaultPort || publicConfig.resource_default_ports?.[type] || publicConfig.resource_default_ports?.web || '';
  };

  const load = async () => {
    setLoading(true);
    try {
      const [resourceData, organizationData, gatewayData] = await Promise.all([getResources(), getOrganizations(), getGateways()]);
      setResources(Array.isArray(resourceData) ? resourceData : []);
      setOrganizations(Array.isArray(organizationData) ? organizationData : []);
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const defaultOrganizationID = () => searchParams.get('organization_id') || organizations[0]?.id || '';
  const defaultGatewayID = (organizationID) => searchParams.get('gateway_id') || gatewaysForOrganization(organizationID)[0]?.id || '';

  const openCreate = (type = searchParams.get('type') || 'web') => {
    const normalizedType = typeOptions.some((item) => item.value === type) ? type : 'web';
    const organizationID = defaultOrganizationID();
    const defaultPort = defaultPortForType(normalizedType);
    setModalError('');
    setForm({
      name: '',
      description: '',
      type: normalizedType,
      organization_id: organizationID,
      gateway_id: defaultGatewayID(organizationID),
      host: '',
      external_port: defaultPort,
      internal_port: defaultPort,
      external_url: '',
      enabled: true,
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
    const organizationID = searchParams.get('organization_id') || organizations[0]?.id || '';
    const defaultPort = defaultPortForType(normalizedType);
    const gatewayID = searchParams.get('gateway_id') || gateways.find((gateway) => gateway.organization_id === organizationID)?.id || '';

    setForm({
      name: '',
      description: '',
      type: normalizedType,
      organization_id: organizationID,
      gateway_id: gatewayID,
      host: '',
      external_port: defaultPort,
      internal_port: defaultPort,
      external_url: '',
      enabled: true,
    });
    setModalError('');
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
    setModalError('');
    setForm({
      ...resource,
      external_port: resourceExternalPort(resource),
      internal_port: resourceInternalPort(resource),
    });
    setModal('edit');
  };

  const selectOrganization = (organizationID) => {
    const firstGateway = gatewaysForOrganization(organizationID)[0]?.id || '';
    setModalError('');
    setForm({ ...form, organization_id: organizationID, gateway_id: firstGateway });
  };

  const selectType = (type) => {
    const defaultPort = defaultPortForType(type);
    setModalError('');
    setForm({
      ...form,
      type,
      external_port: form.external_port || defaultPort,
      internal_port: form.internal_port || defaultPort,
    });
  };

  const isResourceFormFilled = () => Boolean(
    form.name?.trim()
      && form.type
      && form.organization_id
      && form.gateway_id
      && form.host?.trim()
      && form.external_url?.trim()
      && String(form.external_port || '').trim()
      && String(form.internal_port || '').trim()
  );

  const validateAndSanitizeResourceForm = () => {
    if (!form.organization_id) return { error: 'Organization is required.' };
    if (!form.gateway_id) return { error: 'Gateway is required.' };
    if (!form.type) return { error: 'Type is required.' };
    if (!isValidPort(form.external_port)) return { error: 'External Port must be between 1 and 65535.' };
    if (!isValidPort(form.internal_port)) return { error: 'Internal Port must be between 1 and 65535.' };
    if (!form.name?.trim()) return { error: 'Name is required.' };

    const internalHost = sanitizeInternalHost(form.host);
    if (internalHost.error) return internalHost;

    const externalAddress = sanitizeExternalAddress(form.external_url);
    if (externalAddress.error) return externalAddress;

    return {
      data: {
        name: form.name.trim(),
        description: form.description?.trim(),
        type: form.type,
        organization_id: form.organization_id,
        gateway_id: form.gateway_id,
        host: internalHost.value,
        external_port: parseInt(form.external_port, 10),
        internal_port: parseInt(form.internal_port, 10),
        external_url: externalAddress.value,
        enabled: form.enabled !== false,
        metadata: { ...(form.metadata || {}) },
      },
    };
  };

  const handleSave = async () => {
    setModalError('');
    const validation = validateAndSanitizeResourceForm();
    if (validation.error) {
      setModalError(validation.error);
      return;
    }
    setSaving(true);
    const data = validation.data;

    try {
      if (modal === 'create') {
        await createResource(data);
      } else {
        await updateResource(form.id, data);
      }
      setModal(null);
      await load();
    } catch (e) {
      setModalError(e.message || 'Failed to save resource');
    } finally {
      setSaving(false);
    }
  };

  const confirmRevokeResource = async () => {
    if (!revokeResourceTarget) return;
    setRevoking(true);
    try {
      await updateResource(revokeResourceTarget.id, { enabled: false });
      setRevokeResourceTarget(null);
      await load();
    } catch (e) {
      console.error(e);
    } finally {
      setRevoking(false);
    }
  };

  const confirmReactivateResource = async () => {
    if (!reactivateResourceTarget) return;
    setReactivating(true);
    try {
      await updateResource(reactivateResourceTarget.id, { enabled: true });
      setReactivateResourceTarget(null);
      await load();
    } catch (e) {
      console.error(e);
    } finally {
      setReactivating(false);
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
    { key: 'type', label: 'Type', render: (value) => <ResourceTypeText type={value} /> },
    { key: 'organization_id', label: 'Organization', render: (value) => {
      const organization = organizationByID.get(value);
      return organization ? displayOrganizationName(organization) : '-';
    } },
    { key: 'gateway_id', label: 'Gateway', render: (value) => {
      const gateway = gatewayByID.get(value);
      return gateway ? displayGatewayName(gateway) : '-';
    } },
    { key: 'host', label: 'Internal Host', render: (value) => <span className="text-mono text-xs">{value || '-'}</span> },
    { key: 'internal_port', label: 'Internal Port', render: (_, row) => <span className="text-mono text-xs">{resourceInternalPort(row) || '-'}</span> },
    {
      key: 'metadata',
      label: 'External Host',
      render: (_, row) => <span className="text-mono text-xs">{catalogHost(row)}</span>,
    },
    { key: 'external_port', label: 'External Port', render: (_, row) => <span className="text-mono text-xs">{resourceExternalPort(row) || '-'}</span> },
    { key: 'enabled', label: 'Status', render: (value) => <StatusText variant={value ? 'success' : 'danger'}>{value ? 'Enabled' : 'Disabled'}</StatusText> },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      render: (_, row) => (
        <TableActions>
          <TableIconButton icon={Edit2} label="Edit resource" onClick={() => openEdit(row)} />
          {row.enabled === false ? (
            <TableIconButton icon={RotateCcw} label="Reactivate resource" onClick={() => setReactivateResourceTarget(row)} />
          ) : (
            <TableIconButton icon={Ban} label="Revoke resource" danger onClick={() => setRevokeResourceTarget(row)} />
          )}
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
      if (organizationFilter !== 'all' && resource.organization_id !== organizationFilter) return false;
      if (!needle) return true;
      const organization = organizationByID.get(resource.organization_id);
      const gateway = gatewayByID.get(resource.gateway_id);
      return [
        resource.name,
        resource.description,
        resource.host,
        resource.external_url,
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
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <PageHeader title="Resources" subtitle="Attach WEB, SSH, and RDP resources to an organization gateway" createLabel="Add Resource" onCreate={() => openCreate()} />

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

      <div className="min-h-0 flex-1">
        <DataTable
          columns={columns}
          data={resourcePagination.pageItems}
          loading={loading}
          minRows={resourcePagination.pageSize}
          emptyIcon={Server}
          emptyTitle={hasFilters ? 'No resources match filters' : 'No resources configured'}
          emptyMessage={hasFilters ? 'Adjust search or filters to find resources.' : 'Create a gateway first, then attach protected resources to it.'}
          fillHeight
          onRowClick={(row) => navigateWithReturn(navigate, `/resources/${encodeURIComponent(row.id)}`, location)}
        />
      </div>

      {/* <div className="pt-6">
        <Pagination
          currentPage={resourcePagination.currentPage}
          totalPages={resourcePagination.totalPages}
          onPageChange={resourcePagination.setCurrentPage}
        />
      </div> */}

      <Modal
        open={!!modal}
        onClose={() => {
          setModalError('');
          setModal(null);
        }}
        title={modal === 'create' ? 'Add Resource' : 'Edit Resource'}
        size="3xl"
        footer={
          <>
            <Button
              variant="secondary"
              onClick={() => {
                setModalError('');
                setModal(null);
              }}
            >
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={saving || !isResourceFormFilled()}>
              {saving ? 'Saving...' : modal === 'create' ? 'Create Resource' : 'Save Changes'}
            </Button>
          </>
        }
      >
        <div className="mb-4 min-h-6">
          {modalError ? (
            <div className="flex items-center gap-2 text-sm font-semibold text-danger">
              <AlertCircle size={17} />
              <span>{modalError}</span>
            </div>
          ) : null}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-x-4 gap-y-3">
          <FormField label="Organization" className="mb-0 md:col-span-2">
            <FormSelect value={form.organization_id || ''} onChange={(e) => selectOrganization(e.target.value)}>
              <option value="">Select organization</option>
              {organizations.map((organization) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}
            </FormSelect>
          </FormField>
          <FormField label="Gateway" className="mb-0 md:col-span-2">
            <FormSelect value={form.gateway_id || ''} onChange={(e) => {
              setModalError('');
              setForm({ ...form, gateway_id: e.target.value });
            }}>
              <option value="">Select gateway</option>
              {gatewaysForOrganization(form.organization_id).map((gateway) => (
                <option key={gateway.id} value={gateway.id}>{gateway.name}</option>
              ))}
            </FormSelect>
          </FormField>

          <FormField label="Type" className="mb-0">
            <FormSelect value={form.type || 'web'} onChange={(e) => selectType(e.target.value)}>
              {typeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </FormSelect>
          </FormField>
          <FormField label="External Port" className="mb-0">
            <FormInput type="number" value={form.external_port || ''} onChange={(e) => {
              setModalError('');
              setForm({ ...form, external_port: e.target.value });
            }} />
          </FormField>
          <FormField label="Internal Port" className="mb-0">
            <FormInput type="number" value={form.internal_port || ''} onChange={(e) => {
              setModalError('');
              setForm({ ...form, internal_port: e.target.value });
            }} />
          </FormField>
          <FormField label="Name" className="mb-0">
            <FormInput value={form.name || ''} onChange={(e) => {
              setModalError('');
              setForm({ ...form, name: e.target.value });
            }} placeholder="Production Admin Portal" />
          </FormField>

          <FormField label="Internal Host" className="mb-0 md:col-span-2">
            <FormInput value={form.host || ''} onChange={(e) => {
              setModalError('');
              setForm({ ...form, host: e.target.value });
            }} placeholder="10.0.0.5 or server.internal" />
          </FormField>
          <FormField label="External Host" className="mb-0 md:col-span-2">
            <FormInput value={form.external_url || ''} onChange={(e) => {
              setModalError('');
              setForm({ ...form, external_url: e.target.value });
            }} placeholder="https://app.company.com or ssh.company.com" />
          </FormField>

          <div className="md:col-span-4 flex flex-wrap items-center gap-x-8 gap-y-3 pt-2">
            <FormCheckbox id="res-enabled" checked={form.enabled !== false} onChange={(e) => {
              setModalError('');
              setForm({ ...form, enabled: e.target.checked });
            }} label="Enabled" />
          </div>
        </div>
      </Modal>

      <ConfirmDialog
        open={!!revokeResourceTarget}
        onClose={() => setRevokeResourceTarget(null)}
        onConfirm={confirmRevokeResource}
        title="Revoke resource"
        message={
          revokeResourceTarget
            ? `Revoke "${displayResourceName(revokeResourceTarget)}"? New sessions for this resource will be disabled until it is reactivated.`
            : ''
        }
        confirmLabel="Revoke resource"
        loadingLabel="Revoking..."
        loading={revoking}
      />

      <ConfirmDialog
        open={!!reactivateResourceTarget}
        onClose={() => setReactivateResourceTarget(null)}
        onConfirm={confirmReactivateResource}
        title="Reactivate resource"
        message={
          reactivateResourceTarget
            ? `Reactivate "${displayResourceName(reactivateResourceTarget)}"? The resource can become available again according to its policies.`
            : ''
        }
        confirmLabel="Reactivate resource"
        confirmVariant="primary"
        loadingLabel="Reactivating..."
        loading={reactivating}
      />
    </div>
  );
}
