import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Edit2, Router, Trash2 } from 'lucide-react';
import {
  deleteGateway,
  getGateways,
  getOrganizations,
  updateGateway,
} from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable, { TableActions, TableIconButton } from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import Modal from '../components/ui/Modal';
import FormField, { FormInput, FormSelect } from '../components/ui/FormField';
import Pagination from '../components/ui/Pagination';
import { usePaginatedTable } from '../components/ui/usePaginatedTable';
import { formatDateTime } from '../utils/format';

function statusVariant(status) {
  const value = (status || '').toLowerCase();
  if (value === 'enrolled' || value === 'active') return 'success';
  if (value === 'revoked') return 'danger';
  if (value === 'pending') return 'warning';
  return 'neutral';
}

export default function Gateways() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [gateways, setGateways] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [query, setQuery] = useState(() => searchParams.get('q') || '');
  const [statusFilter, setStatusFilter] = useState('all');
  const [organizationFilter, setOrganizationFilter] = useState(() => searchParams.get('tenant_id') || 'all');

  const organizationByID = useMemo(() => {
    const result = new Map();
    organizations.forEach((organization) => result.set(organization.id, organization));
    return result;
  }, [organizations]);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [gatewayData, organizationData] = await Promise.all([getGateways(), getOrganizations()]);
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
      setOrganizations(Array.isArray(organizationData) ? organizationData : []);
    } catch (e) {
      setError(e.message || 'Failed to load gateways');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const openEdit = (gateway) => {
    setForm({
      id: gateway.id,
      name: gateway.name || '',
      fqdn: gateway.fqdn || '',
      tenant_id: gateway.tenant_id || '',
    });
    setModal('edit');
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    try {
      await updateGateway(form.id, {
        name: form.name?.trim(),
        fqdn: form.fqdn?.trim(),
        tenant_id: form.tenant_id,
      });
      setModal(null);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to update gateway');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this gateway? This cannot be undone.')) return;
    setError('');
    try {
      await deleteGateway(id);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to delete gateway');
    }
  };

  const columns = [
    {
      key: 'name',
      label: 'Gateway',
      render: (_, row) => (
        <div>
          <strong className="text-text-primary">{row.name || '-'}</strong>
        </div>
      ),
    },
    {
      key: 'tenant_id',
      label: 'Organization',
      render: (value) => organizationByID.get(value)?.name || value || '-',
    },
    { key: 'fqdn', label: 'FQDN', render: (value) => <span className="text-mono">{value || '-'}</span> },
    { key: 'status', label: 'Status', render: (value) => <Badge variant={statusVariant(value)}>{value || 'unknown'}</Badge> },
    { key: 'token_expires_at', label: 'Token Expires', render: (value) => <span className="text-mono">{formatDateTime(value)}</span> },
    { key: 'cert_expires_at', label: 'Cert Expires', render: (value) => <span className="text-mono">{formatDateTime(value)}</span> },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      render: (_, row) => (
        <TableActions>
          <TableIconButton icon={Edit2} label="Edit gateway" onClick={() => openEdit(row)} />
          <TableIconButton
            icon={Trash2}
            label="Delete gateway"
            danger
            onClick={() => handleDelete(row.id)}
          />
        </TableActions>
      ),
    },
  ];
  const filteredGateways = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return gateways.filter((gateway) => {
      const status = String(gateway.status || '').toLowerCase();
      const isActiveStatus = status === 'active' || status === 'enrolled';
      if (statusFilter === 'active' && !isActiveStatus) return false;
      if (statusFilter !== 'all' && statusFilter !== 'active' && status !== statusFilter) return false;
      if (organizationFilter !== 'all' && gateway.tenant_id !== organizationFilter) return false;
      if (!needle) return true;
      const organization = organizationByID.get(gateway.tenant_id);
      return [
        gateway.name,
        gateway.fqdn,
        gateway.id,
        gateway.tenant_id,
        organization?.name,
        organization?.domain,
      ].some((value) => String(value || '').toLowerCase().includes(needle));
    });
  }, [gateways, query, statusFilter, organizationFilter, organizationByID]);
  const hasFilters = query.trim() || statusFilter !== 'all' || organizationFilter !== 'all';
  const gatewayPagination = usePaginatedTable(filteredGateways);

  const handleQueryChange = (value) => {
    setQuery(value);
    gatewayPagination.resetPage();
  };

  const handleStatusFilterChange = (value) => {
    setStatusFilter(value);
    gatewayPagination.resetPage();
  };

  const handleOrganizationFilterChange = (value) => {
    setOrganizationFilter(value);
    gatewayPagination.resetPage();
  };

  return (
    <>
      <PageHeader title="Gateways" subtitle="Enroll edge gateways under one organization and attach resources to them" />

      {error && (
        <div className="bg-danger-muted border border-danger rounded-md p-3 mb-4 text-sm text-danger">
          {error}
        </div>
      )}

      <ListToolbar
        query={query}
        onQueryChange={handleQueryChange}
        placeholder="Search gateway name, FQDN, or organization"
        summary={`${filteredGateways.length} of ${gateways.length}`}
      >
        <ListToolbarSelect value={statusFilter} onChange={handleStatusFilterChange}>
          <option value="all">All statuses</option>
          <option value="active">Active</option>
          <option value="pending">Pending</option>
          <option value="revoked">Revoked</option>
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
        data={gatewayPagination.pageItems}
        loading={loading}
        minRows={gatewayPagination.pageSize}
        emptyIcon={Router}
        emptyTitle={hasFilters ? 'No gateways match filters' : 'No gateways created yet'}
        emptyMessage={hasFilters ? 'Adjust search or filters to find gateways.' : 'Create an organization first, then enroll its first gateway.'}
        onRowClick={(row) => navigate(`/dashboard/gateways/${encodeURIComponent(row.id)}`)}
      />

      {/* <div className="pt-6">
        <Pagination
          currentPage={gatewayPagination.currentPage}
          totalPages={gatewayPagination.totalPages}
          onPageChange={gatewayPagination.setCurrentPage}
        />
      </div> */}

      <Modal
        open={!!modal}
        onClose={() => setModal(null)}
        title="Edit Gateway"
        size="lg"
        footer={(
          <>
            <Button variant="secondary" onClick={() => setModal(null)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving || !form.name?.trim() || !form.tenant_id}>
              {saving ? 'Saving...' : 'Save Changes'}
            </Button>
          </>
        )}
      >
        <div className="grid gap-4">
          <FormField label="Organization" className="mb-0">
            <FormSelect value={form.tenant_id || ''} onChange={(event) => setForm({ ...form, tenant_id: event.target.value })}>
              <option value="">Select organization</option>
              {organizations.map((organization) => (
                <option key={organization.id} value={organization.id}>{organization.name}</option>
              ))}
            </FormSelect>
          </FormField>
          <FormField label="Gateway name" className="mb-0">
            <FormInput value={form.name || ''} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          </FormField>
          <FormField label="FQDN" className="mb-0">
            <FormInput value={form.fqdn || ''} onChange={(event) => setForm({ ...form, fqdn: event.target.value })} placeholder="gateway.example.com" />
          </FormField>
        </div>
      </Modal>
    </>
  );
}
