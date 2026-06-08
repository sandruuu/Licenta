import { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Ban, Copy, Edit2, RotateCcw, Router, Trash2 } from 'lucide-react';
import {
  deleteGateway,
  getGateways,
  getOrganizations,
  regenerateGatewayToken,
  revokeGateway,
  updateGateway,
} from '../api';
import GatewayCreateModal from '../components/organizations/GatewayCreateModal';
import useGatewayCreate from '../components/organizations/useGatewayCreate';
import PageHeader from '../components/ui/PageHeader';
import DataTable, { TableActions, TableIconButton } from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import ConfirmDialog from '../components/ui/ConfirmDialog';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import Modal from '../components/ui/Modal';
import FormField, { FormInput, FormSelect } from '../components/ui/FormField';
import Pagination from '../components/ui/Pagination';
import StatusText from '../components/ui/StatusText';
import { usePaginatedTable } from '../components/ui/usePaginatedTable';
import { formatDateTime } from '../utils/format';
import { navigateWithReturn } from '../utils/navigation';

function statusVariant(status) {
  const value = (status || '').toLowerCase();
  if (value === 'enrolled' || value === 'active') return 'success';
  if (value === 'revoked') return 'danger';
  if (value === 'pending') return 'warning';
  return 'neutral';
}

function isRevokedGateway(gateway) {
  return String(gateway?.status || '').toLowerCase() === 'revoked';
}

function invalidatedValue(row, value) {
  if (isRevokedGateway(row)) {
    return <StatusText variant="danger">Invalidated</StatusText>;
  }
  return <span className="text-mono">{formatDateTime(value)}</span>;
}

export default function Gateways() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const [gateways, setGateways] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [reactivating, setReactivating] = useState(false);
  const [error, setError] = useState('');
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [deleteGatewayTarget, setDeleteGatewayTarget] = useState(null);
  const [revokeGatewayTarget, setRevokeGatewayTarget] = useState(null);
  const [reactivateGatewayTarget, setReactivateGatewayTarget] = useState(null);
  const [reactivationEnrollment, setReactivationEnrollment] = useState(null);
  const [query, setQuery] = useState(() => searchParams.get('q') || '');
  const [statusFilter, setStatusFilter] = useState('all');
  const [organizationFilter, setOrganizationFilter] = useState(() => searchParams.get('organization_id') || 'all');

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

  const gatewayCreate = useGatewayCreate(load);

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
        organization_id: form.tenant_id,
      });
      setModal(null);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to update gateway');
    } finally {
      setSaving(false);
    }
  };

  const confirmDeleteGateway = async () => {
    if (!deleteGatewayTarget) return;
    setError('');
    setDeleting(true);
    try {
      await deleteGateway(deleteGatewayTarget.id);
      setDeleteGatewayTarget(null);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to delete gateway');
    } finally {
      setDeleting(false);
    }
  };

  const confirmRevokeGateway = async () => {
    if (!revokeGatewayTarget) return;
    setError('');
    setRevoking(true);
    try {
      await revokeGateway(revokeGatewayTarget.id);
      setRevokeGatewayTarget(null);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to revoke gateway');
    } finally {
      setRevoking(false);
    }
  };

  const confirmReactivateGateway = async () => {
    if (!reactivateGatewayTarget) return;
    setError('');
    setReactivating(true);
    try {
      const result = await regenerateGatewayToken(reactivateGatewayTarget.id);
      setReactivationEnrollment({
        ...result,
        name: reactivateGatewayTarget.name,
        fqdn: reactivateGatewayTarget.fqdn,
      });
      setReactivateGatewayTarget(null);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to reactivate gateway');
    } finally {
      setReactivating(false);
    }
  };

  const copyText = async (value) => {
    try {
      await navigator.clipboard?.writeText(value || '');
    } catch {
      // Clipboard support is best-effort in local development browsers.
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
    { key: 'status', label: 'Status', render: (value) => <StatusText variant={statusVariant(value)}>{value || 'unknown'}</StatusText> },
    { key: 'token_expires_at', label: 'Token Expires', render: (value, row) => invalidatedValue(row, value) },
    { key: 'cert_expires_at', label: 'Cert Expires', render: (value, row) => invalidatedValue(row, value) },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      render: (_, row) => {
        const revoked = isRevokedGateway(row);
        return (
          <TableActions>
            <TableIconButton icon={Edit2} label="Edit gateway" onClick={() => openEdit(row)} />
            {revoked ? (
              <TableIconButton icon={RotateCcw} label="Reactivate gateway" onClick={() => setReactivateGatewayTarget(row)} />
            ) : (
              <TableIconButton icon={Ban} label="Revoke gateway" danger onClick={() => setRevokeGatewayTarget(row)} />
            )}
            <TableIconButton
              icon={Trash2}
              label="Delete gateway"
              danger
              onClick={() => setDeleteGatewayTarget(row)}
            />
          </TableActions>
        );
      },
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

  const openCreateGateway = () => {
    const selectedOrganization = organizationFilter !== 'all'
      ? organizations.find((organization) => organization.id === organizationFilter)
      : organizations[0];

    if (!selectedOrganization) {
      setError('Create an organization before adding a gateway.');
      return;
    }

    gatewayCreate.openGatewayCreate(selectedOrganization);
  };

  const handleCreateGatewayOrganizationChange = (organizationID) => {
    const selectedOrganization = organizations.find((organization) => organization.id === organizationID);
    if (selectedOrganization) gatewayCreate.setGatewayOrganization(selectedOrganization);
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <PageHeader
        title="Gateways"
        subtitle="Enroll edge gateways under one organization and attach resources to them"
        createLabel="Add Gateway"
        onCreate={openCreateGateway}
      />

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

      <div className="min-h-0 flex-1">
        <DataTable
          columns={columns}
          data={gatewayPagination.pageItems}
          loading={loading}
          minRows={gatewayPagination.pageSize}
          emptyIcon={Router}
          emptyTitle={hasFilters ? 'No gateways match filters' : 'No gateways created yet'}
          emptyMessage={hasFilters ? 'Adjust search or filters to find gateways.' : 'Create an organization first, then enroll its first gateway.'}
          fillHeight
          onRowClick={(row) => navigateWithReturn(navigate, `/gateways/${encodeURIComponent(row.id)}`, location)}
        />
      </div>

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

      <ConfirmDialog
        open={!!deleteGatewayTarget}
        onClose={() => setDeleteGatewayTarget(null)}
        onConfirm={confirmDeleteGateway}
        title="Delete gateway"
        message={
          deleteGatewayTarget
            ? `Delete "${deleteGatewayTarget.name || deleteGatewayTarget.fqdn || deleteGatewayTarget.id}"? This gateway will no longer be available for protected resources.`
            : ''
        }
        confirmLabel="Delete gateway"
        loading={deleting}
      />

      <ConfirmDialog
        open={!!revokeGatewayTarget}
        onClose={() => setRevokeGatewayTarget(null)}
        onConfirm={confirmRevokeGateway}
        title="Revoke gateway"
        message={
          revokeGatewayTarget
            ? `Revoke "${revokeGatewayTarget.name || revokeGatewayTarget.fqdn || revokeGatewayTarget.id}" and terminate its active sessions? The gateway will need to be enrolled again before it can protect resources.`
            : ''
        }
        confirmLabel="Revoke gateway"
        loading={revoking}
      />

      <ConfirmDialog
        open={!!reactivateGatewayTarget}
        onClose={() => setReactivateGatewayTarget(null)}
        onConfirm={confirmReactivateGateway}
        title="Reactivate gateway"
        message={
          reactivateGatewayTarget
            ? `Reactivate "${reactivateGatewayTarget.name || reactivateGatewayTarget.fqdn || reactivateGatewayTarget.id}"? A new enrollment token will be generated and the gateway will need to enroll again.`
            : ''
        }
        confirmLabel="Reactivate gateway"
        confirmVariant="primary"
        loadingLabel="Reactivating..."
        loading={reactivating}
      />

      <Modal
        open={!!reactivationEnrollment}
        onClose={() => setReactivationEnrollment(null)}
        title="Gateway reactivation token"
        size="lg"
        footer={(
          <Button onClick={() => setReactivationEnrollment(null)}>Done</Button>
        )}
      >
        <div className="rounded-md border border-warning/30 bg-warning-muted p-3">
          <div className="text-xs font-bold text-text-primary">Enrollment token</div>
          <div className="mt-3 flex items-center gap-2">
            <code className="text-mono min-w-0 flex-1 [overflow-wrap:anywhere] text-text-primary">
              {reactivationEnrollment?.enrollment_token || '-'}
            </code>
            <button
              type="button"
              onClick={() => copyText(reactivationEnrollment?.enrollment_token)}
              title="Copy enrollment token"
              aria-label="Copy enrollment token"
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-transparent text-text-secondary transition-colors hover:bg-warning/10 hover:text-accent"
            >
              <Copy size={14} />
            </button>
          </div>
          <p className="mt-4 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-muted">
            Expires
            <span className="mt-1 block text-mono normal-case tracking-normal text-text-secondary">{formatDateTime(reactivationEnrollment?.token_expires_at)}</span>
          </p>
        </div>
      </Modal>

      {gatewayCreate.open ? (
        <GatewayCreateModal
          organization={gatewayCreate.organization}
          organizations={organizations}
          onOrganizationChange={handleCreateGatewayOrganizationChange}
          form={gatewayCreate.form}
          setForm={gatewayCreate.setForm}
          error={gatewayCreate.error}
          enrollment={gatewayCreate.enrollment}
          saving={gatewayCreate.saving}
          onClose={gatewayCreate.closeGatewayCreate}
          onCreate={gatewayCreate.handleGatewayCreate}
        />
      ) : null}
    </div>
  );
}
