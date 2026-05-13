import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Ban, Copy, RefreshCw, Router, Server, Trash2 } from 'lucide-react';
import {
  deleteGateway,
  getGateways,
  getTenants,
  regenerateGatewayToken,
  revokeGateway,
} from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';

function formatDate(value) {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString('ro-RO', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function statusVariant(status) {
  const value = (status || '').toLowerCase();
  if (value === 'enrolled' || value === 'active') return 'success';
  if (value === 'revoked') return 'danger';
  if (value === 'pending') return 'info';
  return 'neutral';
}

function copyText(text) {
  if (!text) return;
  navigator.clipboard.writeText(text).catch(() => {});
}

export default function Gateways() {
  const navigate = useNavigate();
  const [gateways, setGateways] = useState([]);
  const [tenants, setTenants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [enrollmentInfo, setEnrollmentInfo] = useState(null);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [organizationFilter, setOrganizationFilter] = useState('all');

  const tenantByID = useMemo(() => {
    const result = new Map();
    tenants.forEach((tenant) => result.set(tenant.id, tenant));
    return result;
  }, [tenants]);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [gatewayData, tenantData] = await Promise.all([getGateways(), getTenants()]);
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
      setTenants(Array.isArray(tenantData) ? tenantData : []);
    } catch (e) {
      setError(e.message || 'Failed to load gateways');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleRegenerateToken = async (id) => {
    setError('');
    try {
      const gateway = gateways.find((item) => item.id === id);
      const result = await regenerateGatewayToken(id);
      if (result?.enrollment_token) {
        setEnrollmentInfo({
          token: result.enrollment_token,
          gateway_id: result.id || id,
          tenant_id: result.tenant_id || gateway?.tenant_id || '',
          expires_at: result.token_expires_at,
        });
      }
      await load();
    } catch (e) {
      setError(e.message || 'Failed to regenerate enrollment token');
    }
  };

  const handleRevoke = async (id) => {
    if (!confirm('Revoke this gateway?')) return;
    setError('');
    try {
      await revokeGateway(id);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to revoke gateway');
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
          <div className="text-mono text-text-muted">{row.id}</div>
        </div>
      ),
    },
    {
      key: 'tenant_id',
      label: 'Organization',
      render: (value) => tenantByID.get(value)?.name || value || '-',
    },
    { key: 'fqdn', label: 'FQDN', render: (value) => <span className="text-mono">{value || '-'}</span> },
    { key: 'status', label: 'Status', render: (value) => <Badge variant={statusVariant(value)}>{value || 'unknown'}</Badge> },
    { key: 'token_expires_at', label: 'Token Expires', render: (value) => <span className="text-mono">{formatDate(value)}</span> },
    { key: 'cert_expires_at', label: 'Cert Expires', render: (value) => <span className="text-mono">{formatDate(value)}</span> },
    { key: 'last_seen_at', label: 'Last Seen', render: (value) => <span className="text-mono">{formatDate(value)}</span> },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      render: (_, row) => (
        <div className="flex justify-end gap-1.5">
          <Button
            variant="ghost"
            className="!p-1.5 !shadow-none"
            onClick={() => navigate(`/dashboard/resources?tenant_id=${row.tenant_id}&gateway_id=${row.id}`)}
            title="Add resources"
          >
            <Server size={13} />
          </Button>
          <Button
            variant="ghost"
            className="!p-1.5 !shadow-none"
            onClick={() => handleRegenerateToken(row.id)}
            title="Regenerate enrollment token"
          >
            <RefreshCw size={13} />
          </Button>
          <Button
            variant="ghost"
            className="!p-1.5 !shadow-none"
            onClick={() => handleRevoke(row.id)}
            title="Revoke gateway"
          >
            <Ban size={13} />
          </Button>
          <Button
            variant="ghost"
            className="!p-1.5 !shadow-none !text-danger hover:!bg-danger-muted"
            onClick={() => handleDelete(row.id)}
            title="Delete gateway"
          >
            <Trash2 size={13} />
          </Button>
        </div>
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
      const organization = tenantByID.get(gateway.tenant_id);
      return [
        gateway.name,
        gateway.fqdn,
        gateway.id,
        gateway.tenant_id,
        organization?.name,
        organization?.domain,
      ].some((value) => String(value || '').toLowerCase().includes(needle));
    });
  }, [gateways, query, statusFilter, organizationFilter, tenantByID]);
  const hasFilters = query.trim() || statusFilter !== 'all' || organizationFilter !== 'all';

  return (
    <>
      <PageHeader title="Gateways" subtitle="Enroll edge gateways under one organization and attach resources to them" />

      {error && (
        <div className="bg-danger-muted border border-danger rounded-md p-3 mb-4 text-sm text-danger">
          {error}
        </div>
      )}

      {enrollmentInfo?.token && (
        <div className="bg-surface-card border border-warning/30 rounded-md p-4 mb-4 shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
          <div className="text-xs font-semibold text-text-primary mb-2">Gateway Enrollment Token</div>
          <div className="grid gap-2 md:grid-cols-3">
            <div>
              <div className="text-[10px] font-semibold uppercase text-text-muted">Gateway ID</div>
              <code className="text-mono [overflow-wrap:anywhere] text-text-primary">{enrollmentInfo.gateway_id || '-'}</code>
            </div>
            <div>
              <div className="text-[10px] font-semibold uppercase text-text-muted">Organization ID</div>
              <code className="text-mono [overflow-wrap:anywhere] text-text-primary">{enrollmentInfo.tenant_id || '-'}</code>
            </div>
            <div>
              <div className="text-[10px] font-semibold uppercase text-text-muted">Expires</div>
              <code className="text-mono text-text-primary">{formatDate(enrollmentInfo.expires_at)}</code>
            </div>
          </div>
          <div className="mt-3 flex gap-2 items-center">
            <code className="text-mono flex-1 [overflow-wrap:anywhere] text-text-primary">{enrollmentInfo.token}</code>
            <Button variant="secondary" onClick={() => copyText(enrollmentInfo.token)} className="text-xs px-2 py-1">
              <Copy size={12} /> Copy Token
            </Button>
          </div>
        </div>
      )}

      <ListToolbar
        query={query}
        onQueryChange={setQuery}
        placeholder="Search gateway name, FQDN, or organization"
        summary={`${filteredGateways.length} of ${gateways.length}`}
      >
        <ListToolbarSelect value={statusFilter} onChange={setStatusFilter}>
          <option value="all">All statuses</option>
          <option value="active">Active</option>
          <option value="pending">Pending</option>
          <option value="revoked">Revoked</option>
        </ListToolbarSelect>
        <ListToolbarSelect value={organizationFilter} onChange={setOrganizationFilter} className="min-w-[180px]">
          <option value="all">All organizations</option>
          {tenants.map((tenant) => (
            <option key={tenant.id} value={tenant.id}>{tenant.name}</option>
          ))}
        </ListToolbarSelect>
      </ListToolbar>

      <DataTable
        columns={columns}
        data={filteredGateways}
        loading={loading}
        emptyIcon={Router}
        emptyTitle={hasFilters ? 'No gateways match filters' : 'No gateways created yet'}
        emptyMessage={hasFilters ? 'Adjust search or filters to find gateways.' : 'Create an organization first, then enroll its first gateway.'}
      />
    </>
  );
}
