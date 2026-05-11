import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Ban, Copy, RefreshCw, Router, Server, Trash2 } from 'lucide-react';
import {
  createGateway,
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
import FormField, { FormInput, FormRow, FormSelect } from '../components/ui/FormField';

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
  const [searchParams] = useSearchParams();
  const [gateways, setGateways] = useState([]);
  const [tenants, setTenants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [enrollmentInfo, setEnrollmentInfo] = useState(null);
  const [form, setForm] = useState({
    tenant_id: searchParams.get('tenant_id') || '',
    name: '',
    fqdn: '',
  });

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
      const tenantList = Array.isArray(tenantData) ? tenantData : [];
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
      setTenants(tenantList);
      setForm((current) => ({
        ...current,
        tenant_id: current.tenant_id || tenantList[0]?.id || '',
      }));
    } catch (e) {
      setError(e.message || 'Failed to load gateways');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    setError('');
    setEnrollmentInfo(null);
    if (!form.tenant_id) {
      setError('Select a tenant before creating a gateway');
      return;
    }
    if (!form.name.trim()) {
      setError('Gateway name is required');
      return;
    }

    setSaving(true);
    try {
      const result = await createGateway({
        tenant_id: form.tenant_id,
        name: form.name.trim(),
        fqdn: form.fqdn.trim(),
        auth_mode: 'builtin',
      });
      if (result?.enrollment_token) {
        setEnrollmentInfo({
          token: result.enrollment_token,
          gateway_id: result.id,
          tenant_id: result.tenant_id,
          expires_at: result.token_expires_at,
        });
      }
      setForm((current) => ({ tenant_id: current.tenant_id, name: '', fqdn: '' }));
      await load();
    } catch (e2) {
      setError(e2.message || 'Failed to create gateway');
    } finally {
      setSaving(false);
    }
  };

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
      label: 'Tenant',
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

  return (
    <>
      <PageHeader title="Gateways" subtitle="Enroll edge gateways under one tenant and attach resources to them" />

      {error && (
        <div className="bg-danger-muted border border-danger rounded-md p-3 mb-4 text-sm text-danger">
          {error}
        </div>
      )}

      <div className="bg-surface-card border border-border rounded-md p-5 mb-4 shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
        <form onSubmit={handleCreate}>
          <FormRow>
            <FormField label="Tenant" htmlFor="gw-tenant">
              <FormSelect
                id="gw-tenant"
                value={form.tenant_id}
                onChange={(e) => setForm({ ...form, tenant_id: e.target.value })}
                disabled={tenants.length === 0}
              >
                <option value="">Select tenant</option>
                {tenants.map((tenant) => (
                  <option key={tenant.id} value={tenant.id}>{tenant.name}</option>
                ))}
              </FormSelect>
            </FormField>
            <FormField label="Name" htmlFor="gw-name">
              <FormInput
                id="gw-name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="HQ Gateway"
              />
            </FormField>
          </FormRow>
          <FormField label="FQDN" htmlFor="gw-fqdn" hint="Used as the public identity and endpoint advertised by this gateway.">
            <FormInput
              id="gw-fqdn"
              value={form.fqdn}
              onChange={(e) => setForm({ ...form, fqdn: e.target.value })}
              placeholder="gateway.example.com"
            />
          </FormField>
          <Button type="submit" disabled={saving || tenants.length === 0}>
            <Router size={14} /> {saving ? 'Creating...' : 'Create Gateway'}
          </Button>
        </form>

        {enrollmentInfo?.token && (
          <div className="mt-4 p-3 border border-warning/30 rounded-md bg-warning-muted">
            <div className="text-xs font-semibold text-text-primary mb-2">Gateway Enrollment</div>
            <div className="grid gap-2 md:grid-cols-3">
              <div>
                <div className="text-[10px] font-semibold uppercase text-text-muted">Gateway ID</div>
                <code className="text-mono [overflow-wrap:anywhere] text-text-primary">{enrollmentInfo.gateway_id || '-'}</code>
              </div>
              <div>
                <div className="text-[10px] font-semibold uppercase text-text-muted">Tenant ID</div>
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
      </div>

      <DataTable
        columns={columns}
        data={gateways}
        loading={loading}
        emptyIcon={Router}
        emptyTitle="No gateways created yet"
        emptyMessage="Create a tenant first, then enroll its first gateway."
      />
    </>
  );
}
