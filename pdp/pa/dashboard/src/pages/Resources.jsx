import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Copy, Edit, Eye, EyeOff, Key, Server, Shield, Trash2 } from 'lucide-react';
import {
  createResource,
  deleteResource,
  getGateways,
  getResources,
  getTenants,
  regenerateSecret,
  updateResource,
} from '../api';
import PageHeader from '../components/ui/PageHeader';
import Modal from '../components/ui/Modal';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import FormField, { FormCheckbox, FormInput, FormSelect } from '../components/ui/FormField';
import { usePublicConfig } from '../config/publicConfig';

const typeMeta = [
  { value: 'web', label: 'WEB' },
  { value: 'ssh', label: 'SSH' },
  { value: 'rdp', label: 'RDP' },
];

function splitList(value) {
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

function copyText(text) {
  navigator.clipboard.writeText(text).catch(() => {});
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
  const [tenants, setTenants] = useState([]);
  const [gateways, setGateways] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [credModal, setCredModal] = useState(null);
  const [showSecret, setShowSecret] = useState(false);

  const tenantByID = useMemo(() => new Map(tenants.map((tenant) => [tenant.id, tenant])), [tenants]);
  const gatewayByID = useMemo(() => new Map(gateways.map((gateway) => [gateway.id, gateway])), [gateways]);
  const typeOptions = useMemo(() => typeMeta.map((item) => ({
    ...item,
    defaultPort: publicConfig.resource_default_ports?.[item.value] || 0,
  })), [publicConfig.resource_default_ports]);

  const gatewaysForTenant = (tenantID) => gateways.filter((gateway) => gateway.tenant_id === tenantID);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [resourceData, tenantData, gatewayData] = await Promise.all([getResources(), getTenants(), getGateways()]);
      setResources(Array.isArray(resourceData) ? resourceData : []);
      setTenants(Array.isArray(tenantData) ? tenantData : []);
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

  const defaultTenantID = () => searchParams.get('tenant_id') || tenants[0]?.id || '';
  const defaultGatewayID = (tenantID) => searchParams.get('gateway_id') || gatewaysForTenant(tenantID)[0]?.id || '';

  const openCreate = (type = searchParams.get('type') || 'web') => {
    const normalizedType = typeOptions.some((item) => item.value === type) ? type : 'web';
    const tenantID = defaultTenantID();
    const option = typeOptions.find((item) => item.value === normalizedType);
    setForm({
      name: '',
      description: '',
      type: normalizedType,
      tenant_id: tenantID,
      gateway_id: defaultGatewayID(tenantID),
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

  const openEdit = (resource) => {
    setForm({
      ...resource,
      catalog_fqdn: resource.metadata?.catalog_fqdn || '',
      allowed_roles: (resource.allowed_roles || []).join(', '),
      tags: (resource.tags || []).join(', '),
    });
    setModal('edit');
  };

  const selectTenant = (tenantID) => {
    const firstGateway = gatewaysForTenant(tenantID)[0]?.id || '';
    setForm({ ...form, tenant_id: tenantID, gateway_id: firstGateway });
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
        const created = await createResource(data);
        if (created?.client_id) {
          setShowSecret(true);
          setCredModal({ client_id: created.client_id, client_secret: created.client_secret, name: created.name });
        }
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

  const handleRegenSecret = async (resource) => {
    if (!confirm('Regenerate this resource secret?')) return;
    setError('');
    setSaving(true);
    try {
      const result = await regenerateSecret(resource.id);
      setShowSecret(true);
      setCredModal({ client_id: result.client_id, client_secret: result.client_secret, name: resource.name });
      await load();
    } catch (e) {
      setError(e.message || 'Failed to regenerate secret');
    } finally {
      setSaving(false);
    }
  };

  const columns = [
    {
      key: 'name',
      label: 'Resource',
      render: (_, row) => (
        <div>
          <span className="font-semibold text-text-primary text-xs">{row.name}</span>
          {row.description && <div className="text-xs text-text-muted">{row.description}</div>}
        </div>
      ),
    },
    { key: 'type', label: 'Type', render: (value) => <Badge variant={typeVariant(value)}>{(value || '').toUpperCase()}</Badge> },
    { key: 'tenant_id', label: 'Tenant', render: (value) => tenantByID.get(value)?.name || value || '-' },
    { key: 'gateway_id', label: 'Gateway', render: (value) => gatewayByID.get(value)?.name || value || '-' },
    { key: 'host', label: 'Internal Host', render: (value) => <span className="text-mono text-xs">{value || '-'}</span> },
    { key: 'port', label: 'Port', render: (value) => <span className="text-mono text-xs">{value || '-'}</span> },
    {
      key: 'metadata',
      label: 'Catalog FQDN',
      render: (value, row) => <span className="text-mono text-xs">{value?.catalog_fqdn || row.external_url || '-'}</span>,
    },
    { key: 'enabled', label: 'Status', render: (value) => <Badge variant={value ? 'success' : 'danger'}>{value ? 'Enabled' : 'Disabled'}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      render: (_, row) => (
        <div className="flex items-center justify-end gap-1">
          <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => openEdit(row)} title="Edit">
            <Edit size={12} />
          </Button>
          <Button
            variant="ghost"
            className="!p-1.5 !shadow-none"
            onClick={() => navigate(`/dashboard/policies?tenant_id=${encodeURIComponent(row.tenant_id || '')}&gateway_id=${encodeURIComponent(row.gateway_id || '')}&resource_id=${encodeURIComponent(row.id)}`)}
            title="View policies"
          >
            <Shield size={12} />
          </Button>
          <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => handleRegenSecret(row)} title="Regenerate secret">
            <Key size={12} />
          </Button>
          <Button variant="ghost" className="!p-1.5 !shadow-none !text-danger hover:!bg-danger-muted" onClick={() => handleDelete(row.id)} title="Delete">
            <Trash2 size={12} />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Resources" subtitle="Attach WEB, SSH, and RDP resources to a tenant gateway" createLabel="Add Resource" onCreate={() => openCreate()} />

      {error && (
        <div className="bg-danger-muted border border-danger rounded-md p-3 mb-4 text-sm text-danger">
          {error}
        </div>
      )}

      <DataTable
        columns={columns}
        data={resources}
        loading={loading}
        emptyIcon={Server}
        emptyTitle="No resources configured"
        emptyMessage="Create a gateway first, then attach protected resources to it."
      />

      <Modal
        open={!!credModal}
        onClose={() => { setCredModal(null); setShowSecret(false); }}
        title="Resource Credentials"
        size="md"
        footer={<Button onClick={() => { setCredModal(null); setShowSecret(false); }}>Done</Button>}
      >
        {credModal && (
          <>
            <FormField label="Resource">
              <div className="bg-surface-secondary border border-border rounded-md px-3 py-2 font-mono text-[13px] text-text-primary">{credModal.name}</div>
            </FormField>
            <FormField label="Client ID">
              <div className="flex items-center gap-2 bg-surface-secondary border border-border rounded-md px-3 py-2 font-mono text-[13px]">
                <code className="flex-1 min-w-0 break-all text-text-primary">{credModal.client_id}</code>
                <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => copyText(credModal.client_id)}><Copy size={12} /></Button>
              </div>
            </FormField>
            <FormField label="Client Secret">
              <div className="flex items-center gap-2 bg-surface-secondary border border-border rounded-md px-3 py-2 font-mono text-[13px]">
                <code className="flex-1 min-w-0 break-all text-text-primary">{showSecret ? credModal.client_secret : 'hidden'}</code>
                <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => setShowSecret(!showSecret)}>
                  {showSecret ? <EyeOff size={12} /> : <Eye size={12} />}
                </Button>
                <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => copyText(credModal.client_secret)}><Copy size={12} /></Button>
              </div>
            </FormField>
          </>
        )}
      </Modal>

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
          <FormField label="Tenant" className="mb-0 md:col-span-2">
            <FormSelect value={form.tenant_id || ''} onChange={(e) => selectTenant(e.target.value)}>
              <option value="">Select tenant</option>
              {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
            </FormSelect>
          </FormField>
          <FormField label="Gateway" className="mb-0 md:col-span-2">
            <FormSelect value={form.gateway_id || ''} onChange={(e) => setForm({ ...form, gateway_id: e.target.value })}>
              <option value="">Select gateway</option>
              {gatewaysForTenant(form.tenant_id).map((gateway) => (
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
