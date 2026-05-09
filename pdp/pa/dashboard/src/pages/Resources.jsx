import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getResources, createResource, updateResource, deleteResource, generateCert, regenerateSecret } from '../api';
import PageHeader from '../components/ui/PageHeader';
import Modal from '../components/ui/Modal';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import FormField, { FormInput, FormSelect, FormRow, FormCheckbox } from '../components/ui/FormField';
import { Plus, Trash2, Edit, RefreshCw, ShieldCheck, X, Server, Copy, Key, Eye, EyeOff, Globe, Terminal, Monitor, Router, ChevronDown } from 'lucide-react';

const typeOptions = ['ssh', 'rdp', 'web', 'gateway'];
const certModes = ['manual', 'self-signed', 'letsencrypt'];

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('ro-RO');
}

function copyText(text) {
  navigator.clipboard.writeText(text).catch(() => {});
}

export default function Resources() {
  const [resources, setResources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [certModal, setCertModal] = useState(null);
  const [credModal, setCredModal] = useState(null);
  const [showSecret, setShowSecret] = useState(false);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const navigate = useNavigate();

  const load = () => {
    setLoading(true);
    getResources()
      .then((data) => setResources(Array.isArray(data) ? data : []))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const openCreate = () => {
    setForm({
      name: '', description: '', type: 'ssh', host: '', port: 22,
      external_url: '', enabled: true, cert_mode: 'self-signed',
      cert_domain: '', allowed_roles: '', require_mfa: false, tags: '',
    });
    setModal('create');
  };

  const openEdit = (res) => {
    setForm({
      ...res,
      allowed_roles: (res.allowed_roles || []).join(', '),
      tags: (res.tags || []).join(', '),
    });
    setModal('edit');
  };

  const handleSave = async () => {
    setSaving(true);
    const data = {
      ...form,
      port: parseInt(form.port) || 0,
      allowed_roles: form.allowed_roles ? form.allowed_roles.split(',').map(s => s.trim()).filter(Boolean) : [],
      tags: form.tags ? form.tags.split(',').map(s => s.trim()).filter(Boolean) : [],
    };

    try {
      if (modal === 'create') {
        const created = await createResource(data);
        setModal(null);
        if (created && created.client_id) {
          setShowSecret(true);
          setCredModal({ client_id: created.client_id, client_secret: created.client_secret, name: created.name });
        }
      } else {
        await updateResource(form.id, data);
        setModal(null);
      }
      load();
    } catch (e) {
      console.error(e);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this resource?')) return;
    await deleteResource(id);
    load();
  };

  const handleGenerateCert = async (id) => {
    const res = resources.find(r => r.id === id);
    setSaving(true);
    try {
      await generateCert(id, res?.cert_domain || res?.host, 365);
      setCertModal(null);
      load();
    } catch(e) {
      console.error(e);
    } finally {
      setSaving(false);
    }
  };

  const handleRegenSecret = async (id) => {
    if (!confirm('Regenerate secret? The gateway will need to re-link with the new secret.')) return;
    setSaving(true);
    try {
      const result = await regenerateSecret(id);
      if (result && result.client_id) {
        const res = resources.find(r => r.id === id);
        setShowSecret(true);
        setCredModal({ client_id: result.client_id, client_secret: result.client_secret, name: res?.name || '' });
      }
      load();
    } catch(e) {
      console.error(e);
    } finally {
      setSaving(false);
    }
  };

  const defaultPort = (type) => {
    switch (type) {
      case 'ssh': return 22;
      case 'rdp': return 3389;
      case 'web': return 443;
      case 'gateway': return 9443;
      default: return 0;
    }
  };

  const columns = [
    { key: 'name', label: 'Name', render: (v, row) => (
      <div>
        <span className="font-semibold text-text-primary text-xs">{v}</span>
        {row.description && <div className="text-xs text-text-muted">{row.description}</div>}
      </div>
    )},
    { key: 'type', label: 'Type', render: (v) => <Badge variant={v === 'web' ? 'info' : v === 'ssh' ? 'success' : v === 'rdp' ? 'accent' : 'warning'}>{v}</Badge> },
    { key: 'client_id', label: 'Client ID', render: (v) => <span className="text-mono text-xs" title={v}>{v ? v.slice(0, 10) + '...' : '—'}</span> },
    { key: 'host', label: 'Host', render: (v) => <span className="text-mono text-xs">{v}</span> },
    { key: 'port', label: 'Port', render: (v) => <span className="text-mono text-xs">{v || '—'}</span> },
    { key: 'cert_mode', label: 'Certificate', render: (v, row) => (
      <span className="text-xs">
        {v === 'self-signed' && <span className="text-warning">Self-Signed</span>}
        {v === 'letsencrypt' && <span className="text-success">Let's Encrypt</span>}
        {v === 'manual' && <span className="text-text-muted">Manual</span>}
        {row.cert_expiry && <div className="text-text-muted text-[11px]">Exp: {formatDate(row.cert_expiry)}</div>}
      </span>
    )},
    { key: 'enabled', label: 'Status', render: (v) => <Badge variant={v ? 'success' : 'danger'}>{v ? 'Enabled' : 'Disabled'}</Badge> },
    { key: 'require_mfa', label: 'MFA', render: (v) => v ? <ShieldCheck size={16} className="text-warning" /> : '—' },
    { key: 'actions', label: 'Actions', align: 'right', render: (_, row) => (
      <div className="flex items-center justify-end gap-1">
        <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => navigate(`/dashboard/protect-app?id=${row.id}`)} title="Edit"><Edit size={12} /></Button>
        <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => handleRegenSecret(row.id)} title="Regenerate Secret"><Key size={12} /></Button>
        <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => setCertModal(row.id)} title="Generate Cert"><RefreshCw size={12} /></Button>
        <Button variant="ghost" className="!p-1.5 !shadow-none !text-danger hover:!bg-danger-muted" onClick={() => handleDelete(row.id)} title="Delete"><Trash2 size={12} /></Button>
      </div>
    )},
  ];

  const addMenuItems = [
    { type: 'web', label: 'Web Application', icon: Globe, iconClass: 'text-info' },
    { type: 'ssh', label: 'SSH Server', icon: Terminal, iconClass: 'text-success' },
    { type: 'rdp', label: 'RDP Server', icon: Monitor, iconClass: 'text-accent' },
    { type: 'gateway', label: 'Gateway', icon: Router, iconClass: 'text-warning' },
  ];

  return (
    <>
      <PageHeader title="Resources" subtitle="Manage protected applications and services" />

      {/* Type selector dropdown */}
      <div className="flex justify-end mb-4 relative">
        <button className="inline-flex items-center gap-1.5 px-4 py-2 bg-accent text-white rounded-md hover:bg-accent-hover transition-colors font-semibold text-xs shadow-sm"
                onClick={() => setAddMenuOpen(!addMenuOpen)}>
          <Plus size={14} /> Add Application <ChevronDown size={12} />
        </button>
        {addMenuOpen && (
          <div className="absolute right-0 top-full mt-1.5 z-50 bg-surface-card border border-border rounded-md shadow-lg min-w-[220px] overflow-hidden">
            {addMenuItems.map(({ type, label, icon: Icon, iconClass }) => (
              <button key={type}
                      className="flex items-center gap-2.5 w-full px-4 py-2.5 text-[13px] text-text-primary bg-transparent border-none cursor-pointer transition-colors hover:bg-surface-secondary"
                      onClick={() => { setAddMenuOpen(false); navigate(`/dashboard/protect-app?type=${type}`); }}>
                <Icon size={16} className={iconClass} />
                {label}
              </button>
            ))}
          </div>
        )}
      </div>

      <DataTable columns={columns} data={resources} loading={loading} emptyIcon={Server} emptyTitle="No resources configured" emptyMessage="Add your first resource to get started." />

      {/* Credentials Modal */}
      <Modal open={!!credModal} onClose={() => { setCredModal(null); setShowSecret(false); }} title="Application Credentials" size="md"
        footer={<Button onClick={() => { setCredModal(null); setShowSecret(false); }}>Done</Button>}>
        {credModal && (
          <>
            <div className="p-3 bg-warning-muted text-warning rounded-md text-xs font-medium">
              <strong>Save these credentials now.</strong> The secret will not be shown again unless regenerated.
            </div>
            <FormField label="Application Name">
              <div className="bg-surface-secondary border border-border rounded-md px-3 py-2 font-mono text-[13px] text-text-primary">{credModal.name}</div>
            </FormField>
            <FormField label="Client ID (Integration Key)">
              <div className="flex items-center gap-2 bg-surface-secondary border border-border rounded-md px-3 py-2 font-mono text-[13px]">
                <code className="flex-1 min-w-0 break-all text-text-primary">{credModal.client_id}</code>
                <Button variant="ghost" className="!p-1.5 !shadow-none flex-shrink-0" onClick={() => copyText(credModal.client_id)}><Copy size={12} /></Button>
              </div>
            </FormField>
            <FormField label="Client Secret (Secret Key)">
              <div className="flex items-center gap-2 bg-surface-secondary border border-border rounded-md px-3 py-2 font-mono text-[13px]">
                <code className="flex-1 min-w-0 break-all text-text-primary">{showSecret ? credModal.client_secret : '••••••••••••••••••••••••••••••••••••••••'}</code>
                <Button variant="ghost" className="!p-1.5 !shadow-none flex-shrink-0" onClick={() => setShowSecret(!showSecret)}>
                  {showSecret ? <EyeOff size={12} /> : <Eye size={12} />}
                </Button>
                <Button variant="ghost" className="!p-1.5 !shadow-none flex-shrink-0" onClick={() => copyText(credModal.client_secret)}><Copy size={12} /></Button>
              </div>
            </FormField>
            <FormField label="API Hostname">
              <div className="flex items-center gap-2 bg-surface-secondary border border-border rounded-md px-3 py-2 font-mono text-[13px]">
                <code className="flex-1 min-w-0 break-all text-text-primary">{window.location.origin}</code>
                <Button variant="ghost" className="!p-1.5 !shadow-none flex-shrink-0" onClick={() => copyText(window.location.origin)}><Copy size={12} /></Button>
              </div>
            </FormField>
            <div className="mt-4 p-3 bg-surface-secondary rounded-md text-[13px] text-text-secondary">
              Enter these credentials in your <strong>Gateway Admin → Applications → Add</strong> to protect this application.
            </div>
          </>
        )}
      </Modal>

      {/* Create/Edit Modal */}
      <Modal open={!!modal} onClose={() => setModal(null)} title={modal === 'create' ? 'Add Resource' : 'Edit Resource'} size="lg"
        footer={
          <>
            <Button variant="secondary" onClick={() => setModal(null)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? 'Saving...' : modal === 'create' ? 'Create Resource' : 'Save Changes'}
            </Button>
          </>
        }>
        <FormField label="Name">
          <FormInput value={form.name || ''} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Production SSH Server" />
        </FormField>
        <FormField label="Description">
          <FormInput value={form.description || ''} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Optional description" />
        </FormField>
        <FormRow>
          <FormField label="Type">
            <FormSelect value={form.type || 'ssh'} onChange={(e) => setForm({ ...form, type: e.target.value, port: defaultPort(e.target.value) })}>
              {typeOptions.map((t) => <option key={t} value={t}>{t.toUpperCase()}</option>)}
            </FormSelect>
          </FormField>
          <FormField label="Port">
            <FormInput type="number" value={form.port || ''} onChange={(e) => setForm({ ...form, port: e.target.value })} />
          </FormField>
        </FormRow>
        <FormField label="Host">
          <FormInput value={form.host || ''} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="10.0.0.5 or server.internal" />
        </FormField>
        {form.type === 'web' && (
          <FormField label="External URL">
            <FormInput value={form.external_url || ''} onChange={(e) => setForm({ ...form, external_url: e.target.value })} placeholder="https://app.example.com" />
          </FormField>
        )}
        <FormRow>
          <FormField label="Certificate Mode">
            <FormSelect value={form.cert_mode || 'self-signed'} onChange={(e) => setForm({ ...form, cert_mode: e.target.value })}>
              {certModes.map((m) => <option key={m} value={m}>{m === 'letsencrypt' ? "Let's Encrypt" : m.charAt(0).toUpperCase() + m.slice(1)}</option>)}
            </FormSelect>
          </FormField>
          <FormField label="Certificate Domain">
            <FormInput value={form.cert_domain || ''} onChange={(e) => setForm({ ...form, cert_domain: e.target.value })} placeholder="auto from host" />
          </FormField>
        </FormRow>
        <FormField label="Allowed Roles (comma-separated)">
          <FormInput value={form.allowed_roles || ''} onChange={(e) => setForm({ ...form, allowed_roles: e.target.value })} placeholder="admin, user" />
        </FormField>
        <FormField label="Tags (comma-separated)">
          <FormInput value={form.tags || ''} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="production, critical" />
        </FormField>
        <FormRow>
          <FormCheckbox id="res-enabled" checked={form.enabled ?? true} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} label="Enabled" />
          <FormCheckbox id="res-mfa" checked={form.require_mfa ?? false} onChange={(e) => setForm({ ...form, require_mfa: e.target.checked })} label="Require MFA" />
        </FormRow>
      </Modal>

      {/* Generate Cert Modal */}
      <Modal open={!!certModal} onClose={() => setCertModal(null)} title="Generate Certificate" size="sm"
        footer={
          <>
            <Button variant="secondary" onClick={() => setCertModal(null)}>Cancel</Button>
            <Button onClick={() => handleGenerateCert(certModal)} disabled={saving}>
              {saving ? 'Generating...' : 'Generate'}
            </Button>
          </>
        }>
        <p className="text-sm text-text-muted">
          This will generate a new self-signed ECDSA P-256 certificate (365 days) for this resource.
        </p>
      </Modal>
    </>
  );
}
