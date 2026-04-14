import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getResources, createResource, updateResource, deleteResource, generateCert, regenerateSecret } from '../api';
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
  const [modal, setModal] = useState(null); // null | 'create' | 'edit'
  const [certModal, setCertModal] = useState(null); // resource id
  const [credModal, setCredModal] = useState(null); // {client_id, client_secret, name}
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
        // Show credentials modal with the newly created resource's keys
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

  if (loading) return <div className="loading"><div className="spinner" /> Loading resources...</div>;

  return (
    <>
      <div className="page-header">
        <h2>Resources</h2>
        <p>Manage protected applications and services</p>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{resources.length} Resource{resources.length !== 1 ? 's' : ''}</h3>
          <div style={{ position: 'relative' }}>
            <button className="btn btn-primary" onClick={() => setAddMenuOpen(!addMenuOpen)}><Plus size={14} /> Add Application <ChevronDown size={12} /></button>
            {addMenuOpen && (
              <div style={{
                position: 'absolute', right: 0, top: '100%', marginTop: 6, zIndex: 50,
                background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
                boxShadow: '0 8px 24px rgba(0,0,0,0.3)', minWidth: 220, overflow: 'hidden',
              }}>
                {[
                  { type: 'web', label: 'Web Application', icon: Globe, color: '#3b82f6' },
                  { type: 'ssh', label: 'SSH Server', icon: Terminal, color: '#22c55e' },
                  { type: 'rdp', label: 'RDP Server', icon: Monitor, color: '#a855f7' },
                  { type: 'gateway', label: 'Gateway', icon: Router, color: '#f59e0b' },
                ].map(({ type, label, icon: Icon, color }) => (
                  <button
                    key={type}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10, width: '100%',
                      padding: '10px 16px', border: 'none', background: 'transparent',
                      color: 'var(--text-primary)', fontSize: 13, cursor: 'pointer',
                      transition: 'background 0.15s',
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-secondary)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                    onClick={() => { setAddMenuOpen(false); navigate(`/dashboard/protect-app?type=${type}`); }}
                  >
                    <Icon size={16} color={color} />
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Client ID</th>
                <th>Host</th>
                <th>Port</th>
                <th>Certificate</th>
                <th>Status</th>
                <th>MFA</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {resources.length === 0 ? (
                <tr>
                  <td colSpan={9}>
                    <div className="empty-state">
                      <Server size={40} />
                      <p>No resources configured. Add your first resource to get started.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                resources.map((res) => (
                  <tr key={res.id}>
                    <td>
                      <strong style={{ color: 'var(--text-primary)' }}>{res.name}</strong>
                      {res.description && <div className="text-sm text-muted">{res.description}</div>}
                    </td>
                    <td><span className={`badge badge-${res.type}`}>{res.type}</span></td>
                    <td>
                      <span className="text-mono text-sm" title={res.client_id}>
                        {res.client_id ? res.client_id.slice(0, 10) + '...' : '—'}
                      </span>
                    </td>
                    <td className="text-mono">{res.host}</td>
                    <td className="text-mono">{res.port || '—'}</td>
                    <td>
                      <span className="text-sm">
                        {res.cert_mode === 'self-signed' && <span className="text-warning">Self-Signed</span>}
                        {res.cert_mode === 'letsencrypt' && <span className="text-success">Let's Encrypt</span>}
                        {res.cert_mode === 'manual' && <span className="text-muted">Manual</span>}
                        {res.cert_expiry && (
                          <div className="text-muted text-sm">Exp: {formatDate(res.cert_expiry)}</div>
                        )}
                      </span>
                    </td>
                    <td>
                      <span className={`badge badge-${res.enabled ? 'enabled' : 'disabled'}`}>
                        {res.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td>{res.require_mfa ? <ShieldCheck size={16} color="var(--warning)" /> : '—'}</td>
                    <td>
                      <div className="flex gap-2">
                        <button className="btn btn-secondary btn-sm" onClick={() => navigate(`/dashboard/protect-app?id=${res.id}`)} title="Edit">
                          <Edit size={12} />
                        </button>
                        <button className="btn btn-secondary btn-sm" onClick={() => handleRegenSecret(res.id)} title="Regenerate Secret">
                          <Key size={12} />
                        </button>
                        <button className="btn btn-secondary btn-sm" onClick={() => setCertModal(res.id)} title="Generate Cert">
                          <RefreshCw size={12} />
                        </button>
                        <button className="btn btn-danger btn-sm" onClick={() => handleDelete(res.id)} title="Delete">
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Credentials Modal — shown after create or regenerate */}
      {credModal && (
        <div className="modal-overlay" onClick={() => { setCredModal(null); setShowSecret(false); }}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 520 }}>
            <div className="modal-header">
              <h3>Application Credentials</h3>
              <button className="modal-close" onClick={() => { setCredModal(null); setShowSecret(false); }}><X size={18} /></button>
            </div>
            <div className="modal-body">
              <p className="text-sm" style={{ marginBottom: 16, color: 'var(--warning)' }}>
                <strong>Save these credentials now.</strong> The secret will not be shown again unless regenerated.
              </p>
              <div className="form-group">
                <label>Application Name</label>
                <div className="cred-display">{credModal.name}</div>
              </div>
              <div className="form-group">
                <label>Client ID (Integration Key)</label>
                <div className="cred-display cred-copy">
                  <code>{credModal.client_id}</code>
                  <button className="btn btn-secondary btn-sm" onClick={() => copyText(credModal.client_id)} title="Copy"><Copy size={12} /></button>
                </div>
              </div>
              <div className="form-group">
                <label>Client Secret (Secret Key)</label>
                <div className="cred-display cred-copy">
                  <code>{showSecret ? credModal.client_secret : '••••••••••••••••••••••••••••••••••••••••'}</code>
                  <button className="btn btn-secondary btn-sm" onClick={() => setShowSecret(!showSecret)} title={showSecret ? 'Hide' : 'Show'}>
                    {showSecret ? <EyeOff size={12} /> : <Eye size={12} />}
                  </button>
                  <button className="btn btn-secondary btn-sm" onClick={() => copyText(credModal.client_secret)} title="Copy"><Copy size={12} /></button>
                </div>
              </div>
              <div className="form-group">
                <label>API Hostname</label>
                <div className="cred-display cred-copy">
                  <code>{window.location.origin}</code>
                  <button className="btn btn-secondary btn-sm" onClick={() => copyText(window.location.origin)} title="Copy"><Copy size={12} /></button>
                </div>
              </div>
              <div style={{ marginTop: 16, padding: '12px 16px', background: 'var(--bg-secondary)', borderRadius: 8, fontSize: 13, color: 'var(--text-secondary)' }}>
                Enter these credentials in your <strong>Gateway Admin → Applications → Add</strong> to protect this application.
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-primary" onClick={() => { setCredModal(null); setShowSecret(false); }}>Done</button>
            </div>
          </div>
        </div>
      )}

      {/* Create/Edit Modal */}
      {modal && (
        <div className="modal-overlay" onClick={() => setModal(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{modal === 'create' ? 'Add Resource' : 'Edit Resource'}</h3>
              <button className="modal-close" onClick={() => setModal(null)}><X size={18} /></button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Name</label>
                <input className="form-input" value={form.name || ''} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Production SSH Server" />
              </div>
              <div className="form-group">
                <label>Description</label>
                <input className="form-input" value={form.description || ''} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Optional description" />
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Type</label>
                  <select
                    className="form-select"
                    value={form.type || 'ssh'}
                    onChange={(e) => setForm({ ...form, type: e.target.value, port: defaultPort(e.target.value) })}
                  >
                    {typeOptions.map((t) => (
                      <option key={t} value={t}>{t.toUpperCase()}</option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label>Port</label>
                  <input className="form-input" type="number" value={form.port || ''} onChange={(e) => setForm({ ...form, port: e.target.value })} />
                </div>
              </div>
              <div className="form-group">
                <label>Host</label>
                <input className="form-input" value={form.host || ''} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="10.0.0.5 or server.internal" />
              </div>
              {form.type === 'web' && (
                <div className="form-group">
                  <label>External URL</label>
                  <input className="form-input" value={form.external_url || ''} onChange={(e) => setForm({ ...form, external_url: e.target.value })} placeholder="https://app.example.com" />
                </div>
              )}
              <div className="form-row">
                <div className="form-group">
                  <label>Certificate Mode</label>
                  <select className="form-select" value={form.cert_mode || 'self-signed'} onChange={(e) => setForm({ ...form, cert_mode: e.target.value })}>
                    {certModes.map((m) => (
                      <option key={m} value={m}>{m === 'letsencrypt' ? "Let's Encrypt" : m.charAt(0).toUpperCase() + m.slice(1)}</option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label>Certificate Domain</label>
                  <input className="form-input" value={form.cert_domain || ''} onChange={(e) => setForm({ ...form, cert_domain: e.target.value })} placeholder="auto from host" />
                </div>
              </div>
              <div className="form-group">
                <label>Allowed Roles (comma-separated)</label>
                <input className="form-input" value={form.allowed_roles || ''} onChange={(e) => setForm({ ...form, allowed_roles: e.target.value })} placeholder="admin, user" />
              </div>
              <div className="form-group">
                <label>Tags (comma-separated)</label>
                <input className="form-input" value={form.tags || ''} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="production, critical" />
              </div>
              <div className="form-row">
                <div className="form-checkbox">
                  <input type="checkbox" checked={form.enabled ?? true} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                  <label>Enabled</label>
                </div>
                <div className="form-checkbox">
                  <input type="checkbox" checked={form.require_mfa ?? false} onChange={(e) => setForm({ ...form, require_mfa: e.target.checked })} />
                  <label>Require MFA</label>
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setModal(null)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                {saving ? 'Saving...' : modal === 'create' ? 'Create Resource' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Generate Cert Modal */}
      {certModal && (
        <div className="modal-overlay" onClick={() => setCertModal(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 400 }}>
            <div className="modal-header">
              <h3>Generate Certificate</h3>
              <button className="modal-close" onClick={() => setCertModal(null)}><X size={18} /></button>
            </div>
            <div className="modal-body">
              <p className="text-sm text-muted" style={{ marginBottom: 16 }}>
                This will generate a new self-signed ECDSA P-256 certificate (365 days) for this resource.
              </p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setCertModal(null)}>Cancel</button>
              <button className="btn btn-primary" onClick={() => handleGenerateCert(certModal)} disabled={saving}>
                {saving ? 'Generating...' : 'Generate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
