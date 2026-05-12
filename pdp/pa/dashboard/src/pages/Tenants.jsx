import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  getTenants, createTenant, updateTenant, deleteTenant,
  getIdPs, createIdP, updateIdP, deleteIdP, discoverIdP,
} from '../api';
import {
  Plus, Trash2, Edit, X, Building2, Globe, Router, Shield,
  ChevronDown, Key, Users, CheckCircle2, AlertCircle, Loader2, Star,
} from 'lucide-react';

// eslint-disable-next-line no-unused-vars
function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('ro-RO');
}

export default function Tenants() {
  const [tenants, setTenants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null); // null | 'create' | 'edit' | 'idp'
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const navigate = useNavigate();

  // IdP state
  const [idpTenantId, setIdpTenantId] = useState('');
  const [idps, setIdps] = useState([]);
  const [idpLoading, setIdpLoading] = useState(false);
  const [idpModal, setIdpModal] = useState(null); // null | 'create' | 'edit'
  const [idpForm, setIdpForm] = useState({});
  const [idpSaving, setIdpSaving] = useState(false);
  const [idpError, setIdpError] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);
  const [idpAdvancedOpen, setIdpAdvancedOpen] = useState(false);

  const load = () => {
    setLoading(true);
    getTenants()
      .then((data) => setTenants(Array.isArray(data) ? data : []))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const openCreate = () => {
    setForm({ name: '', domain: '', domains: '', description: '', enabled: true });
    setModal('create');
    setAddMenuOpen(false);
  };

  const openEdit = (t) => {
    setForm({
      ...t,
      domains: Array.isArray(t.domains) ? t.domains.join(', ') : (t.domains || ''),
    });
    setModal('edit');
  };

  const handleSave = async () => {
    setSaving(true);
    const payload = {
      ...form,
      domains: form.domains ? form.domains.split(',').map((d) => d.trim()).filter(Boolean) : [],
    };
    try {
      if (modal === 'create') {
        await createTenant(payload);
      } else {
        await updateTenant(form.id, payload);
      }
      setModal(null);
      load();
    } catch (e) {
      console.error(e);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this tenant? All associated gateways, resources, and policies will be orphaned.')) return;
    await deleteTenant(id);
    load();
  };

  const createGateway = (tenant) => {
    navigate(`/dashboard/gateways?tenant_id=${tenant.id}`);
  };

  // ─── IdP Management ────────────────────────

  const openIdPManager = (tenant) => {
    setIdpTenantId(tenant.id);
    setIdpModal(null);
    setIdpForm({});
    setTestResult(null);
    setIdpAdvancedOpen(false);
    setModal('idp');
    loadIdPs(tenant.id);
  };

  const loadIdPs = (tid) => {
    setIdpLoading(true);
    setIdpError('');
    getIdPs(tid)
      .then((data) => setIdps(Array.isArray(data) ? data : []))
      .catch((e) => setIdpError(e.message || 'Failed to load IdPs'))
      .finally(() => setIdpLoading(false));
  };

  const openIdpCreate = () => {
    setIdpForm({
      name: '',
      type: 'oidc',
      issuer: '',
      client_id: '',
      client_secret: '',
      scopes: 'openid profile email',
      domains: '',
      enabled: true,
      auto_discovery: true,
      claim_username: 'preferred_username',
      claim_email: 'email',
      claim_groups: 'groups',
      group_role_mapping: [],
      is_default: idps.length === 0,
      has_client_secret: false,
    });
    setIdpError('');
    setTestResult(null);
    setIdpAdvancedOpen(false);
    setIdpModal('create');
  };

  const openIdpEdit = (idp) => {
    const cm = idp.claim_mapping || {};
    const grm = idp.group_role_mapping || [];
    setIdpForm({
      id: idp.id,
      name: idp.name || '',
      type: idp.type || 'oidc',
      issuer: idp.issuer || '',
      client_id: idp.client_id || '',
      client_secret: '',
      scopes: idp.scopes || 'openid profile email',
      domains: Array.isArray(idp.domains) ? idp.domains.join(', ') : (idp.domains || ''),
      enabled: idp.enabled !== false,
      auto_discovery: idp.auto_discovery !== false,
      claim_username: cm.username || 'preferred_username',
      claim_email: cm.email || 'email',
      claim_groups: cm.groups || 'groups',
      group_role_mapping: grm,
      is_default: idp.is_default === true,
      has_client_secret: idp.has_client_secret === true,
    });
    setIdpAdvancedOpen(
      grm.length > 0
      || (cm.username && cm.username !== 'preferred_username')
      || (cm.email && cm.email !== 'email')
      || (cm.groups && cm.groups !== 'groups')
    );
    setTestResult(null);
    setIdpModal('edit');
  };

  const handleIdpSave = async () => {
    setIdpError('');
    if (!idpForm.name.trim() || !idpForm.issuer.trim() || !idpForm.client_id.trim()) {
      setIdpError('Name, Issuer URL, and OIDC Client ID are required');
      return;
    }
    setIdpSaving(true);
    try {
      const payload = {
        name: idpForm.name.trim(),
        type: idpForm.type,
        issuer: idpForm.issuer.trim(),
        client_id: idpForm.client_id.trim(),
        client_secret: idpForm.client_secret || undefined,
        scopes: idpForm.scopes.trim(),
        domains: idpForm.domains
          ? idpForm.domains.split(',').map((d) => d.trim()).filter(Boolean)
          : [],
        enabled: idpForm.enabled,
        auto_discovery: idpForm.auto_discovery,
        claim_mapping: {
          username: idpForm.claim_username.trim() || 'preferred_username',
          email: idpForm.claim_email.trim() || 'email',
          groups: idpForm.claim_groups.trim() || 'groups',
        },
        group_role_mapping: idpForm.group_role_mapping || [],
        is_default: idpForm.enabled !== false && idpForm.is_default === true,
      };

      if (idpModal === 'create') {
        await createIdP(idpTenantId, payload);
      } else {
        await updateIdP(idpForm.id, payload);
      }

      loadIdPs(idpTenantId);
      load();
      setIdpModal(null);
    } catch (e) {
      setIdpError(e.message || 'Failed to save IdP');
    } finally {
      setIdpSaving(false);
    }
  };

  const handleIdpDelete = async (id) => {
    if (!confirm('Delete this Identity Provider?')) return;
    setIdpError('');
    try {
      await deleteIdP(id);
      loadIdPs(idpTenantId);
      load();
    } catch (e) {
      setIdpError(e.message || 'Failed to delete IdP');
    }
  };

  const handleSetDefaultIdp = async (idp) => {
    if (!idp?.id || idp.is_default) return;
    setIdpError('');
    try {
      await updateIdP(idp.id, { is_default: true });
      loadIdPs(idpTenantId);
      load();
    } catch (e) {
      setIdpError(e.message || 'Failed to update default IdP');
    }
  };

  const handleTestConnection = async () => {
    setIdpError('');
    setTesting(true);
    setTestResult(null);
    try {
      const r = await discoverIdP(idpForm.issuer.trim());
      setTestResult(r);
    } catch (e) {
      setTestResult({ ok: false, error: e.message || 'Discovery probe failed' });
    } finally {
      setTesting(false);
    }
  };

  const addGroupRule = () => {
    setIdpForm((f) => ({
      ...f,
      group_role_mapping: [...(f.group_role_mapping || []), { group_name: '', role: 'user' }],
    }));
  };

  const updateGroupRule = (index, field, value) => {
    setIdpForm((f) => {
      const rules = [...(f.group_role_mapping || [])];
      rules[index] = { ...rules[index], [field]: value };
      return { ...f, group_role_mapping: rules };
    });
  };

  const removeGroupRule = (index) => {
    setIdpForm((f) => {
      const rules = (f.group_role_mapping || []).filter((_, i) => i !== index);
      return { ...f, group_role_mapping: rules };
    });
  };

  const statusBadge = (enabled) => (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide ${
      enabled ? 'bg-success-muted text-success' : 'bg-surface-secondary text-text-muted'
    }`}>
      {enabled ? 'Active' : 'Inactive'}
    </span>
  );

  const idpTenantName = tenants.find((t) => t.id === idpTenantId)?.name || '';
  const federatedCallbackURL = 'https://localhost:8443/auth/federated/callback';
  const idpLabelClass = 'block text-[10px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5';
  const idpInputClass = 'w-full h-9 px-3 bg-surface border border-border rounded text-[12px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition-colors';
  const idpMonoInputClass = `${idpInputClass} font-mono`;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-bold tracking-[-0.3px] text-text-primary">Tenants</h1>
          <p className="text-xs text-text-secondary mt-0.5 font-medium">Manage organizations, identity providers, and gateways</p>
        </div>
        <div className="relative">
          <button
            onClick={() => setAddMenuOpen(!addMenuOpen)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-md hover:bg-accent-hover transition-colors font-semibold text-xs shadow-sm"
          >
            <Plus size={16} />
            Create Tenant
            <ChevronDown size={14} />
          </button>
          {addMenuOpen && (
            <div className="absolute right-0 mt-2 w-56 bg-surface-card rounded-md shadow-lg border border-border py-1 z-10">
              <button
                onClick={openCreate}
                className="w-full text-left px-4 py-2 text-sm text-text-secondary hover:bg-surface-hover flex items-center gap-2"
              >
                <Building2 size={16} className="text-accent" />
                New Organization
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="bg-surface-card rounded-md border border-border overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
        {loading ? (
          <div className="p-8 text-center text-text-muted">Loading tenants...</div>
        ) : tenants.length === 0 ? (
          <div className="p-8 text-center text-text-muted">
            <Building2 size={48} className="mx-auto mb-3 opacity-40" />
            <p className="text-sm font-medium text-text-primary">No tenants yet</p>
            <p className="text-xs mt-1">Create the first organization to start managing gateways and resources.</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-surface-secondary">
                <th className="text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">Name</th>
                <th className="text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">Domain</th>
                <th className="text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">IdP</th>
                <th className="text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">Status</th>
                <th className="text-right px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {tenants.map((t) => (
                <tr key={t.id} className="hover:bg-surface-hover transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-md bg-accent-muted flex items-center justify-center">
                        <Building2 size={16} className="text-accent" />
                      </div>
                      <div>
                        <p className="font-medium text-text-primary text-xs">{t.name}</p>
                        {t.description && <p className="text-[11px] text-text-muted mt-0.5">{t.description}</p>}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-1.5">
                      <Globe size={14} className="text-text-muted" />
                      <span className="text-xs text-text-secondary font-mono">{t.domain || '—'}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-xs text-text-muted">
                      {t.default_idp_id ? (
                        <span className="inline-flex items-center gap-1 text-accent font-semibold">
                          <Shield size={12} /> Configured
                        </span>
                      ) : '—'}
                    </span>
                  </td>
                  <td className="px-6 py-4">{statusBadge(t.enabled)}</td>
                  <td className="px-6 py-4">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => openIdPManager(t)}
                        className="p-1.5 text-accent hover:bg-accent-muted rounded-md transition-colors"
                        title="Manage Identity Providers"
                      >
                        <Shield size={16} />
                      </button>
                      <button
                        onClick={() => createGateway(t)}
                        className="p-1.5 text-text-secondary hover:bg-surface-hover rounded-md transition-colors"
                        title="Create Gateway for this tenant"
                      >
                        <Router size={16} />
                      </button>
                      <button
                        onClick={() => openEdit(t)}
                        className="p-1.5 text-text-secondary hover:bg-surface-hover rounded-md transition-colors"
                        title="Edit tenant"
                      >
                        <Edit size={16} />
                      </button>
                      <button
                        onClick={() => handleDelete(t.id)}
                        className="p-1.5 text-danger hover:bg-danger-muted rounded-md transition-colors"
                        title="Delete tenant"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ─── Tenant Create/Edit Modal ─── */}
      {modal && (modal === 'create' || modal === 'edit') ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="bg-surface-card rounded-md border border-border shadow-2xl w-full max-w-md mx-4 overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border">
              <h2 className="text-base font-semibold text-text-primary">
                {modal === 'create' ? 'Create Tenant' : 'Edit Tenant'}
              </h2>
              <button onClick={() => setModal(null)} className="p-1 text-text-muted hover:text-text-primary rounded-md">
                <X size={20} />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Name *</label>
                <input type="text" value={form.name || ''} onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition font-sans"
                  placeholder="e.g. Company HQ" />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Domain</label>
                <input type="text" value={form.domain || ''} onChange={(e) => setForm({ ...form, domain: e.target.value })}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition font-mono"
                  placeholder="e.g. company.com" />
                <p className="text-[11px] text-text-muted mt-1">Used for Home Realm Discovery (HRD).</p>
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Additional HRD Domains (comma-separated)</label>
                <input type="text" value={form.domains || ''} onChange={(e) => setForm({ ...form, domains: e.target.value })}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition"
                  placeholder="subsidiary.com, branch.org" />
                <p className="text-[11px] text-text-muted mt-1">Additional email domains for Home Realm Discovery.</p>
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Description</label>
                <textarea value={form.description || ''} onChange={(e) => setForm({ ...form, description: e.target.value })}
                  rows={2}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition resize-none font-sans"
                  placeholder="Optional description..." />
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="tenant-enabled" checked={form.enabled !== false}
                  onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                  className="rounded border-border text-accent focus:ring-accent" />
                <label htmlFor="tenant-enabled" className="text-[13px] text-text-secondary">Enabled</label>
              </div>
            </div>
            <div className="flex justify-end gap-2 px-6 py-4 border-t border-border bg-surface-secondary">
              <button onClick={() => setModal(null)}
                className="px-4 py-2 text-xs font-semibold text-text-secondary hover:text-text-primary">Cancel</button>
              <button onClick={handleSave} disabled={saving || !form.name}
                className="px-4 py-2 text-xs font-semibold bg-accent text-white rounded-md hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                {saving ? 'Saving...' : modal === 'create' ? 'Create' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {/* ─── IdP Manager Modal ─── */}
      {modal === 'idp' ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
          <div className="bg-surface-card rounded-md border border-border shadow-2xl w-[min(920px,calc(100vw-32px))] h-[min(620px,calc(100vh-48px))] overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-surface-card flex-shrink-0">
              <div>
                <h2 className="text-base font-semibold text-text-primary">
                  Identity Providers — {idpTenantName}
                </h2>
                <p className="text-[11px] text-text-muted mt-0.5">OIDC client registrations for this organization</p>
              </div>
              <button onClick={() => setModal(null)} className="p-1 text-text-muted hover:text-text-primary rounded-md">
                <X size={20} />
              </button>
            </div>

            <div className="px-6 py-4 border-b border-border bg-surface-secondary flex-shrink-0">
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-medium text-text-secondary">
                  {idps.length} provider{idps.length === 1 ? '' : 's'} configured
                </span>
                <button onClick={openIdpCreate}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-accent text-white rounded-md hover:bg-accent-hover transition-colors">
                  <Plus size={14} /> Add Provider
                </button>
              </div>
            </div>

            <div className="p-6 overflow-y-auto flex-1">
              {idpError && (
                <div className="bg-danger-muted border border-danger rounded-md p-3 text-sm text-danger mb-4">{idpError}</div>
              )}

              {idpLoading ? (
                <div className="text-center py-10 text-text-muted text-sm">Loading...</div>
              ) : idps.length === 0 ? (
                <div className="text-center py-12 border border-dashed border-border rounded-md">
                  <Shield size={32} className="mx-auto mb-2 opacity-40" />
                  <p className="text-sm font-medium text-text-primary">No identity providers</p>
                  <p className="text-xs text-text-muted mt-1">Add the first OIDC registration for this organization.</p>
                </div>
              ) : (
                <div className="border border-border rounded-md overflow-hidden">
                  <table className="w-full table-fixed">
                    <thead className="bg-surface-secondary">
                      <tr>
                        <th className="w-[23%] text-left px-4 py-2.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.6px]">Provider</th>
                        <th className="w-[18%] text-left px-4 py-2.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.6px]">Client ID</th>
                        <th className="w-[29%] text-left px-4 py-2.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.6px]">Issuer</th>
                        <th className="w-[18%] text-left px-4 py-2.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.6px]">HRD</th>
                        <th className="w-[12%] text-right px-4 py-2.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.6px]">Actions</th>
                    </tr>
                  </thead>
                    <tbody className="divide-y divide-border bg-surface-card">
                    {idps.map((idp) => (
                      <tr key={idp.id} className="hover:bg-surface-hover">
                          <td className="px-4 py-3 align-top">
                            <div className="flex items-start gap-2 min-w-0">
                              <Key size={14} className="text-accent flex-shrink-0 mt-0.5" />
                              <div className="min-w-0">
                                <div className="flex items-center gap-1.5 min-w-0">
                                  <p className="text-xs font-semibold text-text-primary truncate">{idp.name}</p>
                                {idp.is_default ? (
                                    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-semibold bg-accent-muted text-accent flex-shrink-0">
                                    <Star size={9} fill="currentColor" /> Default
                                  </span>
                                ) : null}
                              </div>
                                <div className="mt-1">{statusBadge(idp.enabled)}</div>
                            </div>
                          </div>
                        </td>
                          <td className="px-4 py-3 align-top">
                            <span className="block text-[11px] text-text-secondary font-mono truncate" title={idp.client_id || ''}>{idp.client_id || '-'}</span>
                        </td>
                          <td className="px-4 py-3 align-top">
                            <span className="block text-[11px] text-text-secondary font-mono break-all line-clamp-2" title={idp.issuer || ''}>{idp.issuer || '-'}</span>
                        </td>
                          <td className="px-4 py-3 align-top">
                          <div className="flex flex-wrap gap-1">
                            {(Array.isArray(idp.domains) && idp.domains.length > 0)
                              ? idp.domains.map((d) => (
                                    <span key={d} className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-accent-muted text-accent max-w-full">
                                      <Globe size={9} className="mr-0.5 flex-shrink-0" /><span className="truncate">{d}</span>
                                  </span>
                                ))
                                : <span className="text-[11px] text-text-muted">-</span>}
                          </div>
                        </td>
                          <td className="px-4 py-3 align-top">
                            <div className="flex justify-end gap-1">
                            {!idp.is_default && idp.enabled !== false ? (
                              <button onClick={() => handleSetDefaultIdp(idp)}
                                className="p-1 text-text-secondary hover:bg-accent-muted hover:text-accent rounded transition-colors" title="Set as default">
                                <Star size={14} />
                              </button>
                            ) : null}
                            <button onClick={() => openIdpEdit(idp)}
                              className="p-1 text-text-secondary hover:bg-surface-hover rounded transition-colors" title="Edit">
                              <Edit size={14} />
                            </button>
                            <button onClick={() => handleIdpDelete(idp.id)}
                              className="p-1 text-danger hover:bg-danger-muted rounded transition-colors" title="Delete">
                              <Trash2 size={14} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                </div>
              )}
            </div>
          </div>

          {/* ─── IdP Create/Edit Modal (nested) ─── */}
          {idpModal ? (
            <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
              <div className="bg-surface-card rounded-md border border-border shadow-2xl w-[min(720px,calc(100vw-32px))] h-[min(700px,calc(100vh-48px))] overflow-hidden flex flex-col">
                <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-surface-card flex-shrink-0">
                  <h3 className="text-sm font-semibold text-text-primary">
                    {idpModal === 'create' ? 'Add OIDC Client Registration' : 'Edit OIDC Client Registration'}
                  </h3>
                  <button onClick={() => setIdpModal(null)} className="p-1 text-text-muted hover:text-text-primary rounded-md">
                    <X size={18} />
                  </button>
                </div>

                <div className="p-6 space-y-5 overflow-y-auto flex-1">
                  {idpError && (
                    <div className="bg-danger-muted border border-danger rounded-md p-3 text-xs text-danger">{idpError}</div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className={idpLabelClass}>Provider name *</label>
                      <input type="text" value={idpForm.name || ''} onChange={(e) => setIdpForm({ ...idpForm, name: e.target.value })}
                        className={idpInputClass}
                        placeholder="Keycloak Lab" />
                    </div>
                    <div>
                      <label className={idpLabelClass}>OIDC client ID *</label>
                      <input type="text" value={idpForm.client_id || ''} onChange={(e) => setIdpForm({ ...idpForm, client_id: e.target.value })}
                        className={idpMonoInputClass}
                        placeholder="ztna-pdp" />
                    </div>
                    <div className="md:col-span-2">
                      <label className={idpLabelClass}>Issuer URL *</label>
                      <input type="text" value={idpForm.issuer || ''} onChange={(e) => setIdpForm({ ...idpForm, issuer: e.target.value })}
                        className={idpMonoInputClass}
                        placeholder="http://keycloak.ztna.local:8080/realms/ztna-lab" />
                    </div>
                    <div>
                      <label className={idpLabelClass}>
                        OIDC client secret
                        {idpModal === 'edit' && idpForm.has_client_secret ? (
                          <span className="ml-2 px-1.5 py-0.5 rounded bg-success-muted text-success text-[9px] normal-case tracking-normal">saved</span>
                        ) : null}
                      </label>
                      <input type="password" value={idpForm.client_secret || ''} onChange={(e) => setIdpForm({ ...idpForm, client_secret: e.target.value })}
                        className={idpInputClass}
                        placeholder={idpModal === 'edit' ? 'Leave blank to keep saved secret' : 'Required for confidential clients'} />
                    </div>
                    <div>
                      <label className={idpLabelClass}>Scopes</label>
                      <input type="text" value={idpForm.scopes || ''} onChange={(e) => setIdpForm({ ...idpForm, scopes: e.target.value })}
                        className={idpMonoInputClass}
                        placeholder="openid profile email" />
                    </div>
                    <div>
                      <label className={idpLabelClass}>HRD domains</label>
                      <input type="text" value={idpForm.domains || ''} onChange={(e) => setIdpForm({ ...idpForm, domains: e.target.value })}
                        className={idpMonoInputClass}
                        placeholder="demo.ztna.test, partner.ztna.test" />
                    </div>
                    <div>
                      <label className={idpLabelClass}>Callback URL</label>
                      <input type="text" value={federatedCallbackURL} readOnly
                        className={`${idpMonoInputClass} text-text-muted bg-surface-secondary`} />
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border pt-4">
                    <label className="flex items-center gap-2 cursor-pointer text-[12px] text-text-secondary">
                      <input type="checkbox" checked={idpForm.enabled !== false}
                        onChange={(e) => setIdpForm({ ...idpForm, enabled: e.target.checked, is_default: e.target.checked ? idpForm.is_default : false })}
                        className="rounded border-border text-accent" /> Enabled
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer text-[12px] text-text-secondary">
                      <input type="checkbox" checked={idpForm.is_default === true}
                        onChange={(e) => setIdpForm({ ...idpForm, is_default: e.target.checked })}
                        disabled={idpForm.enabled === false || (idpModal === 'edit' && idpForm.is_default === true) || (idpModal === 'create' && idps.length === 0)}
                        className="rounded border-border text-accent disabled:opacity-50" /> Default for tenant
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer text-[12px] text-text-secondary">
                      <input type="checkbox" checked={idpForm.auto_discovery !== false}
                        onChange={(e) => setIdpForm({ ...idpForm, auto_discovery: e.target.checked })}
                        className="rounded border-border text-accent" /> Auto-discovery
                    </label>
                  </div>

                  <div className="border-t border-border pt-4">
                    <button type="button" onClick={() => setIdpAdvancedOpen((open) => !open)}
                      className="w-full flex items-center justify-between text-left">
                      <span className="inline-flex items-center gap-2 text-xs font-semibold text-text-primary">
                        <ChevronDown size={14} className={`text-text-muted transition-transform ${idpAdvancedOpen ? '' : '-rotate-90'}`} />
                        Advanced mapping
                      </span>
                      <span className="text-[11px] text-text-muted">
                        {(idpForm.group_role_mapping || []).length} role rule{(idpForm.group_role_mapping || []).length === 1 ? '' : 's'}
                      </span>
                    </button>

                    {idpAdvancedOpen ? (
                      <div className="mt-4 space-y-5">
                        <div>
                          <h4 className="text-xs font-semibold text-text-primary mb-3 flex items-center gap-1.5">
                            <Key size={14} className="text-accent" /> Claims
                          </h4>
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            <div>
                              <label className={idpLabelClass}>Username claim</label>
                              <input type="text" value={idpForm.claim_username || ''}
                                onChange={(e) => setIdpForm({ ...idpForm, claim_username: e.target.value })}
                                className={idpMonoInputClass} />
                            </div>
                            <div>
                              <label className={idpLabelClass}>Email claim</label>
                              <input type="text" value={idpForm.claim_email || ''}
                                onChange={(e) => setIdpForm({ ...idpForm, claim_email: e.target.value })}
                                className={idpMonoInputClass} />
                            </div>
                            <div>
                              <label className={idpLabelClass}>Groups claim</label>
                              <input type="text" value={idpForm.claim_groups || ''}
                                onChange={(e) => setIdpForm({ ...idpForm, claim_groups: e.target.value })}
                                className={idpMonoInputClass} />
                            </div>
                          </div>
                        </div>

                        <div>
                          <div className="flex items-center justify-between mb-3">
                            <h4 className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
                              <Users size={14} className="text-accent" /> Group roles
                            </h4>
                            <button onClick={addGroupRule}
                              className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-semibold border border-border rounded text-text-secondary hover:bg-surface-hover transition-colors">
                              <Plus size={10} /> Add
                            </button>
                          </div>

                          {(idpForm.group_role_mapping || []).length === 0 ? (
                            <div className="text-center py-3 text-[11px] text-text-muted border border-dashed border-border rounded-md">
                              Default role: user
                            </div>
                          ) : (
                            <div className="border border-border rounded-md overflow-hidden">
                              <table className="w-full table-fixed">
                                <thead className="bg-surface-secondary">
                                  <tr>
                                    <th className="w-[58%] text-left px-3 py-2 text-[10px] font-semibold text-text-muted uppercase tracking-[0.4px]">Group name</th>
                                    <th className="w-[32%] text-left px-3 py-2 text-[10px] font-semibold text-text-muted uppercase tracking-[0.4px]">Role</th>
                                    <th className="w-[10%]"></th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                  {(idpForm.group_role_mapping || []).map((rule, idx) => (
                                    <tr key={idx}>
                                      <td className="px-3 py-2">
                                        <input type="text" value={rule.group_name || ''}
                                          onChange={(e) => updateGroupRule(idx, 'group_name', e.target.value)}
                                          className={idpMonoInputClass}
                                          placeholder="ZTNA-Admins" />
                                      </td>
                                      <td className="px-3 py-2">
                                        <select value={rule.role || 'user'}
                                          onChange={(e) => updateGroupRule(idx, 'role', e.target.value)}
                                          className={idpInputClass}>
                                          <option value="admin">admin</option>
                                          <option value="operator">operator</option>
                                          <option value="auditor">auditor</option>
                                          <option value="user">user</option>
                                        </select>
                                      </td>
                                      <td className="px-2 py-2 text-right">
                                        <button onClick={() => removeGroupRule(idx)}
                                          className="p-1 text-danger hover:bg-danger-muted rounded transition-colors" title="Remove">
                                          <X size={13} />
                                        </button>
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      </div>
                    ) : null}
                  </div>
                </div>

                <div className="flex justify-between items-center gap-4 px-6 py-4 border-t border-border bg-surface-secondary flex-shrink-0">
                  <div className="min-w-0">
                    <button onClick={handleTestConnection} disabled={testing || !idpForm.issuer?.trim()}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-semibold border border-border rounded text-text-secondary hover:bg-surface-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                      {testing ? <Loader2 size={12} className="animate-spin" /> : <CheckCircle2 size={12} />}
                      {testing ? 'Testing...' : 'Test Discovery'}
                    </button>
                    {testResult && (
                      <div className={`mt-1.5 max-w-[380px] p-1.5 rounded border text-[10px] ${
                        testResult.ok ? 'border-success bg-success-muted' : 'border-danger bg-danger-muted'
                      }`}>
                        {testResult.ok ? (
                          <span className="flex items-center gap-1 text-success font-semibold min-w-0">
                            <CheckCircle2 size={10} className="flex-shrink-0" /> <span className="truncate">OK - {testResult.authorization_endpoint}</span>
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-danger"><AlertCircle size={10} /> {testResult.error}</span>
                        )}
                      </div>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => setIdpModal(null)}
                      className="px-3 py-1.5 text-[11px] font-semibold text-text-secondary hover:text-text-primary">Cancel</button>
                    <button onClick={handleIdpSave}
                      disabled={idpSaving || !idpForm.name || !idpForm.issuer || !idpForm.client_id}
                      className="px-4 py-1.5 text-[11px] font-semibold bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                      {idpSaving ? 'Saving...' : 'Save'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
