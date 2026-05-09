import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getTenants, createTenant, updateTenant, deleteTenant } from '../api';
import { Plus, Trash2, Edit, X, Building2, Globe, Router, ChevronDown } from 'lucide-react';

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('ro-RO');
}

export default function Tenants() {
  const [tenants, setTenants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null); // null | 'create' | 'edit'
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const navigate = useNavigate();

  const load = () => {
    setLoading(true);
    getTenants()
      .then((data) => setTenants(Array.isArray(data) ? data : []))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const openCreate = () => {
    setForm({ name: '', domain: '', description: '', enabled: true });
    setModal('create');
    setAddMenuOpen(false);
  };

  const openEdit = (t) => {
    setForm({ ...t });
    setModal('edit');
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      if (modal === 'create') {
        await createTenant(form);
      } else {
        await updateTenant(form.id, form);
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

  const statusBadge = (enabled) => (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide ${
      enabled ? 'bg-success-muted text-success' : 'bg-surface-secondary text-text-muted'
    }`}>
      {enabled ? 'Active' : 'Inactive'}
    </span>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-bold tracking-[-0.3px] text-text-primary">Tenants</h1>
          <p className="text-xs text-text-secondary mt-0.5 font-medium">Manage organizations and their isolated environments</p>
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
                <th className="text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">Status</th>
                <th className="text-left px-6 py-3 text-[10px] font-semibold text-text-muted uppercase tracking-[0.8px]">Created</th>
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
                  <td className="px-6 py-4">{statusBadge(t.enabled)}</td>
                  <td className="px-6 py-4 text-xs text-text-secondary">{formatDate(t.created_at)}</td>
                  <td className="px-6 py-4">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => createGateway(t)}
                        className="p-1.5 text-accent hover:bg-accent-muted rounded-md transition-colors"
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

      {/* Modal */}
      {modal && (
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
                <input
                  type="text"
                  value={form.name || ''}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition font-sans"
                  placeholder="e.g. Company HQ"
                />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Domain</label>
                <input
                  type="text"
                  value={form.domain || ''}
                  onChange={(e) => setForm({ ...form, domain: e.target.value })}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition font-mono"
                  placeholder="e.g. company.com"
                />
                <p className="text-[11px] text-text-muted mt-1">Used for Home Realm Discovery (HRD) in a future phase.</p>
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Description</label>
                <textarea
                  value={form.description || ''}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  rows={2}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition resize-none font-sans"
                  placeholder="Optional description..."
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="tenant-enabled"
                  checked={form.enabled !== false}
                  onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                  className="rounded border-border text-accent focus:ring-accent"
                />
                <label htmlFor="tenant-enabled" className="text-[13px] text-text-secondary">Enabled</label>
              </div>
            </div>
            <div className="flex justify-end gap-2 px-6 py-4 border-t border-border bg-surface-secondary">
              <button
                onClick={() => setModal(null)}
                className="px-4 py-2 text-xs font-semibold text-text-secondary hover:text-text-primary"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !form.name}
                className="px-4 py-2 text-xs font-semibold bg-accent text-white rounded-md hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {saving ? 'Saving...' : modal === 'create' ? 'Create' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
