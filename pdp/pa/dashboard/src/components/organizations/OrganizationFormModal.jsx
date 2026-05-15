import { X } from 'lucide-react';
import { FormCheckbox } from '../ui/FormField';

export default function OrganizationFormModal({ mode, form, setForm, saving, onClose, onSave }) {
  if (mode !== 'create' && mode !== 'edit') return null;

  return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-graphite/45 backdrop-blur-sm">
          <div className="bg-surface-card rounded-md border border-border shadow-2xl w-full max-w-md mx-4 overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border">
              <h2 className="text-base font-semibold text-text-primary">
                {mode === 'create' ? 'Create Organization' : 'Edit Organization'}
              </h2>
              <button onClick={onClose} className="p-1 text-text-muted hover:text-text-primary rounded-md">
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
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Primary domain</label>
                <input type="text" value={form.domain || ''} onChange={(e) => setForm({ ...form, domain: e.target.value })}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition font-mono"
                  placeholder="e.g. company.com" />
                <p className="text-[11px] text-text-muted mt-1">Primary email domain used for Home Realm Discovery.</p>
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Description</label>
                <textarea value={form.description || ''} onChange={(e) => setForm({ ...form, description: e.target.value })}
                  rows={2}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-[13px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition resize-none font-sans"
                  placeholder="Optional description..." />
              </div>
              <FormCheckbox
                id="organization-enabled"
                checked={form.enabled !== false}
                onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                label="Enabled"
              />
            </div>
            <div className="flex justify-end gap-2 px-6 py-4 border-t border-border bg-surface-secondary">
              <button onClick={onClose}
                className="px-4 py-2 text-xs font-semibold text-text-secondary hover:text-text-primary">Cancel</button>
              <button onClick={onSave} disabled={saving || !form.name}
                className="px-4 py-2 text-xs font-semibold bg-accent text-white-smoke rounded-md hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                {saving ? 'Saving...' : mode === 'create' ? 'Create' : 'Save'}
              </button>
            </div>
          </div>
        </div>
  );
}
