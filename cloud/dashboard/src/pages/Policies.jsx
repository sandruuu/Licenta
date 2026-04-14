import { useState, useEffect } from 'react';
import { getRules, createRule, updateRule, deleteRule } from '../api';
import { Plus, Trash2, Edit, X, Shield } from 'lucide-react';

export default function Policies() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const load = () => {
    setLoading(true);
    getRules()
      .then((data) => setRules(Array.isArray(data) ? data : []))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const openCreate = () => {
    setForm({
      name: '', description: '', action: 'allow', priority: 100, enabled: true,
      conditions: {
        min_health_score: 0,
        required_checks: '',
        allowed_roles: '',
        allowed_ips: '',
        allowed_time_start: '',
        allowed_time_end: '',
        allowed_days: '',
        target_resources: '',
        target_ports: '',
        max_risk_score: 100,
      },
    });
    setModal('create');
  };

  const openEdit = (rule) => {
    setForm({
      ...rule,
      conditions: {
        min_health_score: rule.conditions?.min_health_score || 0,
        required_checks: (rule.conditions?.required_checks || []).join(', '),
        allowed_roles: (rule.conditions?.allowed_roles || []).join(', '),
        allowed_ips: (rule.conditions?.allowed_ips || []).join(', '),
        allowed_time_start: rule.conditions?.allowed_time_start || '',
        allowed_time_end: rule.conditions?.allowed_time_end || '',
        allowed_days: (rule.conditions?.allowed_days || []).join(', '),
        target_resources: (rule.conditions?.target_resources || []).join(', '),
        target_ports: (rule.conditions?.target_ports || []).join(', '),
        max_risk_score: rule.conditions?.max_risk_score || 100,
      },
    });
    setModal('edit');
  };

  const handleSave = async () => {
    setSaving(true);
    const toArr = (s) => s ? s.split(',').map(v => v.trim()).filter(Boolean) : [];
    const toIntArr = (s) => s ? s.split(',').map(v => parseInt(v.trim())).filter(v => !isNaN(v)) : [];

    const data = {
      ...form,
      priority: parseInt(form.priority) || 100,
      conditions: {
        min_health_score: parseInt(form.conditions?.min_health_score) || 0,
        required_checks: toArr(form.conditions?.required_checks),
        allowed_roles: toArr(form.conditions?.allowed_roles),
        allowed_ips: toArr(form.conditions?.allowed_ips),
        allowed_time_start: form.conditions?.allowed_time_start || '',
        allowed_time_end: form.conditions?.allowed_time_end || '',
        allowed_days: toArr(form.conditions?.allowed_days),
        target_resources: toArr(form.conditions?.target_resources),
        target_ports: toIntArr(form.conditions?.target_ports),
        max_risk_score: parseInt(form.conditions?.max_risk_score) || 100,
      },
    };

    try {
      if (modal === 'create') {
        await createRule(data);
      } else {
        await updateRule(form.id, data);
      }
      setError(null);
      setModal(null);
      load();
    } catch (e) {
      setError(e.message || 'Failed to save rule');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this policy rule?')) return;
    try {
      await deleteRule(id);
      setError(null);
      load();
    } catch (e) {
      setError(e.message || 'Failed to delete rule');
    }
  };

  const updateCondition = (key, value) => {
    setForm({ ...form, conditions: { ...form.conditions, [key]: value } });
  };

  if (loading) return <div className="loading"><div className="spinner" /> Loading policies...</div>;

  return (
    <>
      <div className="page-header">
        <h2>Policies</h2>
        <p>Define access control rules and conditions</p>
      </div>

      {error && (
        <div className="card" style={{ background: 'var(--danger-bg, #2d1b1b)', border: '1px solid var(--danger, #e74c3c)', marginBottom: 16, padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ color: 'var(--danger, #e74c3c)' }}>{error}</span>
          <button className="btn btn-secondary btn-sm" onClick={() => setError(null)}><X size={14} /></button>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>{rules.length} Policy Rule{rules.length !== 1 ? 's' : ''}</h3>
          <button className="btn btn-primary" onClick={openCreate}><Plus size={14} /> Add Rule</button>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Priority</th>
                <th>Name</th>
                <th>Action</th>
                <th>Min Health</th>
                <th>Max Risk</th>
                <th>Roles</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.length === 0 ? (
                <tr>
                  <td colSpan={8}>
                    <div className="empty-state">
                      <Shield size={40} />
                      <p>No policy rules defined. Add a rule to control access.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                rules.map((rule) => (
                  <tr key={rule.id}>
                    <td className="text-mono">{rule.priority}</td>
                    <td>
                      <strong style={{ color: 'var(--text-primary)' }}>{rule.name}</strong>
                      {rule.description && <div className="text-sm text-muted">{rule.description}</div>}
                    </td>
                    <td>
                      <span className={`badge badge-${rule.action === 'allow' ? 'allow' : rule.action === 'deny' ? 'deny' : 'mfa'}`}>
                        {rule.action}
                      </span>
                    </td>
                    <td className="text-mono">{rule.conditions?.min_health_score || 0}</td>
                    <td className="text-mono">{rule.conditions?.max_risk_score || '—'}</td>
                    <td className="text-sm">{(rule.conditions?.allowed_roles || []).join(', ') || 'Any'}</td>
                    <td>
                      <span className={`badge badge-${rule.enabled ? 'enabled' : 'disabled'}`}>
                        {rule.enabled ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td>
                      <div className="flex gap-2">
                        <button className="btn btn-secondary btn-sm" onClick={() => openEdit(rule)}><Edit size={12} /></button>
                        <button className="btn btn-danger btn-sm" onClick={() => handleDelete(rule.id)}><Trash2 size={12} /></button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create/Edit Modal */}
      {modal && (
        <div className="modal-overlay" onClick={() => setModal(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 640 }}>
            <div className="modal-header">
              <h3>{modal === 'create' ? 'Add Policy Rule' : 'Edit Policy Rule'}</h3>
              <button className="modal-close" onClick={() => setModal(null)}><X size={18} /></button>
            </div>
            <div className="modal-body">
              <div className="form-row">
                <div className="form-group">
                  <label>Name</label>
                  <input className="form-input" value={form.name || ''} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Block High Risk" />
                </div>
                <div className="form-group">
                  <label>Priority</label>
                  <input className="form-input" type="number" value={form.priority ?? 100} onChange={(e) => setForm({ ...form, priority: e.target.value })} />
                </div>
              </div>
              <div className="form-group">
                <label>Description</label>
                <input className="form-input" value={form.description || ''} onChange={(e) => setForm({ ...form, description: e.target.value })} />
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Action</label>
                  <select className="form-select" value={form.action || 'allow'} onChange={(e) => setForm({ ...form, action: e.target.value })}>
                    <option value="allow">Allow</option>
                    <option value="deny">Deny</option>
                    <option value="mfa_required">Require MFA</option>
                    <option value="restrict">Restrict</option>
                  </select>
                </div>
                <div className="form-checkbox" style={{ paddingTop: 24 }}>
                  <input type="checkbox" checked={form.enabled ?? true} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                  <label>Enabled</label>
                </div>
              </div>

              <h4 style={{ margin: '20px 0 12px', fontSize: 13, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Conditions</h4>

              <div className="form-row">
                <div className="form-group">
                  <label>Min Health Score</label>
                  <input className="form-input" type="number" min="0" max="100" value={form.conditions?.min_health_score ?? 0}
                    onChange={(e) => updateCondition('min_health_score', e.target.value)} />
                </div>
                <div className="form-group">
                  <label>Max Risk Score</label>
                  <input className="form-input" type="number" min="0" max="100" value={form.conditions?.max_risk_score ?? 100}
                    onChange={(e) => updateCondition('max_risk_score', e.target.value)} />
                </div>
              </div>
              <div className="form-group">
                <label>Allowed Roles (comma-separated)</label>
                <input className="form-input" value={form.conditions?.allowed_roles || ''}
                  onChange={(e) => updateCondition('allowed_roles', e.target.value)} placeholder="admin, user" />
              </div>
              <div className="form-group">
                <label>Allowed IPs (comma-separated CIDR)</label>
                <input className="form-input" value={form.conditions?.allowed_ips || ''}
                  onChange={(e) => updateCondition('allowed_ips', e.target.value)} placeholder="10.0.0.0/8, 192.168.1.0/24" />
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Allowed Time Start</label>
                  <input className="form-input" value={form.conditions?.allowed_time_start || ''}
                    onChange={(e) => updateCondition('allowed_time_start', e.target.value)} placeholder="08:00" />
                </div>
                <div className="form-group">
                  <label>Allowed Time End</label>
                  <input className="form-input" value={form.conditions?.allowed_time_end || ''}
                    onChange={(e) => updateCondition('allowed_time_end', e.target.value)} placeholder="18:00" />
                </div>
              </div>
              <div className="form-group">
                <label>Allowed Days (comma-separated)</label>
                <input className="form-input" value={form.conditions?.allowed_days || ''}
                  onChange={(e) => updateCondition('allowed_days', e.target.value)} placeholder="Monday, Tuesday, Wednesday" />
              </div>
              <div className="form-group">
                <label>Required Health Checks (comma-separated)</label>
                <input className="form-input" value={form.conditions?.required_checks || ''}
                  onChange={(e) => updateCondition('required_checks', e.target.value)} placeholder="firewall, antivirus, disk_encryption" />
              </div>
              <div className="form-group">
                <label>Target Resources (comma-separated IDs)</label>
                <input className="form-input" value={form.conditions?.target_resources || ''}
                  onChange={(e) => updateCondition('target_resources', e.target.value)} placeholder="Leave empty for all" />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setModal(null)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                {saving ? 'Saving...' : modal === 'create' ? 'Create Rule' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
