import { useState, useEffect } from 'react';
import { getRules, createRule, updateRule, deleteRule } from '../api';
import PageHeader from '../components/ui/PageHeader';
import Modal from '../components/ui/Modal';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import FormField, { FormInput, FormSelect, FormRow, FormCheckbox } from '../components/ui/FormField';
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
        min_health_score: 0, required_checks: '', allowed_roles: '', allowed_ips: '',
        allowed_time_start: '', allowed_time_end: '', allowed_days: '',
        target_resources: '', target_ports: '', max_risk_score: 100,
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

  const columns = [
    { key: 'priority', label: 'Priority', render: (v) => <span className="text-mono text-xs">{v}</span> },
    { key: 'name', label: 'Name', render: (v, row) => (
      <div>
        <span className="font-semibold text-text-primary text-xs">{v}</span>
        {row.description && <div className="text-xs text-text-muted">{row.description}</div>}
      </div>
    )},
    { key: 'action', label: 'Action', render: (v) => <Badge variant={v === 'allow' ? 'success' : v === 'deny' ? 'danger' : 'warning'}>{v}</Badge> },
    { key: 'conditions', label: 'Min Health', render: (v) => <span className="text-mono text-xs">{v?.min_health_score || 0}</span> },
    { key: 'conditions', label: 'Max Risk', render: (v) => <span className="text-mono text-xs">{v?.max_risk_score || '—'}</span> },
    { key: 'conditions', label: 'Roles', render: (v) => <span className="text-xs">{(v?.allowed_roles || []).join(', ') || 'Any'}</span> },
    { key: 'enabled', label: 'Status', render: (v) => <Badge variant={v ? 'success' : 'danger'}>{v ? 'Active' : 'Disabled'}</Badge> },
    { key: 'actions', label: 'Actions', align: 'right', render: (_, row) => (
      <div className="flex items-center justify-end gap-1">
        <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => openEdit(row)}><Edit size={12} /></Button>
        <Button variant="ghost" className="!p-1.5 !shadow-none !text-danger hover:!bg-danger-muted" onClick={() => handleDelete(row.id)}><Trash2 size={12} /></Button>
      </div>
    )},
  ];

  return (
    <>
      <PageHeader title="Policies" subtitle="Define access control rules and conditions" createLabel="Add Rule" onCreate={openCreate} />

      {error && (
        <div className="flex items-center justify-between px-4 py-3 mb-4 bg-danger-muted border border-danger rounded-md text-danger text-sm">
          <span>{error}</span>
          <Button variant="ghost" className="!p-1 !shadow-none" onClick={() => setError(null)}><X size={14} /></Button>
        </div>
      )}

      <DataTable columns={columns} data={rules} loading={loading} emptyIcon={Shield} emptyTitle="No policy rules defined" emptyMessage="Add a rule to control access." />

      {/* Create/Edit Modal */}
      <Modal open={!!modal} onClose={() => setModal(null)} title={modal === 'create' ? 'Add Policy Rule' : 'Edit Policy Rule'} size="lg"
        footer={
          <>
            <Button variant="secondary" onClick={() => setModal(null)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? 'Saving...' : modal === 'create' ? 'Create Rule' : 'Save Changes'}
            </Button>
          </>
        }>
        <FormRow>
          <FormField label="Name">
            <FormInput value={form.name || ''} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Block High Risk" />
          </FormField>
          <FormField label="Priority">
            <FormInput type="number" value={form.priority ?? 100} onChange={(e) => setForm({ ...form, priority: e.target.value })} />
          </FormField>
        </FormRow>
        <FormField label="Description">
          <FormInput value={form.description || ''} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </FormField>
        <FormRow>
          <FormField label="Action">
            <FormSelect value={form.action || 'allow'} onChange={(e) => setForm({ ...form, action: e.target.value })}>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
              <option value="mfa_required">Require MFA</option>
              <option value="restrict">Restrict</option>
            </FormSelect>
          </FormField>
          <div className="flex items-end pb-4">
            <FormCheckbox id="policy-enabled" checked={form.enabled ?? true} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} label="Enabled" />
          </div>
        </FormRow>

        <h4 className="mt-5 mb-3 text-[13px] text-text-muted uppercase tracking-[0.05em] font-semibold">Conditions</h4>

        <FormRow>
          <FormField label="Min Health Score">
            <FormInput type="number" min="0" max="100" value={form.conditions?.min_health_score ?? 0}
              onChange={(e) => updateCondition('min_health_score', e.target.value)} />
          </FormField>
          <FormField label="Max Risk Score">
            <FormInput type="number" min="0" max="100" value={form.conditions?.max_risk_score ?? 100}
              onChange={(e) => updateCondition('max_risk_score', e.target.value)} />
          </FormField>
        </FormRow>
        <FormField label="Allowed Roles (comma-separated)">
          <FormInput value={form.conditions?.allowed_roles || ''}
            onChange={(e) => updateCondition('allowed_roles', e.target.value)} placeholder="admin, user" />
        </FormField>
        <FormField label="Allowed IPs (comma-separated CIDR)">
          <FormInput value={form.conditions?.allowed_ips || ''}
            onChange={(e) => updateCondition('allowed_ips', e.target.value)} placeholder="10.0.0.0/8, 192.168.1.0/24" />
        </FormField>
        <FormRow>
          <FormField label="Allowed Time Start">
            <FormInput value={form.conditions?.allowed_time_start || ''}
              onChange={(e) => updateCondition('allowed_time_start', e.target.value)} placeholder="08:00" />
          </FormField>
          <FormField label="Allowed Time End">
            <FormInput value={form.conditions?.allowed_time_end || ''}
              onChange={(e) => updateCondition('allowed_time_end', e.target.value)} placeholder="18:00" />
          </FormField>
        </FormRow>
        <FormField label="Allowed Days (comma-separated)">
          <FormInput value={form.conditions?.allowed_days || ''}
            onChange={(e) => updateCondition('allowed_days', e.target.value)} placeholder="Monday, Tuesday, Wednesday" />
        </FormField>
        <FormField label="Required Health Checks (comma-separated)">
          <FormInput value={form.conditions?.required_checks || ''}
            onChange={(e) => updateCondition('required_checks', e.target.value)} placeholder="firewall, antivirus, disk_encryption" />
        </FormField>
        <FormField label="Target Resources (comma-separated IDs)">
          <FormInput value={form.conditions?.target_resources || ''}
            onChange={(e) => updateCondition('target_resources', e.target.value)} placeholder="Leave empty for all" />
        </FormField>
      </Modal>
    </>
  );
}
