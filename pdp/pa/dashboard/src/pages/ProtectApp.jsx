import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getResource, createResource, updateResource, getRules, createRule, updateRule, deleteRule } from '../api';
import { Globe, Terminal, Monitor, Router, ArrowLeft, Copy, Eye, EyeOff, Plus, Trash2, ChevronDown, ChevronRight, Save } from 'lucide-react';
import PageHeader from '../components/ui/PageHeader';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import { FormInput } from '../components/ui/FormField';

const appTypes = [
  { type: 'web', title: 'Web Application', icon: Globe, color: '#3b82f6', defaultPort: 443 },
  { type: 'ssh', title: 'SSH Server', icon: Terminal, color: '#22c55e', defaultPort: 22 },
  { type: 'rdp', title: 'RDP Server', icon: Monitor, color: '#a855f7', defaultPort: 3389 },
  { type: 'gateway', title: 'Gateway', icon: Router, color: '#f59e0b', defaultPort: 9443 },
];

function copyText(text) {
  navigator.clipboard.writeText(text).catch(() => {});
}

// Collapsible section component
function Section({ title, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-surface-card border border-border rounded-md shadow-[0_1px_3px_rgba(0,0,0,0.06)] mb-5">
      <div
        className="px-6 py-4 flex items-center gap-2 cursor-pointer select-none"
        onClick={() => setOpen(!open)}
      >
        {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        <h3 className="text-[15px] font-bold text-text-primary">{title}</h3>
      </div>
      {open && <div className="px-6 pb-5 border-t border-border">{children}</div>}
    </div>
  );
}

// Credential row component
function CredRow({ label, value, secret, showSecret, onToggleSecret }) {
  return (
    <div className={`flex ${secret ? 'items-start' : 'items-center'} py-3.5 border-b border-border gap-4`}>
      <label className={`w-[130px] flex-shrink-0 text-[13px] font-semibold text-text-secondary ${secret ? 'pt-2' : ''}`}>{label}</label>
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <input
            readOnly
            value={secret && !showSecret ? 'Click to view' : value}
            onClick={(e) => { if (secret && !showSecret) onToggleSecret(); else e.target.select(); }}
            className={`flex-1 px-3 py-2 bg-surface border border-border rounded-md text-[13px]
              ${(!secret || showSecret) ? 'text-mono text-text-primary' : 'text-text-muted cursor-pointer'}
              focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition`}
          />
          <Button variant="secondary" className="text-xs px-2 py-1" onClick={() => { if (secret && !showSecret) onToggleSecret(); copyText(value); }} title="Copy & select">select</Button>
        </div>
        {secret && <p className="text-[11px] text-text-muted mt-1">Don't share your client secret with anyone.</p>}
      </div>
    </div>
  );
}

export default function ProtectApp() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [step, setStep] = useState('choose');
  const [selectedType, setSelectedType] = useState(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // App data
  const [appId, setAppId] = useState(null);
  const [resourceData, setResourceData] = useState(null);
  const [creds, setCreds] = useState(null);
  const [showSecret, setShowSecret] = useState(false);
  const [appName, setAppName] = useState('');

  // Policies
  const [appPolicies, setAppPolicies] = useState([]);
  const [groupPolicies, setGroupPolicies] = useState([]);
  const [globalPolicies, setGlobalPolicies] = useState([]);

  // Auto-select type from URL param and create, or load existing resource by id
  useEffect(() => {
    const idParam = searchParams.get('id');
    const typeParam = searchParams.get('type');
    if (idParam) {
      handleLoadExisting(idParam);
    } else if (typeParam && step === 'choose') {
      const found = appTypes.find(a => a.type === typeParam);
      if (found) {
        setSelectedType(found);
        handleCreateForType(found);
      }
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Load and categorize policies when app is created
  useEffect(() => {
    if (appId) loadPolicies();
  }, [appId]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadPolicies = async () => {
    try {
      const rules = await getRules();
      const list = Array.isArray(rules) ? rules : [];
      setAppPolicies(list.filter(r => r.conditions?.target_resources?.includes(appId)));
      setGroupPolicies(list.filter(r =>
        (!r.conditions?.target_resources || r.conditions.target_resources.length === 0) &&
        r.conditions?.allowed_roles?.length > 0
      ));
      setGlobalPolicies(list.filter(r =>
        (!r.conditions?.target_resources || r.conditions.target_resources.length === 0) &&
        (!r.conditions?.allowed_roles || r.conditions.allowed_roles.length === 0)
      ));
    } catch (e) {
      console.error('Failed to load policies', e);
    }
  };

  const handleLoadExisting = async (id) => {
    setSaving(true);
    setError('');
    try {
      const res = await getResource(id);
      if (res && res.id) {
        setAppId(res.id);
        setResourceData(res);
        setCreds({ client_id: res.client_id, client_secret: res.client_secret });
        setAppName(res.name || '');
        const found = appTypes.find(a => a.type === res.type);
        if (found) setSelectedType(found);
        setStep('app');
      } else {
        setError('Resource not found');
      }
    } catch (e) {
      setError(e?.message || 'Failed to load resource');
    } finally {
      setSaving(false);
    }
  };

  const handleCreateForType = async (appType) => {
    setSaving(true);
    setError('');
    try {
      const data = { name: appType.title, type: appType.type, enabled: true };
      const created = await createResource(data);
      if (created && created.client_id) {
        setAppId(created.id);
        setResourceData(created);
        setCreds({ client_id: created.client_id, client_secret: created.client_secret });
        setAppName(created.name);
        setStep('app');
      } else {
        navigate('/dashboard/resources');
      }
    } catch (e) {
      setError(e?.message || 'Failed to create application');
      setStep('choose');
    } finally {
      setSaving(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setSuccessMsg('');
    try {
      await updateResource(appId, { name: appName });
      setResourceData(prev => prev ? { ...prev, name: appName } : prev);
      setSuccessMsg('Application saved successfully');
      setTimeout(() => setSuccessMsg(''), 3000);
    } catch (e) {
      setError(e?.message || 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  const handleAddAppPolicy = async () => {
    try {
      await createRule({
        name: `${appName} - New Policy`,
        priority: 100,
        action: 'allow',
        enabled: true,
        conditions: { target_resources: [appId] },
      });
      loadPolicies();
    } catch (e) { console.error(e); }
  };

  const handleTogglePolicy = async (rule) => {
    try {
      await updateRule(rule.id, { ...rule, enabled: !rule.enabled });
      loadPolicies();
    } catch (e) { console.error(e); }
  };

  const handleDeletePolicy = async (id) => {
    if (!confirm('Delete this policy rule?')) return;
    try {
      await deleteRule(id);
      loadPolicies();
    } catch (e) { console.error(e); }
  };

  // Loading state
  if (saving && step === 'choose') {
    return (
      <div className="flex items-center justify-center py-12 text-text-muted">
        <span className="spinner" /> {searchParams.get('id') ? 'Loading application...' : 'Creating application...'}
      </div>
    );
  }

  // --- Step 1: Choose type ---
  if (step === 'choose') {
    return (
      <>
        <PageHeader title="Protect an Application" subtitle="Choose the type of application you want to protect with ZTNA" />
        {error && (
          <div className="text-sm text-danger mb-4 px-3 py-2 bg-danger-muted/50 rounded-md">{error}</div>
        )}
        <div className="grid grid-cols-[repeat(auto-fill,minmax(240px,1fr))] gap-5">
          {appTypes.map((app) => {
            const Icon = app.icon;
            return (
              <div
                key={app.type}
                className="bg-surface-card border border-border rounded-md cursor-pointer transition duration-150 hover:-translate-y-0.5 hover:shadow-lg p-0 overflow-hidden"
                onClick={() => { setSelectedType(app); handleCreateForType(app); }}
              >
                <div className="p-7 text-center">
                  <div
                    className="w-14 h-14 rounded-[14px] flex items-center justify-center mx-auto mb-3"
                    style={{ background: `${app.color}15`, border: `2px solid ${app.color}30` }}
                  >
                    <Icon size={24} color={app.color} />
                  </div>
                  <h3 className="text-[15px] font-semibold text-text-primary mb-1">{app.title}</h3>
                  <Badge variant={app.type === 'web' ? 'info' : app.type === 'ssh' ? 'success' : app.type === 'rdp' ? 'accent' : 'warning'}>
                    {app.type.toUpperCase()}
                  </Badge>
                </div>
              </div>
            );
          })}
        </div>
        <div className="mt-5">
          <Button variant="secondary" onClick={() => navigate('/dashboard/resources')}>
            <ArrowLeft size={14} /> Back to Resources
          </Button>
        </div>
      </>
    );
  }

  // --- Step 2: Full Application Page ---
  if (step === 'app' && creds) {
    const typeInfo = selectedType || appTypes[0];
    const Icon = typeInfo.icon;

    const policyActionVariant = (action) => {
      if (action === 'allow') return 'success';
      if (action === 'deny') return 'danger';
      return 'info';
    };

    const PolicyTable = ({ policies, showAdd, onAdd }) => (
      <div className="mt-3">
        {policies.length === 0 ? (
          <p className="text-xs text-text-muted py-2">No policies configured.</p>
        ) : (
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-2 py-1.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.5px]">Name</th>
                <th className="text-left px-2 py-1.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.5px]">Action</th>
                <th className="text-left px-2 py-1.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.5px]">Priority</th>
                <th className="text-center px-2 py-1.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.5px]">Enabled</th>
                <th className="text-right px-2 py-1.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.5px]">Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.map(r => (
                <tr key={r.id} className="border-b border-border">
                  <td className="px-2 py-1.5 text-text-primary">{r.name}</td>
                  <td className="px-2 py-1.5">
                    <Badge variant={policyActionVariant(r.action)}>{r.action}</Badge>
                  </td>
                  <td className="px-2 py-1.5">{r.priority}</td>
                  <td className="px-2 py-1.5 text-center">
                    <input type="checkbox" checked={r.enabled} onChange={() => handleTogglePolicy(r)} className="accent-accent rounded" />
                  </td>
                  <td className="px-2 py-1.5 text-right">
                    <button className="inline-flex items-center gap-1 px-2 py-1.5 border border-border rounded text-xs text-danger hover:bg-danger-muted transition-colors" onClick={() => handleDeletePolicy(r.id)} title="Delete">
                      <Trash2 size={12} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {showAdd && (
          <Button variant="secondary" className="text-xs mt-2" onClick={onAdd}>
            <Plus size={12} /> Add Policy
          </Button>
        )}
      </div>
    );

    return (
      <>
        <div className="flex items-center justify-between mb-7">
          <div className="flex items-center gap-3">
            <div
              className="w-10 h-10 rounded-[10px] flex items-center justify-center"
              style={{ background: `${typeInfo.color}15`, border: `2px solid ${typeInfo.color}30` }}
            >
              <Icon size={20} color={typeInfo.color} />
            </div>
            <div>
              <h2 className="text-[18px] font-bold tracking-[-0.3px] text-text-primary">ZTNA Gateway - {typeInfo.title}</h2>
              <p className="text-xs text-text-secondary mt-0.5 font-medium">Application credentials and configuration</p>
            </div>
          </div>
        </div>

        {error && (
          <div className="text-sm text-danger mb-4 px-3 py-2 bg-danger-muted/50 rounded-md">{error}</div>
        )}
        {successMsg && (
          <div className="text-sm text-success mb-4 px-3 py-2 bg-success-muted/50 rounded-md">{successMsg}</div>
        )}

        {/* Details Section */}
        <Section title="Details">
          <CredRow label="Client ID" value={creds.client_id} />
          <CredRow label="Client secret" value={creds.client_secret} secret showSecret={showSecret} onToggleSecret={() => setShowSecret(!showSecret)} />
          <CredRow label="API hostname" value={window.location.host} />
        </Section>

        {/* Policy Section */}
        <Section title="Policy">
          <div className="mt-3">
            <h4 className="text-[13px] font-bold text-text-secondary uppercase tracking-[0.5px] mb-2">App Policy</h4>
            <p className="text-xs text-text-muted mb-1">Rules that apply specifically to this application.</p>
            <PolicyTable policies={appPolicies} showAdd onAdd={handleAddAppPolicy} />
          </div>

          <div className="mt-6 pt-4 border-t border-border">
            <h4 className="text-[13px] font-bold text-text-secondary uppercase tracking-[0.5px] mb-2">Group Policy</h4>
            <p className="text-xs text-text-muted mb-1">Rules that apply based on user roles/groups.</p>
            <PolicyTable policies={groupPolicies} />
          </div>

          <div className="mt-6 pt-4 border-t border-border">
            <h4 className="text-[13px] font-bold text-text-secondary uppercase tracking-[0.5px] mb-2">Global Policy</h4>
            <p className="text-xs text-text-muted mb-1">Rules that apply to all applications system-wide.</p>
            <PolicyTable policies={globalPolicies} />
          </div>
        </Section>

        {/* Settings Section */}
        <Section title="Settings">
          <div className="mt-3 space-y-4">
            <div>
              <label className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Application Type</label>
              <div className="flex items-center gap-2 px-3 py-2 bg-surface border border-border rounded-md">
                <Icon size={16} color={typeInfo.color} />
                <span className="text-[13px] text-text-primary">{typeInfo.title}</span>
                <Badge className="ml-auto" variant={typeInfo.type === 'web' ? 'info' : typeInfo.type === 'ssh' ? 'success' : typeInfo.type === 'rdp' ? 'accent' : 'warning'}>
                  {typeInfo.type.toUpperCase()}
                </Badge>
              </div>
            </div>
            <div>
              <label htmlFor="protect-app-name" className="block text-[11px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5">Application Name</label>
              <FormInput
                id="protect-app-name"
                value={appName}
                onChange={(e) => setAppName(e.target.value)}
                placeholder="Application name"
              />
            </div>
          </div>
        </Section>

        {/* Bottom Actions */}
        <div className="flex justify-between mt-2 mb-10">
          <Button variant="secondary" onClick={() => navigate('/dashboard/resources')}>
            <ArrowLeft size={14} /> Back to Resources
          </Button>
          <Button variant="primary" onClick={handleSave} disabled={saving}>
            <Save size={14} /> {saving ? 'Saving...' : 'Save'}
          </Button>
        </div>
      </>
    );
  }

  return null;
}
