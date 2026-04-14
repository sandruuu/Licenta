import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getResource, createResource, updateResource, getRules, createRule, updateRule, deleteRule } from '../api';
import { Globe, Terminal, Monitor, Router, ArrowLeft, Copy, Eye, EyeOff, Plus, Trash2, ChevronDown, ChevronRight, Save } from 'lucide-react';

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
    <div className="card" style={{ marginBottom: 20 }}>
      <div
        style={{ padding: '16px 24px', display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none' }}
        onClick={() => setOpen(!open)}
      >
        {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        <h3 style={{ fontSize: 15, fontWeight: 700 }}>{title}</h3>
      </div>
      {open && <div style={{ padding: '0 24px 20px', borderTop: '1px solid var(--border)' }}>{children}</div>}
    </div>
  );
}

// Credential row component
function CredRow({ label, value, secret, showSecret, onToggleSecret }) {
  return (
    <div style={{ display: 'flex', alignItems: secret ? 'flex-start' : 'center', padding: '14px 0', borderBottom: '1px solid var(--border)', gap: 16 }}>
      <label style={{ width: 130, flexShrink: 0, fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', paddingTop: secret ? 8 : 0 }}>{label}</label>
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <input
            className="form-input"
            readOnly
            value={secret && !showSecret ? 'Click to view' : value}
            onClick={(e) => { if (secret && !showSecret) onToggleSecret(); else e.target.select(); }}
            style={{
              fontFamily: (!secret || showSecret) ? "'SF Mono', Monaco, 'Cascadia Code', monospace" : 'inherit',
              fontSize: 13, flex: 1, marginBottom: 0,
              cursor: (secret && !showSecret) ? 'pointer' : 'text',
              color: (secret && !showSecret) ? 'var(--text-muted)' : 'var(--text-primary)',
            }}
          />
          <button className="btn btn-secondary btn-sm" onClick={() => { if (secret && !showSecret) onToggleSecret(); copyText(value); }} title="Copy &amp; select">select</button>
        </div>
        {secret && <p className="text-sm text-muted" style={{ marginTop: 4 }}>Don&apos;t share your client secret with anyone.</p>}
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
    return <div className="loading"><div className="spinner" /> {searchParams.get('id') ? 'Loading application...' : 'Creating application...'}</div>;
  }

  // --- Step 1: Choose type (fallback) ---
  if (step === 'choose') {
    return (
      <>
        <div className="page-header">
          <h2>Protect an Application</h2>
          <p>Choose the type of application you want to protect with ZTNA</p>
        </div>
        {error && <div className="text-sm" style={{ color: 'var(--danger)', marginBottom: 16, padding: '8px 12px', background: 'rgba(239,68,68,0.1)', borderRadius: 8 }}>{error}</div>}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 20 }}>
          {appTypes.map((app) => {
            const Icon = app.icon;
            return (
              <div key={app.type} className="card" style={{ cursor: 'pointer', transition: 'transform 0.15s, box-shadow 0.15s', padding: 0 }}
                onClick={() => { setSelectedType(app); handleCreateForType(app); }}
                onMouseEnter={(e) => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 8px 24px rgba(0,0,0,0.3)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = ''; }}>
                <div style={{ padding: '28px 20px', textAlign: 'center' }}>
                  <div style={{ width: 56, height: 56, borderRadius: 14, background: `${app.color}15`, border: `2px solid ${app.color}30`, display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 12px' }}>
                    <Icon size={24} color={app.color} />
                  </div>
                  <h3 style={{ fontSize: 15, marginBottom: 4, color: 'var(--text-primary)' }}>{app.title}</h3>
                  <span className={`badge badge-${app.type}`}>{app.type.toUpperCase()}</span>
                </div>
              </div>
            );
          })}
        </div>
        <div style={{ marginTop: 20 }}>
          <button className="btn btn-secondary" onClick={() => navigate('/dashboard/resources')}><ArrowLeft size={14} /> Back to Resources</button>
        </div>
      </>
    );
  }

  // --- Step 2: Full Application Page ---
  if (step === 'app' && creds) {
    const typeInfo = selectedType || appTypes[0];
    const Icon = typeInfo.icon;

    const PolicyTable = ({ policies, showAdd, onAdd }) => (
      <div style={{ marginTop: 12 }}>
        {policies.length === 0 ? (
          <p className="text-sm text-muted" style={{ padding: '8px 0' }}>No policies configured.</p>
        ) : (
          <table style={{ width: '100%', fontSize: 13 }}>
            <thead><tr>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Name</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Action</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Priority</th>
              <th style={{ textAlign: 'center', padding: '6px 8px' }}>Enabled</th>
              <th style={{ textAlign: 'right', padding: '6px 8px' }}>Actions</th>
            </tr></thead>
            <tbody>
              {policies.map(r => (
                <tr key={r.id}>
                  <td style={{ padding: '6px 8px', color: 'var(--text-primary)' }}>{r.name}</td>
                  <td style={{ padding: '6px 8px' }}><span className={`badge badge-${r.action === 'allow' ? 'enabled' : r.action === 'deny' ? 'disabled' : 'web'}`}>{r.action}</span></td>
                  <td style={{ padding: '6px 8px' }}>{r.priority}</td>
                  <td style={{ padding: '6px 8px', textAlign: 'center' }}>
                    <input type="checkbox" checked={r.enabled} onChange={() => handleTogglePolicy(r)} style={{ accentColor: 'var(--accent)' }} />
                  </td>
                  <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                    <button className="btn btn-danger btn-sm" onClick={() => handleDeletePolicy(r.id)} title="Delete"><Trash2 size={12} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {showAdd && (
          <button className="btn btn-secondary btn-sm" style={{ marginTop: 8 }} onClick={onAdd}><Plus size={12} /> Add Policy</button>
        )}
      </div>
    );

    return (
      <>
        <div className="page-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, background: `${typeInfo.color}15`, border: `2px solid ${typeInfo.color}30`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Icon size={20} color={typeInfo.color} />
            </div>
            <div>
              <h2>ZTNA Gateway - {typeInfo.title}</h2>
              <p>Application credentials and configuration</p>
            </div>
          </div>
        </div>

        {error && <div className="text-sm" style={{ color: 'var(--danger)', marginBottom: 16, padding: '8px 12px', background: 'rgba(239,68,68,0.1)', borderRadius: 8 }}>{error}</div>}
        {successMsg && <div className="text-sm" style={{ color: 'var(--success)', marginBottom: 16, padding: '8px 12px', background: 'rgba(34,197,94,0.1)', borderRadius: 8 }}>{successMsg}</div>}

        {/* --- Details Section --- */}
        <Section title="Details">
          <CredRow label="Client ID" value={creds.client_id} />
          <CredRow label="Client secret" value={creds.client_secret} secret showSecret={showSecret} onToggleSecret={() => setShowSecret(!showSecret)} />
          <CredRow label="API hostname" value={window.location.host} />
        </Section>

        {/* --- Policy Section --- */}
        <Section title="Policy">
          <div style={{ marginTop: 12 }}>
            <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>App Policy</h4>
            <p className="text-sm text-muted" style={{ marginBottom: 4 }}>Rules that apply specifically to this application.</p>
            <PolicyTable policies={appPolicies} showAdd onAdd={handleAddAppPolicy} />
          </div>

          <div style={{ marginTop: 24, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
            <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>Group Policy</h4>
            <p className="text-sm text-muted" style={{ marginBottom: 4 }}>Rules that apply based on user roles/groups.</p>
            <PolicyTable policies={groupPolicies} />
          </div>

          <div style={{ marginTop: 24, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
            <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>Global Policy</h4>
            <p className="text-sm text-muted" style={{ marginBottom: 4 }}>Rules that apply to all applications system-wide.</p>
            <PolicyTable policies={globalPolicies} />
          </div>
        </Section>

        {/* --- Settings Section --- */}
        <Section title="Settings">
          <div style={{ marginTop: 12 }}>
            <div className="form-group">
              <label>Application Type</label>
              <div className="cred-display" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Icon size={16} color={typeInfo.color} />
                <span>{typeInfo.title}</span>
                <span className={`badge badge-${typeInfo.type}`} style={{ marginLeft: 'auto' }}>{typeInfo.type.toUpperCase()}</span>
              </div>
            </div>
            <div className="form-group">
              <label>Application Name</label>
              <input className="form-input" value={appName} onChange={(e) => setAppName(e.target.value)} placeholder="Application name" />
            </div>
          </div>
        </Section>

        {/* --- Bottom Actions --- */}
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8, marginBottom: 40 }}>
          <button className="btn btn-secondary" onClick={() => navigate('/dashboard/resources')}>
            <ArrowLeft size={14} /> Back to Resources
          </button>
          <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
            <Save size={14} /> {saving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </>
    );
  }

  return null;
}
