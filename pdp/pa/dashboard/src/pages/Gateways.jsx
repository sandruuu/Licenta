import { useEffect, useState } from 'react';
import { Plus, RefreshCw, Trash2, Ban, Copy, Router, Settings, Save, X, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import {
  getGateways,
  createGateway,
  regenerateGatewayToken,
  revokeGateway,
  deleteGateway,
  updateGateway,
  testGatewayFederation,
} from '../api';
import PageHeader from '../components/ui/PageHeader';
import Modal from '../components/ui/Modal';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import FormField, { FormInput, FormRow } from '../components/ui/FormField';

function formatDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString('ro-RO', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function statusVariant(status) {
  const v = (status || '').toLowerCase();
  if (v === 'enrolled' || v === 'active') return 'success';
  if (v === 'revoked') return 'danger';
  if (v === 'pending') return 'info';
  return 'neutral';
}

function certExpiryInfo(value) {
  if (!value) return { label: '—', variant: 'neutral', title: 'No certificate' };
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return { label: value, variant: 'neutral', title: value };
  const ms = d.getTime() - Date.now();
  const hours = ms / 3_600_000;
  const days = Math.floor(hours / 24);
  const formatted = formatDate(value);
  if (ms <= 0) {
    return { label: `Expired (${formatted})`, variant: 'neutral', title: 'Certificate has expired' };
  }
  if (hours < 24) {
    const h = Math.max(1, Math.floor(hours));
    return { label: `${h}h left`, variant: 'danger', title: `Expires ${formatted}` };
  }
  if (hours < 24 * 7) {
    return { label: `${days}d left`, variant: 'warning', title: `Expires ${formatted}` };
  }
  return { label: `${days}d left`, variant: 'success', title: `Expires ${formatted}` };
}

function copyText(text) {
  if (!text) return;
  navigator.clipboard.writeText(text).catch(() => {});
}

export default function Gateways() {
  const [gateways, setGateways] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [createdToken, setCreatedToken] = useState('');
  const [form, setForm] = useState({
    name: '',
    fqdn: '',
    assigned_resources: '',
    auth_mode: 'builtin',
    issuer: '',
    client_id: '',
    client_secret: '',
    scopes: 'openid profile email',
    claim_username: 'preferred_username',
    claim_email: 'email',
  });
  const [editingIdP, setEditingIdP] = useState(null);
  const [idpForm, setIdpForm] = useState({
    auth_mode: 'builtin',
    issuer: '',
    client_id: '',
    client_secret: '',
    scopes: 'openid profile email',
    claim_username: 'preferred_username',
    claim_email: 'email',
  });
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  const load = () => {
    setLoading(true);
    getGateways()
      .then((data) => setGateways(Array.isArray(data) ? data : []))
      .catch((e) => setError(e.message || 'Failed to load gateways'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    setError('');
    setCreatedToken('');
    if (!form.name.trim()) {
      setError('Gateway name is required');
      return;
    }

    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        fqdn: form.fqdn.trim(),
        assigned_resources: form.assigned_resources
          ? form.assigned_resources.split(',').map((x) => x.trim()).filter(Boolean)
          : [],
        auth_mode: form.auth_mode,
      };
      if (form.auth_mode === 'federated') {
        if (!form.issuer.trim() || !form.client_id.trim()) {
          setError('Federated mode requires Issuer URL and Client ID');
          setSaving(false);
          return;
        }
        payload.federation_config = {
          issuer: form.issuer.trim(),
          client_id: form.client_id.trim(),
          client_secret: form.client_secret.trim(),
          scopes: form.scopes.trim() || 'openid profile email',
          claim_mapping: {
            username: form.claim_username.trim() || 'preferred_username',
            email: form.claim_email.trim() || 'email',
          },
          auto_discovery: true,
        };
      }
      const result = await createGateway(payload);
      if (result && result.enrollment_token) {
        setCreatedToken(result.enrollment_token);
      }
      setForm({
        name: '',
        fqdn: '',
        assigned_resources: '',
        auth_mode: 'builtin',
        issuer: '',
        client_id: '',
        client_secret: '',
        scopes: 'openid profile email',
        claim_username: 'preferred_username',
        claim_email: 'email',
      });
      load();
    } catch (e2) {
      setError(e2.message || 'Failed to create gateway');
    } finally {
      setSaving(false);
    }
  };

  const handleRegenerateToken = async (id) => {
    setError('');
    try {
      const result = await regenerateGatewayToken(id);
      if (result && result.enrollment_token) {
        setCreatedToken(result.enrollment_token);
      }
      load();
    } catch (e) {
      setError(e.message || 'Failed to regenerate enrollment token');
    }
  };

  const handleRevoke = async (id) => {
    if (!confirm('Revoke this gateway?')) return;
    setError('');
    try {
      await revokeGateway(id);
      load();
    } catch (e) {
      setError(e.message || 'Failed to revoke gateway');
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this gateway? This cannot be undone.')) return;
    setError('');
    try {
      await deleteGateway(id);
      load();
    } catch (e) {
      setError(e.message || 'Failed to delete gateway');
    }
  };

  const openIdPSettings = (gw) => {
    const fc = gw.federation_config || {};
    setIdpForm({
      auth_mode: gw.auth_mode || 'builtin',
      issuer: fc.issuer || '',
      client_id: fc.client_id || '',
      client_secret: fc.client_secret || '',
      scopes: fc.scopes || 'openid profile email',
      claim_username: (fc.claim_mapping && fc.claim_mapping.username) || 'preferred_username',
      claim_email: (fc.claim_mapping && fc.claim_mapping.email) || 'email',
    });
    setTestResult(null);
    setEditingIdP(gw.id);
  };

  const handleTestFederation = async () => {
    setError('');
    setTesting(true);
    setTestResult(null);
    try {
      const r = await testGatewayFederation(editingIdP, idpForm.issuer.trim());
      setTestResult(r);
    } catch (e) {
      setTestResult({ ok: false, error: e.message || 'Discovery probe failed' });
    } finally {
      setTesting(false);
    }
  };

  const handleSaveIdP = async () => {
    setError('');
    setSaving(true);
    try {
      const payload = {
        auth_mode: idpForm.auth_mode,
      };
      if (idpForm.auth_mode === 'federated') {
        payload.federation_config = {
          issuer: idpForm.issuer.trim(),
          client_id: idpForm.client_id.trim(),
          client_secret: idpForm.client_secret.trim(),
          scopes: idpForm.scopes.trim(),
          claim_mapping: {
            username: idpForm.claim_username.trim(),
            email: idpForm.claim_email.trim(),
          },
          auto_discovery: true,
        };
      }
      await updateGateway(editingIdP, payload);
      setEditingIdP(null);
      load();
    } catch (e) {
      setError(e.message || 'Failed to save IdP settings');
    } finally {
      setSaving(false);
    }
  };

  const columns = [
    {
      key: 'name',
      label: 'Name',
      render: (v, row) => (
        <div>
          <strong className="text-text-primary">{row.name || '—'}</strong>
          <div className="text-mono text-text-muted">{row.id}</div>
        </div>
      ),
    },
    { key: 'fqdn', label: 'FQDN', render: (v) => <span className="text-mono">{v || '—'}</span> },
    { key: 'status', label: 'Status', render: (v, row) => <Badge variant={statusVariant(row.status)}>{row.status || 'unknown'}</Badge> },
    { key: 'oidc_client_id', label: 'OIDC Client ID', render: (v) => <span className="text-mono">{v || '—'}</span> },
    {
      key: 'auth_mode',
      label: 'Identity Source',
      render: (v, row) => (
        <Badge variant={row.auth_mode === 'federated' ? 'info' : 'success'}>
          {row.auth_mode === 'federated' ? 'Federated' : 'Built-in'}
        </Badge>
      ),
    },
    {
      key: 'assigned_resources',
      label: 'Resources',
      render: (v, row) => Array.isArray(row.assigned_resources) && row.assigned_resources.length
        ? row.assigned_resources.join(', ')
        : '—',
    },
    { key: 'token_expires_at', label: 'Token Expires', render: (v) => <span className="text-mono">{formatDate(v)}</span> },
    {
      key: 'cert_expires_at',
      label: 'Cert Expires',
      render: (v) => {
        const b = certExpiryInfo(v);
        return <Badge variant={b.variant} title={b.title}>{b.label}</Badge>;
      },
    },
    { key: 'last_seen_at', label: 'Last Seen', render: (v) => <span className="text-mono">{formatDate(v)}</span> },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      render: (_, row) => (
        <div className="flex gap-1.5">
          <button className="inline-flex items-center gap-1 px-2 py-1.5 border border-border rounded text-xs text-text-secondary hover:bg-surface-hover hover:text-text-primary transition-colors" onClick={() => handleRegenerateToken(row.id)} title="Regenerate Token">
            <RefreshCw size={12} />
          </button>
          <button className="inline-flex items-center gap-1 px-2 py-1.5 border border-border rounded text-xs text-text-secondary hover:bg-surface-hover hover:text-text-primary transition-colors" onClick={() => openIdPSettings(row)} title="Identity Source">
            <Settings size={12} />
          </button>
          <button className="inline-flex items-center gap-1 px-2 py-1.5 border border-border rounded text-xs text-text-secondary hover:bg-surface-hover hover:text-text-primary transition-colors" onClick={() => handleRevoke(row.id)} title="Revoke">
            <Ban size={12} />
          </button>
          <button className="inline-flex items-center gap-1 px-2 py-1.5 border border-border rounded text-xs text-danger hover:bg-danger-muted transition-colors" onClick={() => handleDelete(row.id)} title="Delete">
            <Trash2 size={12} />
          </button>
        </div>
      ),
    },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12 text-text-muted">
        <span className="spinner" /> Loading gateways...
      </div>
    );
  }

  return (
    <>
      <PageHeader title="Gateways" subtitle="Manage enrollment tokens and lifecycle for edge gateways" />

      {error && (
        <div className="bg-danger-muted border border-danger rounded-md p-3 mb-4 text-sm text-danger">
          {error}
        </div>
      )}

      {/* Create Gateway Form */}
      <div className="bg-surface-card border border-border rounded-md p-6 mb-4 shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
        <h3 className="text-sm font-semibold text-text-primary mb-4">Create Gateway</h3>

        <form onSubmit={handleCreate}>
          <FormRow>
            <FormField label="Name" htmlFor="gw-name">
              <FormInput
                id="gw-name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="HQ Gateway"
                required
              />
            </FormField>
            <FormField label="FQDN" htmlFor="gw-fqdn">
              <FormInput
                id="gw-fqdn"
                value={form.fqdn}
                onChange={(e) => setForm({ ...form, fqdn: e.target.value })}
                placeholder="gateway.example.com"
              />
            </FormField>
          </FormRow>

          <FormField label="Assigned Resources (comma-separated)" htmlFor="gw-resources">
            <FormInput
              id="gw-resources"
              value={form.assigned_resources}
              onChange={(e) => setForm({ ...form, assigned_resources: e.target.value })}
              placeholder="web-app-1, ssh-prod"
            />
          </FormField>

          <FormField label="Identity Source">
            <div className="flex gap-4 mt-1.5">
              <label className="flex items-center gap-1.5 cursor-pointer text-[13px] text-text-secondary">
                <input
                  type="radio"
                  name="create_auth_mode"
                  value="builtin"
                  checked={form.auth_mode === 'builtin'}
                  onChange={() => setForm({ ...form, auth_mode: 'builtin' })}
                  className="accent-accent"
                />
                Built-in (Cloud IdP)
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer text-[13px] text-text-secondary">
                <input
                  type="radio"
                  name="create_auth_mode"
                  value="federated"
                  checked={form.auth_mode === 'federated'}
                  onChange={() => setForm({ ...form, auth_mode: 'federated' })}
                  className="accent-accent"
                />
                Federated (External OIDC)
              </label>
            </div>
            <p className="text-[11px] text-text-muted mt-1">
              {form.auth_mode === 'builtin'
                ? 'Users authenticate against this cloud\u2019s built-in OIDC provider.'
                : 'Users are redirected to an external OIDC IdP (e.g. Keycloak, Okta, Azure AD).'}
            </p>
          </FormField>

          {form.auth_mode === 'federated' && (
            <div className="p-3 border border-border rounded-md mb-4 space-y-4">
              <FormField label="Issuer URL *" htmlFor="gw-issuer">
                <FormInput
                  id="gw-issuer"
                  value={form.issuer}
                  onChange={(e) => setForm({ ...form, issuer: e.target.value })}
                  placeholder="https://keycloak.example.com/realms/corp"
                />
              </FormField>
              <FormRow>
                <FormField label="Client ID *" htmlFor="gw-client-id">
                  <FormInput
                    id="gw-client-id"
                    value={form.client_id}
                    onChange={(e) => setForm({ ...form, client_id: e.target.value })}
                    placeholder="ztna-pdp"
                  />
                </FormField>
                <FormField label="Client Secret" htmlFor="gw-client-secret">
                  <FormInput
                    id="gw-client-secret"
                    type="password"
                    value={form.client_secret}
                    onChange={(e) => setForm({ ...form, client_secret: e.target.value })}
                    placeholder="••••••••"
                  />
                </FormField>
              </FormRow>
              <FormField label="Scopes" htmlFor="gw-scopes">
                <FormInput
                  id="gw-scopes"
                  value={form.scopes}
                  onChange={(e) => setForm({ ...form, scopes: e.target.value })}
                  placeholder="openid profile email"
                />
              </FormField>
              <FormRow>
                <FormField label="Username Claim" htmlFor="gw-username-claim">
                  <FormInput
                    id="gw-username-claim"
                    value={form.claim_username}
                    onChange={(e) => setForm({ ...form, claim_username: e.target.value })}
                    placeholder="preferred_username"
                  />
                </FormField>
                <FormField label="Email Claim" htmlFor="gw-email-claim">
                  <FormInput
                    id="gw-email-claim"
                    value={form.claim_email}
                    onChange={(e) => setForm({ ...form, claim_email: e.target.value })}
                    placeholder="email"
                  />
                </FormField>
              </FormRow>
            </div>
          )}

          <Button variant="primary" type="submit" disabled={saving}>
            <Plus size={14} /> {saving ? 'Creating...' : 'Create Gateway'}
          </Button>
        </form>

        {createdToken && (
          <div className="mt-4 p-3 border border-warning/30 rounded-md bg-warning-muted">
            <div className="text-xs font-semibold text-text-primary mb-1.5">Enrollment Token</div>
            <div className="flex gap-2 items-center">
              <code className="text-mono flex-1 [overflow-wrap:anywhere] text-text-primary">{createdToken}</code>
              <Button variant="secondary" onClick={() => copyText(createdToken)} className="text-xs px-2 py-1">
                <Copy size={12} /> Copy
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Gateway List */}
      <DataTable
        columns={columns}
        data={gateways}
        loading={loading}
        emptyIcon={Router}
        emptyTitle="No gateways created yet."
      />

      {/* IdP Settings Modal */}
      <Modal
        open={!!editingIdP}
        onClose={() => setEditingIdP(null)}
        title="Identity Source Settings"
        size="lg"
      >
        <FormField label="Authentication Mode">
          <div className="flex gap-4 mt-1.5">
            <label className="flex items-center gap-1.5 cursor-pointer text-[13px] text-text-secondary">
              <input
                type="radio"
                name="auth_mode"
                value="builtin"
                checked={idpForm.auth_mode === 'builtin'}
                onChange={() => setIdpForm({ ...idpForm, auth_mode: 'builtin' })}
                className="accent-accent"
              />
              Built-in (Cloud IdP)
            </label>
            <label className="flex items-center gap-1.5 cursor-pointer text-[13px] text-text-secondary">
              <input
                type="radio"
                name="auth_mode"
                value="federated"
                checked={idpForm.auth_mode === 'federated'}
                onChange={() => setIdpForm({ ...idpForm, auth_mode: 'federated' })}
                className="accent-accent"
              />
              Federated (External OIDC)
            </label>
          </div>
        </FormField>

        {idpForm.auth_mode === 'federated' && (
          <div className="space-y-4">
            <FormField label="Issuer URL" htmlFor="idp-issuer">
              <FormInput
                id="idp-issuer"
                value={idpForm.issuer}
                onChange={(e) => setIdpForm({ ...idpForm, issuer: e.target.value })}
                placeholder="https://keycloak.example.com/realms/corp"
              />
            </FormField>
            <FormRow>
              <FormField label="Client ID" htmlFor="idp-client-id">
                <FormInput
                  id="idp-client-id"
                  value={idpForm.client_id}
                  onChange={(e) => setIdpForm({ ...idpForm, client_id: e.target.value })}
                  placeholder="ztna-pdp"
                />
              </FormField>
              <FormField label="Client Secret" htmlFor="idp-client-secret">
                <FormInput
                  id="idp-client-secret"
                  type="password"
                  value={idpForm.client_secret}
                  onChange={(e) => setIdpForm({ ...idpForm, client_secret: e.target.value })}
                  placeholder="••••••••"
                />
              </FormField>
            </FormRow>
            <FormField label="Scopes" htmlFor="idp-scopes">
              <FormInput
                id="idp-scopes"
                value={idpForm.scopes}
                onChange={(e) => setIdpForm({ ...idpForm, scopes: e.target.value })}
                placeholder="openid profile email"
              />
            </FormField>
            <FormRow>
              <FormField label="Username Claim" htmlFor="idp-username-claim">
                <FormInput
                  id="idp-username-claim"
                  value={idpForm.claim_username}
                  onChange={(e) => setIdpForm({ ...idpForm, claim_username: e.target.value })}
                  placeholder="preferred_username"
                />
              </FormField>
              <FormField label="Email Claim" htmlFor="idp-email-claim">
                <FormInput
                  id="idp-email-claim"
                  value={idpForm.claim_email}
                  onChange={(e) => setIdpForm({ ...idpForm, claim_email: e.target.value })}
                  placeholder="email"
                />
              </FormField>
            </FormRow>
          </div>
        )}

        <div className="flex justify-between items-center mt-4 pt-4 border-t border-border">
          <div>
            {idpForm.auth_mode === 'federated' && (
              <Button
                variant="secondary"
                onClick={handleTestFederation}
                disabled={testing || !idpForm.issuer.trim()}
                title="Probe the issuer's /.well-known/openid-configuration"
              >
                {testing ? <Loader2 size={14} className="spinner-icon" /> : <CheckCircle2 size={14} />}{' '}
                {testing ? 'Testing...' : 'Test connection'}
              </Button>
            )}
          </div>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => setEditingIdP(null)}>Cancel</Button>
            <Button variant="primary" onClick={handleSaveIdP} disabled={saving}>
              <Save size={14} /> {saving ? 'Saving...' : 'Save'}
            </Button>
          </div>
        </div>

        {testResult && (
          <div
            className={`mt-3 p-2.5 rounded-md border text-xs ${
              testResult.ok
                ? 'border-success bg-success-muted'
                : 'border-danger bg-danger-muted'
            }`}
          >
            {testResult.ok ? (
              <>
                <div className="flex items-center gap-1.5 font-semibold text-text-primary">
                  <CheckCircle2 size={14} /> Discovery succeeded
                </div>
                <div className="text-mono mt-1.5 [overflow-wrap:anywhere]">
                  <div>auth: {testResult.authorization_endpoint}</div>
                  <div>token: {testResult.token_endpoint}</div>
                  {testResult.userinfo_endpoint && <div>userinfo: {testResult.userinfo_endpoint}</div>}
                  {testResult.jwks_uri && <div>jwks: {testResult.jwks_uri}</div>}
                </div>
              </>
            ) : (
              <div className="flex items-center gap-1.5 text-danger">
                <AlertCircle size={14} /> {testResult.error || 'Discovery failed'}
              </div>
            )}
          </div>
        )}
      </Modal>
    </>
  );
}
