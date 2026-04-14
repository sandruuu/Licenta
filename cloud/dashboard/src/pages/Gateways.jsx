import { useEffect, useState } from 'react';
import { Plus, RefreshCw, Trash2, Ban, Copy, Router, Settings, Save, X } from 'lucide-react';
import {
  getGateways,
  createGateway,
  regenerateGatewayToken,
  revokeGateway,
  deleteGateway,
  updateGateway,
} from '../api';

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

function statusBadge(status) {
  const v = (status || '').toLowerCase();
  if (v === 'enrolled' || v === 'active') return 'badge-active';
  if (v === 'revoked') return 'badge-revoked';
  if (v === 'pending') return 'badge-gateway';
  return 'badge-disabled';
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
  const [form, setForm] = useState({ name: '', fqdn: '', assigned_resources: '' });
  const [editingIdP, setEditingIdP] = useState(null); // gateway id being edited
  const [idpForm, setIdpForm] = useState({
    auth_mode: 'builtin',
    issuer: '',
    client_id: '',
    client_secret: '',
    scopes: 'openid profile email',
    claim_username: 'preferred_username',
    claim_email: 'email',
  });

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
      };
      const result = await createGateway(payload);
      if (result && result.enrollment_token) {
        setCreatedToken(result.enrollment_token);
      }
      setForm({ name: '', fqdn: '', assigned_resources: '' });
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
    setEditingIdP(gw.id);
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

  if (loading) return <div className="loading"><div className="spinner" /> Loading gateways...</div>;

  return (
    <>
      <div className="page-header">
        <h2>Gateways</h2>
        <p>Manage enrollment tokens and lifecycle for edge gateways</p>
      </div>

      {error && (
        <div className="card" style={{ background: 'var(--danger-bg, #2d1b1b)', border: '1px solid var(--danger, #e74c3c)', marginBottom: 16, padding: '12px 16px' }}>
          <span style={{ color: 'var(--danger, #e74c3c)' }}>{error}</span>
        </div>
      )}

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <h3>Create Gateway</h3>
        </div>

        <form onSubmit={handleCreate}>
          <div className="form-row">
            <div className="form-group">
              <label>Name</label>
              <input
                className="form-input"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="HQ Gateway"
                required
              />
            </div>
            <div className="form-group">
              <label>FQDN</label>
              <input
                className="form-input"
                value={form.fqdn}
                onChange={(e) => setForm({ ...form, fqdn: e.target.value })}
                placeholder="gateway.example.com"
              />
            </div>
          </div>

          <div className="form-group">
            <label>Assigned Resources (comma-separated)</label>
            <input
              className="form-input"
              value={form.assigned_resources}
              onChange={(e) => setForm({ ...form, assigned_resources: e.target.value })}
              placeholder="web-app-1, ssh-prod"
            />
          </div>

          <button className="btn btn-primary" type="submit" disabled={saving}>
            <Plus size={14} /> {saving ? 'Creating...' : 'Create Gateway'}
          </button>
        </form>

        {createdToken && (
          <div style={{ marginTop: 14, padding: 12, border: '1px solid var(--warning)', borderRadius: 'var(--radius-sm)', background: 'var(--warning-dim)' }}>
            <div style={{ fontSize: 12, marginBottom: 6, color: 'var(--text-primary)', fontWeight: 600 }}>Enrollment Token</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <code className="text-mono" style={{ flex: 1, overflowWrap: 'anywhere', color: 'var(--text-primary)' }}>{createdToken}</code>
              <button className="btn btn-secondary btn-sm" type="button" onClick={() => copyText(createdToken)}>
                <Copy size={12} /> Copy
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{gateways.length} Gateway{gateways.length !== 1 ? 's' : ''}</h3>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>FQDN</th>
                <th>Status</th>
                <th>OIDC Client ID</th>
                <th>Identity Source</th>
                <th>Resources</th>
                <th>Token Expires</th>
                <th>Cert Expires</th>
                <th>Last Seen</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {gateways.length === 0 ? (
                <tr>
                  <td colSpan={10}>
                    <div className="empty-state">
                      <Router size={40} />
                      <p>No gateways created yet.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                gateways.map((gw) => (
                  <tr key={gw.id}>
                    <td>
                      <strong style={{ color: 'var(--text-primary)' }}>{gw.name || '—'}</strong>
                      <div className="text-sm text-muted text-mono">{gw.id}</div>
                    </td>
                    <td className="text-mono text-sm">{gw.fqdn || '—'}</td>
                    <td><span className={`badge ${statusBadge(gw.status)}`}>{gw.status || 'unknown'}</span></td>
                    <td className="text-mono text-sm">{gw.oidc_client_id || '—'}</td>
                    <td>
                      <span className={`badge ${gw.auth_mode === 'federated' ? 'badge-gateway' : 'badge-active'}`}>
                        {gw.auth_mode === 'federated' ? 'Federated' : 'Built-in'}
                      </span>
                    </td>
                    <td className="text-sm">{Array.isArray(gw.assigned_resources) && gw.assigned_resources.length ? gw.assigned_resources.join(', ') : '—'}</td>
                    <td className="text-mono text-sm">{formatDate(gw.token_expires_at)}</td>
                    <td className="text-mono text-sm">{formatDate(gw.cert_expires_at)}</td>
                    <td className="text-mono text-sm">{formatDate(gw.last_seen_at)}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button className="btn btn-secondary btn-sm" onClick={() => handleRegenerateToken(gw.id)} title="Regenerate Token">
                          <RefreshCw size={12} />
                        </button>
                        <button className="btn btn-secondary btn-sm" onClick={() => openIdPSettings(gw)} title="Identity Source">
                          <Settings size={12} />
                        </button>
                        <button className="btn btn-secondary btn-sm" onClick={() => handleRevoke(gw.id)} title="Revoke">
                          <Ban size={12} />
                        </button>
                        <button className="btn btn-danger btn-sm" onClick={() => handleDelete(gw.id)} title="Delete">
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

      {editingIdP && (
        <div className="modal-overlay" onClick={() => setEditingIdP(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 520 }}>
            <div className="modal-header">
              <h3>Identity Source Settings</h3>
              <button className="btn btn-secondary btn-sm" onClick={() => setEditingIdP(null)}>
                <X size={14} />
              </button>
            </div>

            <div className="form-group">
              <label>Authentication Mode</label>
              <div style={{ display: 'flex', gap: 12, marginTop: 6 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                  <input
                    type="radio"
                    name="auth_mode"
                    value="builtin"
                    checked={idpForm.auth_mode === 'builtin'}
                    onChange={() => setIdpForm({ ...idpForm, auth_mode: 'builtin' })}
                  />
                  Built-in (Cloud IdP)
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                  <input
                    type="radio"
                    name="auth_mode"
                    value="federated"
                    checked={idpForm.auth_mode === 'federated'}
                    onChange={() => setIdpForm({ ...idpForm, auth_mode: 'federated' })}
                  />
                  Federated (External OIDC)
                </label>
              </div>
            </div>

            {idpForm.auth_mode === 'federated' && (
              <>
                <div className="form-group">
                  <label>Issuer URL</label>
                  <input
                    className="form-input"
                    value={idpForm.issuer}
                    onChange={(e) => setIdpForm({ ...idpForm, issuer: e.target.value })}
                    placeholder="https://keycloak.example.com/realms/corp"
                  />
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label>Client ID</label>
                    <input
                      className="form-input"
                      value={idpForm.client_id}
                      onChange={(e) => setIdpForm({ ...idpForm, client_id: e.target.value })}
                      placeholder="ztna-cloud"
                    />
                  </div>
                  <div className="form-group">
                    <label>Client Secret</label>
                    <input
                      className="form-input"
                      type="password"
                      value={idpForm.client_secret}
                      onChange={(e) => setIdpForm({ ...idpForm, client_secret: e.target.value })}
                      placeholder="••••••••"
                    />
                  </div>
                </div>
                <div className="form-group">
                  <label>Scopes</label>
                  <input
                    className="form-input"
                    value={idpForm.scopes}
                    onChange={(e) => setIdpForm({ ...idpForm, scopes: e.target.value })}
                    placeholder="openid profile email"
                  />
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label>Username Claim</label>
                    <input
                      className="form-input"
                      value={idpForm.claim_username}
                      onChange={(e) => setIdpForm({ ...idpForm, claim_username: e.target.value })}
                      placeholder="preferred_username"
                    />
                  </div>
                  <div className="form-group">
                    <label>Email Claim</label>
                    <input
                      className="form-input"
                      value={idpForm.claim_email}
                      onChange={(e) => setIdpForm({ ...idpForm, claim_email: e.target.value })}
                      placeholder="email"
                    />
                  </div>
                </div>
              </>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
              <button className="btn btn-secondary" onClick={() => setEditingIdP(null)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleSaveIdP} disabled={saving}>
                <Save size={14} /> {saving ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
