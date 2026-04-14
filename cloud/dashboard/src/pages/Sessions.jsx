import { useState, useEffect } from 'react';
import { getSessions, revokeSession } from '../api';
import { Radio, XCircle } from 'lucide-react';

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('ro-RO', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export default function Sessions() {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    getSessions()
      .then((data) => setSessions(Array.isArray(data) ? data : []))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleRevoke = async (id) => {
    if (!confirm('Revoke this session?')) return;
    await revokeSession(id);
    load();
  };

  const isExpired = (s) => new Date(s.expires_at) < new Date();
  const getStatus = (s) => {
    if (s.revoked) return 'revoked';
    if (isExpired(s)) return 'expired';
    return 'active';
  };

  if (loading) return <div className="loading"><div className="spinner" /> Loading sessions...</div>;

  return (
    <>
      <div className="page-header">
        <h2>Sessions</h2>
        <p>Active and historical access sessions</p>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{sessions.length} Session{sessions.length !== 1 ? 's' : ''}</h3>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Resource</th>
                <th>Source IP</th>
                <th>Risk</th>
                <th>Status</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sessions.length === 0 ? (
                <tr>
                  <td colSpan={8}>
                    <div className="empty-state">
                      <Radio size={40} />
                      <p>No sessions found.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                sessions.map((sess) => {
                  const status = getStatus(sess);
                  return (
                    <tr key={sess.id}>
                      <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{sess.username}</td>
                      <td className="text-mono">{sess.resource || '—'}</td>
                      <td className="text-mono text-sm">{sess.source_ip || '—'}</td>
                      <td>
                        <span style={{ color: sess.risk_score > 70 ? 'var(--danger)' : sess.risk_score > 40 ? 'var(--warning)' : 'var(--success)' }}>
                          {sess.risk_score}
                        </span>
                      </td>
                      <td>
                        <span className={`badge badge-${status}`}>
                          {status}
                        </span>
                      </td>
                      <td className="text-mono text-sm">{formatDate(sess.created_at)}</td>
                      <td className="text-mono text-sm">{formatDate(sess.expires_at)}</td>
                      <td>
                        {status === 'active' && (
                          <button className="btn btn-danger btn-sm" onClick={() => handleRevoke(sess.id)} title="Revoke">
                            <XCircle size={12} /> Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
