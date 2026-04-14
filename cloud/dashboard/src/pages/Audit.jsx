import { useState, useEffect } from 'react';
import { getAuditLog } from '../api';
import { FileText } from 'lucide-react';

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('ro-RO', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

export default function Audit() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [limit, setLimit] = useState(50);

  const load = () => {
    setLoading(true);
    getAuditLog(limit)
      .then((data) => setEntries(Array.isArray(data) ? data : []))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [limit]);

  if (loading) return <div className="loading"><div className="spinner" /> Loading audit log...</div>;

  return (
    <>
      <div className="page-header">
        <h2>Audit Log</h2>
        <p>Security events and access decisions</p>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{entries.length} Entries</h3>
          <div className="flex gap-2">
            <select
              className="form-select"
              style={{ width: 'auto', padding: '6px 10px', fontSize: 12 }}
              value={limit}
              onChange={(e) => setLimit(parseInt(e.target.value))}
            >
              <option value={25}>Last 25</option>
              <option value={50}>Last 50</option>
              <option value={100}>Last 100</option>
              <option value={500}>Last 500</option>
            </select>
          </div>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>User</th>
                <th>Source IP</th>
                <th>Resource</th>
                <th>Decision</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {entries.length === 0 ? (
                <tr>
                  <td colSpan={7}>
                    <div className="empty-state">
                      <FileText size={40} />
                      <p>No audit entries found.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                entries.map((entry) => (
                  <tr key={entry.id}>
                    <td className="text-mono text-sm" style={{ whiteSpace: 'nowrap' }}>{formatDate(entry.timestamp)}</td>
                    <td>
                      <span className={`badge ${
                        entry.event_type?.includes('login') ? 'badge-ssh' :
                        entry.event_type?.includes('mfa') ? 'badge-gateway' :
                        entry.event_type?.includes('access') ? 'badge-web' :
                        'badge-rdp'
                      }`}>
                        {entry.event_type}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-primary)' }}>{entry.username || '—'}</td>
                    <td className="text-mono text-sm">{entry.source_ip || '—'}</td>
                    <td className="text-sm">{entry.resource || '—'}</td>
                    <td>
                      {entry.decision ? (
                        <span className={`badge badge-${entry.decision === 'allow' ? 'allow' : entry.decision === 'deny' ? 'deny' : 'mfa'}`}>
                          {entry.decision}
                        </span>
                      ) : (
                        <span className={`badge ${entry.success ? 'badge-allow' : 'badge-deny'}`}>
                          {entry.success ? 'OK' : 'FAIL'}
                        </span>
                      )}
                    </td>
                    <td className="text-sm text-muted" style={{ maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {entry.details}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
