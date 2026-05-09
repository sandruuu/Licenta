import { useState, useEffect } from 'react';
import { getSessions, revokeSession } from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import { Radio, XCircle } from 'lucide-react';

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('ro-RO', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
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

  const columns = [
    { key: 'username', label: 'User', render: (v) => <span className="font-medium text-text-primary">{v}</span> },
    { key: 'resource', label: 'Resource', render: (v) => <span className="text-mono">{v || '—'}</span> },
    { key: 'source_ip', label: 'Source IP', render: (v) => <span className="text-mono text-xs">{v || '—'}</span> },
    { key: 'risk_score', label: 'Risk', render: (v) => (
      <span className={v > 70 ? 'text-danger' : v > 40 ? 'text-warning' : 'text-success'}>{v}</span>
    )},
    { key: 'status', label: 'Status', render: (_, row) => {
      const status = getStatus(row);
      return <Badge variant={status === 'active' ? 'success' : status === 'revoked' ? 'danger' : 'neutral'}>{status}</Badge>;
    }},
    { key: 'created_at', label: 'Created', render: (v) => <span className="text-mono text-xs">{formatDate(v)}</span> },
    { key: 'expires_at', label: 'Expires', render: (v) => <span className="text-mono text-xs">{formatDate(v)}</span> },
    { key: 'actions', label: 'Actions', align: 'right', render: (_, row) => {
      const status = getStatus(row);
      return status === 'active' ? (
        <Button variant="danger" className="!px-3 !py-1.5 !text-[11px] !shadow-none" onClick={() => handleRevoke(row.id)}>
          <XCircle size={12} /> Revoke
        </Button>
      ) : null;
    }},
  ];

  return (
    <>
      <PageHeader title="Sessions" subtitle="Active and historical access sessions" />
      <DataTable columns={columns} data={sessions} loading={loading} emptyIcon={Radio} emptyTitle="No sessions found" />
    </>
  );
}
