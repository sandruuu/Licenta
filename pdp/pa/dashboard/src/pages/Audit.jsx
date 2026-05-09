import { useState, useEffect } from 'react';
import { getAuditLog } from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import { FileText } from 'lucide-react';

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('ro-RO', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
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

  const eventBadgeVariant = (type) => {
    if (!type) return 'neutral';
    if (type.includes('login')) return 'info';
    if (type.includes('mfa')) return 'warning';
    if (type.includes('access')) return 'accent';
    return 'neutral';
  };

  const columns = [
    { key: 'timestamp', label: 'Time', render: (v) => <span className="text-mono text-xs whitespace-nowrap">{formatDate(v)}</span> },
    { key: 'event_type', label: 'Event', render: (v) => <Badge variant={eventBadgeVariant(v)}>{v}</Badge> },
    { key: 'username', label: 'User', render: (v) => <span className="text-text-primary">{v || '—'}</span> },
    { key: 'source_ip', label: 'Source IP', render: (v) => <span className="text-mono text-xs">{v || '—'}</span> },
    { key: 'resource', label: 'Resource', render: (v) => <span className="text-xs">{v || '—'}</span> },
    { key: 'decision', label: 'Decision', render: (v, row) => {
      if (v) return <Badge variant={v === 'allow' ? 'success' : v === 'deny' ? 'danger' : 'warning'}>{v}</Badge>;
      return <Badge variant={row.success ? 'success' : 'danger'}>{row.success ? 'OK' : 'FAIL'}</Badge>;
    }},
    { key: 'details', label: 'Details', render: (v) => <span className="text-xs text-text-muted max-w-[250px] truncate block">{v}</span> },
  ];

  return (
    <>
      <PageHeader title="Audit Log" subtitle="Security events and access decisions" />

      <div className="mb-4 flex justify-end">
        <select
          className="bg-surface-card border border-border rounded-md px-3 py-1.5 text-xs text-text-secondary"
          value={limit}
          onChange={(e) => setLimit(parseInt(e.target.value))}
        >
          <option value={25}>Last 25</option>
          <option value={50}>Last 50</option>
          <option value={100}>Last 100</option>
          <option value={500}>Last 500</option>
        </select>
      </div>

      <DataTable columns={columns} data={entries} loading={loading} emptyIcon={FileText} emptyTitle="No audit entries found" />
    </>
  );
}
