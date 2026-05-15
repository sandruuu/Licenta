import { useEffect, useState } from 'react';
import { FileText } from 'lucide-react';
import { getAuditLog } from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import { FormSelect } from '../components/ui/FormField';
import { formatDateTime } from '../utils/format';

export default function Audit() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [limit, setLimit] = useState(50);

  const handleLimitChange = (event) => {
    setLoading(true);
    setLimit(parseInt(event.target.value, 10));
  };

  useEffect(() => {
    let cancelled = false;
    getAuditLog(limit)
      .then((data) => {
        if (!cancelled) setEntries(Array.isArray(data) ? data : []);
      })
      .catch(console.error)
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [limit]);

  const eventBadgeVariant = (type) => {
    if (!type) return 'neutral';
    if (type.includes('login')) return 'info';
    if (type.includes('mfa')) return 'warning';
    if (type.includes('access')) return 'accent';
    return 'neutral';
  };

  const columns = [
    { key: 'timestamp', label: 'Time', render: (v) => <span className="text-mono text-xs whitespace-nowrap">{formatDateTime(v)}</span> },
    { key: 'event_type', label: 'Event', render: (v) => <Badge variant={eventBadgeVariant(v)}>{v}</Badge> },
    { key: 'username', label: 'User', render: (v) => <span className="text-text-primary">{v || '-'}</span> },
    { key: 'source_ip', label: 'Source IP', render: (v) => <span className="text-mono text-xs">{v || '-'}</span> },
    { key: 'resource', label: 'Resource', render: (v) => <span className="text-xs">{v || '-'}</span> },
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
        <FormSelect
          className="w-[150px]"
          value={limit}
          onChange={handleLimitChange}
        >
          <option value={25}>Last 25</option>
          <option value={50}>Last 50</option>
          <option value={100}>Last 100</option>
          <option value={500}>Last 500</option>
        </FormSelect>
      </div>

      <DataTable columns={columns} data={entries} loading={loading} emptyIcon={FileText} emptyTitle="No audit entries found" />
    </>
  );
}
