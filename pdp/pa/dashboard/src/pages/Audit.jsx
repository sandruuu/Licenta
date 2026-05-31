import { useEffect, useMemo, useState } from 'react';
import { FileText } from 'lucide-react';
import { getAuditLog } from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import Modal from '../components/ui/Modal';
import { formatDateTime } from '../utils/format';

function normalize(value) {
  return String(value || '').toLowerCase();
}

function entryOutcome(entry) {
  if (entry.decision === 'deny') return 'denied';
  if (entry.decision === 'step_up' || entry.decision === 'mfa_required') return 'step_up';
  if (entry.decision === 'allow') return 'allowed';
  return entry.success ? 'success' : 'failed';
}

function outcomeBadgeVariant(outcome) {
  if (outcome === 'allowed' || outcome === 'success') return 'success';
  if (outcome === 'denied' || outcome === 'failed') return 'danger';
  if (outcome === 'step_up') return 'warning';
  return 'neutral';
}

function DetailRow({ label, value, mono = false, multiline = false }) {
  return (
    <div className="grid gap-2 border-b border-border-light py-3 last:border-b-0 sm:grid-cols-[150px_1fr]">
      <dt className="text-[11px] font-bold uppercase tracking-[0.08em] text-text-muted">{label}</dt>
      <dd className={`min-w-0 text-sm font-semibold text-text-primary ${mono ? 'text-mono' : ''} ${multiline ? 'whitespace-pre-wrap break-words' : 'truncate'}`}>
        {value || '-'}
      </dd>
    </div>
  );
}

function AuditDetailsModal({ entry, onClose, eventBadgeVariant }) {
  const outcome = entry ? entryOutcome(entry) : '';

  return (
    <Modal
      open={!!entry}
      onClose={onClose}
      title="Audit event details"
      size="2xl"
      footer={<Button onClick={onClose}>Done</Button>}
    >
      {entry ? (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={eventBadgeVariant(entry.event_type)}>{entry.event_type || 'event'}</Badge>
            <Badge variant={outcomeBadgeVariant(outcome)}>{outcome || '-'}</Badge>
          </div>

          <dl className="rounded-md bg-surface-hover px-4">
            <DetailRow label="Timestamp" value={formatDateTime(entry.timestamp)} mono />
            <DetailRow label="Event ID" value={entry.id} mono />
            <DetailRow label="User" value={entry.username} />
            <DetailRow label="User ID" value={entry.user_id} mono />
            <DetailRow label="Source IP" value={entry.source_ip} mono />
            <DetailRow label="Resource" value={entry.resource} />
            <DetailRow label="Decision" value={entry.decision || (entry.success ? 'ok' : 'fail')} />
            <DetailRow label="Success" value={entry.success ? 'true' : 'false'} mono />
            <DetailRow label="Organization" value={entry.tenant_id} mono />
            <DetailRow label="Details" value={entry.details} multiline />
            <DetailRow label="Previous hash" value={entry.prev_hash} mono multiline />
            <DetailRow label="Entry hash" value={entry.entry_hash} mono multiline />
          </dl>
        </div>
      ) : null}
    </Modal>
  );
}

export default function Audit() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [limit, setLimit] = useState(50);
  const [query, setQuery] = useState('');
  const [eventFilter, setEventFilter] = useState('all');
  const [outcomeFilter, setOutcomeFilter] = useState('all');
  const [selectedEntry, setSelectedEntry] = useState(null);

  const handleLimitChange = (value) => {
    setLoading(true);
    setLimit(parseInt(value, 10));
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

  const eventOptions = useMemo(() => {
    const values = new Set();
    entries.forEach((entry) => {
      if (entry.event_type) values.add(entry.event_type);
    });
    return Array.from(values).sort((a, b) => a.localeCompare(b));
  }, [entries]);

  const filteredEntries = useMemo(() => {
    const needle = normalize(query.trim());
    return entries.filter((entry) => {
      if (eventFilter !== 'all' && entry.event_type !== eventFilter) return false;
      if (outcomeFilter !== 'all' && entryOutcome(entry) !== outcomeFilter) return false;
      if (!needle) return true;
      return [
        entry.id,
        entry.event_type,
        entry.user_id,
        entry.username,
        entry.source_ip,
        entry.resource,
        entry.decision,
        entry.details,
        entry.tenant_id,
      ].some((value) => normalize(value).includes(needle));
    });
  }, [entries, query, eventFilter, outcomeFilter]);

  const hasFilters = query.trim() || eventFilter !== 'all' || outcomeFilter !== 'all';

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

      <ListToolbar
        query={query}
        onQueryChange={setQuery}
        placeholder="Search event, user, resource, IP, or details"
        summary={`${filteredEntries.length} of ${entries.length}`}
      >
        <ListToolbarSelect value={eventFilter} onChange={setEventFilter} className="sm:w-[190px]">
          <option value="all">All events</option>
          {eventOptions.map((eventType) => (
            <option key={eventType} value={eventType}>{eventType}</option>
          ))}
        </ListToolbarSelect>
        <ListToolbarSelect value={outcomeFilter} onChange={setOutcomeFilter} className="sm:w-[170px]">
          <option value="all">All outcomes</option>
          <option value="allowed">Allowed</option>
          <option value="denied">Denied</option>
          <option value="step_up">Step-up</option>
          <option value="success">Success</option>
          <option value="failed">Failed</option>
        </ListToolbarSelect>
        <ListToolbarSelect value={limit} onChange={handleLimitChange} className="sm:w-[150px]">
          <option value={25}>Last 25</option>
          <option value={50}>Last 50</option>
          <option value={100}>Last 100</option>
          <option value={500}>Last 500</option>
        </ListToolbarSelect>
      </ListToolbar>

      <DataTable
        columns={columns}
        data={filteredEntries}
        loading={loading}
        emptyIcon={FileText}
        emptyTitle={hasFilters ? 'No audit entries match filters' : 'No audit entries found'}
        emptyMessage={hasFilters ? 'Adjust search or filters to find audit events.' : ''}
        onRowClick={setSelectedEntry}
      />

      <AuditDetailsModal
        entry={selectedEntry}
        onClose={() => setSelectedEntry(null)}
        eventBadgeVariant={eventBadgeVariant}
      />
    </>
  );
}
