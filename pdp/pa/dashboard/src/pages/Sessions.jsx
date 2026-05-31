import { useEffect, useMemo, useState } from 'react';
import { Radio, XCircle } from 'lucide-react';
import { getSessions, revokeSession } from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import { formatDateTime } from '../utils/format';

function normalize(value) {
  return String(value || '').toLowerCase();
}

function riskBand(score) {
  const value = Number(score) || 0;
  if (value > 70) return 'high';
  if (value > 40) return 'medium';
  return 'low';
}

function isExpired(session) {
  return new Date(session.expires_at) < new Date();
}

function getSessionStatus(session) {
  if (session.revoked) return 'revoked';
  if (isExpired(session)) return 'expired';
  return 'active';
}

export default function Sessions() {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');

  const refreshSessions = async () => {
    setLoading(true);
    try {
      const data = await getSessions();
      setSessions(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    getSessions()
      .then((data) => {
        if (active) {
          setSessions(Array.isArray(data) ? data : []);
        }
      })
      .catch(console.error)
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  const handleRevoke = async (id) => {
    if (!confirm('Revoke this session?')) return;
    await revokeSession(id);
    await refreshSessions();
  };

  const protocolOptions = useMemo(() => {
    const values = new Set();
    sessions.forEach((session) => {
      if (session.protocol) values.add(String(session.protocol).toLowerCase());
    });
    return Array.from(values).sort();
  }, [sessions]);

  const filteredSessions = useMemo(() => {
    const needle = normalize(query.trim());
    return sessions.filter((session) => {
      const status = getSessionStatus(session);
      const protocol = normalize(session.protocol);
      if (statusFilter !== 'all' && status !== statusFilter) return false;
      if (protocolFilter !== 'all' && protocol !== protocolFilter) return false;
      if (riskFilter !== 'all' && riskBand(session.risk_score) !== riskFilter) return false;
      if (!needle) return true;
      return [
        session.id,
        session.user_id,
        session.username,
        session.device_id,
        session.source_ip,
        session.resource,
        session.gateway_id,
        session.protocol,
        session.policy_id,
      ].some((value) => normalize(value).includes(needle));
    });
  }, [sessions, query, statusFilter, protocolFilter, riskFilter]);

  const hasFilters = query.trim() || statusFilter !== 'all' || protocolFilter !== 'all' || riskFilter !== 'all';

  const columns = [
    { key: 'username', label: 'User', render: (v) => <span className="font-medium text-text-primary">{v}</span> },
    { key: 'resource', label: 'Resource', render: (v) => <span className="text-mono">{v || '-'}</span> },
    { key: 'source_ip', label: 'Source IP', render: (v) => <span className="text-mono text-xs">{v || '-'}</span> },
    { key: 'risk_score', label: 'Risk', render: (v) => (
      <span className={v > 70 ? 'text-danger' : v > 40 ? 'text-warning' : 'text-success'}>{v}</span>
    )},
    { key: 'status', label: 'Status', render: (_, row) => {
      const status = getSessionStatus(row);
      return <Badge variant={status === 'active' ? 'success' : status === 'revoked' ? 'danger' : 'neutral'}>{status}</Badge>;
    }},
    { key: 'created_at', label: 'Created', render: (v) => <span className="text-mono text-xs">{formatDateTime(v)}</span> },
    { key: 'expires_at', label: 'Expires', render: (v) => <span className="text-mono text-xs">{formatDateTime(v)}</span> },
    { key: 'actions', label: 'Actions', align: 'right', render: (_, row) => {
      const status = getSessionStatus(row);
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

      <ListToolbar
        query={query}
        onQueryChange={setQuery}
        placeholder="Search user, resource, IP, device, or gateway"
        summary={`${filteredSessions.length} of ${sessions.length}`}
      >
        <ListToolbarSelect value={statusFilter} onChange={setStatusFilter}>
          <option value="all">All statuses</option>
          <option value="active">Active</option>
          <option value="expired">Expired</option>
          <option value="revoked">Revoked</option>
        </ListToolbarSelect>
        <ListToolbarSelect value={protocolFilter} onChange={setProtocolFilter}>
          <option value="all">All protocols</option>
          {protocolOptions.map((protocol) => (
            <option key={protocol} value={protocol}>{protocol.toUpperCase()}</option>
          ))}
        </ListToolbarSelect>
        <ListToolbarSelect value={riskFilter} onChange={setRiskFilter}>
          <option value="all">All risk levels</option>
          <option value="low">Low risk</option>
          <option value="medium">Medium risk</option>
          <option value="high">High risk</option>
        </ListToolbarSelect>
      </ListToolbar>

      <DataTable
        columns={columns}
        data={filteredSessions}
        loading={loading}
        emptyIcon={Radio}
        emptyTitle={hasFilters ? 'No sessions match filters' : 'No sessions found'}
        emptyMessage={hasFilters ? 'Adjust search or filters to find sessions.' : ''}
        emptyVariant="plain"
      />
    </>
  );
}
