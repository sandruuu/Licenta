import { useEffect, useMemo, useState } from 'react';
import { Ban, Radio } from 'lucide-react';
import { getGateways, getResources, getSessions, revokeSession } from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable, { TableIconButton } from '../components/ui/DataTable';
import ConfirmDialog from '../components/ui/ConfirmDialog';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import StatusText from '../components/ui/StatusText';
import { displayGatewayName, displayResourceName, displayResourceReference } from '../utils/displayNames';
import { formatDateTime } from '../utils/format';

function normalize(value) {
  return String(value || '').toLowerCase();
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
  const [resources, setResources] = useState([]);
  const [gateways, setGateways] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [revokeTarget, setRevokeTarget] = useState(null);
  const [revokeSaving, setRevokeSaving] = useState(false);

  const refreshSessions = async () => {
    setLoading(true);
    setError('');
    try {
      const [sessionData, resourceData, gatewayData] = await Promise.all([
        getSessions(),
        getResources().catch(() => []),
        getGateways().catch(() => []),
      ]);
      setSessions(Array.isArray(sessionData) ? sessionData : []);
      setResources(Array.isArray(resourceData) ? resourceData : []);
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
    } catch (error) {
      console.error(error);
      setSessions([]);
      setError(error.message || 'Failed to load sessions');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    setError('');
    Promise.all([
      getSessions(),
      getResources().catch(() => []),
      getGateways().catch(() => []),
    ])
      .then(([sessionData, resourceData, gatewayData]) => {
        if (active) {
          setSessions(Array.isArray(sessionData) ? sessionData : []);
          setResources(Array.isArray(resourceData) ? resourceData : []);
          setGateways(Array.isArray(gatewayData) ? gatewayData : []);
        }
      })
      .catch((error) => {
        console.error(error);
        if (active) {
          setSessions([]);
          setError(error.message || 'Failed to load sessions');
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  const resourcesByID = useMemo(() => new Map(resources.map((resource) => [resource.id, resource])), [resources]);
  const gatewaysByID = useMemo(() => new Map(gateways.map((gateway) => [gateway.id, gateway])), [gateways]);

  const sessionResourceLabel = (session) => {
    const resource = resourcesByID.get(session.resource);
    return resource ? displayResourceName(resource) : displayResourceReference(session.resource, resourcesByID, gatewaysByID, 'Resource');
  };

  const sessionGatewayLabel = (session) => {
    const gateway = gatewaysByID.get(session.gateway_id);
    if (gateway) return displayGatewayName(gateway);
    const resource = resourcesByID.get(session.resource);
    if (resource?.gateway_id && gatewaysByID.has(resource.gateway_id)) {
      return displayGatewayName(gatewaysByID.get(resource.gateway_id));
    }
    return 'No gateway';
  };

  const handleRevoke = (session) => {
    setRevokeTarget(session);
  };

  const confirmRevoke = async () => {
    if (!revokeTarget?.id) return;
    setRevokeSaving(true);
    try {
      await revokeSession(revokeTarget.id);
      setRevokeTarget(null);
      await refreshSessions();
    } finally {
      setRevokeSaving(false);
    }
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
      const protocol = normalize(session.protocol);
      if (protocolFilter !== 'all' && protocol !== protocolFilter) return false;
      if (!needle) return true;
      return [
        session.user_id,
        session.username,
        session.device_id,
        session.source_ip,
        sessionResourceLabel(session),
        sessionGatewayLabel(session),
        session.protocol,
        session.policy_id,
      ].some((value) => normalize(value).includes(needle));
    });
  }, [sessions, query, protocolFilter, resourcesByID, gatewaysByID]);

  const hasFilters = query.trim() || protocolFilter !== 'all';
  const emptyTitle = error
    ? 'Sessions unavailable'
    : hasFilters
      ? 'No sessions match filters'
      : 'No active sessions';
  const emptyMessage = error
    ? error
    : hasFilters
      ? 'Adjust search or filters to find sessions.'
      : 'There are no current access sessions.';

  const columns = [
    {
      key: 'username',
      label: 'User',
      align: 'left',
      width: 'minmax(230px, 1.2fr)',
      cellClassName: '!justify-start !text-left',
      render: (_, row) => (
        <div className="min-w-0">
          <p className="truncate text-sm font-bold text-text-primary">{row.username || row.user_id || '-'}</p>
          <p className="mt-1 truncate text-xs font-semibold text-text-muted">{row.device_id || row.user_id || 'No device'}</p>
        </div>
      ),
    },
    {
      key: 'resource',
      label: 'Resource',
      align: 'left',
      width: 'minmax(210px, 1.05fr)',
      cellClassName: '!justify-start !text-left',
      render: (_, row) => (
        <div className="min-w-0">
          <p className="truncate font-bold text-text-primary">{sessionResourceLabel(row)}</p>
          <p className="mt-1 truncate text-xs font-semibold text-text-muted">
            {[row.protocol && String(row.protocol).toUpperCase(), sessionGatewayLabel(row)].filter(Boolean).join(' / ')}
          </p>
        </div>
      ),
    },
    {
      key: 'source_ip',
      label: 'Source IP',
      align: 'left',
      width: 'minmax(140px, 0.72fr)',
      cellClassName: '!justify-start !text-left',
      render: (v) => <span className="truncate text-mono text-xs text-text-primary">{v || '-'}</span>,
    },
    { key: 'status', label: 'Status', render: (_, row) => {
      const status = getSessionStatus(row);
      return <StatusText variant={status === 'active' ? 'success' : status === 'revoked' ? 'danger' : 'neutral'}>{status}</StatusText>;
    }},
    {
      key: 'created_at',
      label: 'Created',
      align: 'left',
      width: 'minmax(190px, 0.85fr)',
      cellClassName: '!justify-start !text-left',
      render: (value) => <span className="truncate text-mono text-xs text-text-primary">{formatDateTime(value)}</span>,
    },
    { key: 'actions', label: 'Actions', align: 'right', render: (_, row) => {
      const status = getSessionStatus(row);
      return status === 'active' ? (
        <TableIconButton icon={Ban} label="Revoke session" danger onClick={() => handleRevoke(row)} />
      ) : null;
    }},
  ];

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <PageHeader title="Active sessions" subtitle="Active access sessions" />

      <ListToolbar
        query={query}
        onQueryChange={setQuery}
        placeholder="Search user, resource, IP, device, or gateway"
        summary={`${filteredSessions.length} of ${sessions.length}`}
      >
        <ListToolbarSelect value={protocolFilter} onChange={setProtocolFilter}>
          <option value="all">All protocols</option>
          {protocolOptions.map((protocol) => (
            <option key={protocol} value={protocol}>{protocol.toUpperCase()}</option>
          ))}
        </ListToolbarSelect>
      </ListToolbar>

      <div className="min-h-0 flex-1">
        <DataTable
          columns={columns}
          data={filteredSessions}
          loading={loading}
          emptyIcon={Radio}
          emptyTitle={emptyTitle}
          emptyMessage={emptyMessage}
          emptyVariant="card"
          fillHeight
        />
      </div>

      <ConfirmDialog
        open={!!revokeTarget}
        onClose={() => !revokeSaving && setRevokeTarget(null)}
        onConfirm={confirmRevoke}
        title="Revoke Session"
        message={`Revoke access for ${revokeTarget?.username || revokeTarget?.user_id || 'this user'} to ${revokeTarget ? sessionResourceLabel(revokeTarget) : 'this resource'}?`}
        confirmLabel="Revoke"
        confirmVariant="danger"
        loadingLabel="Revoking..."
        loading={revokeSaving}
      />
    </div>
  );
}
