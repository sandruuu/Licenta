import { useEffect, useMemo, useState } from 'react';
import { FileText } from 'lucide-react';
import { getAuditLog } from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable from '../components/ui/DataTable';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import { formatDateTime } from '../utils/format';

function normalize(value) {
  return String(value || '').toLowerCase();
}

const AUDIT_EVENT_META = {
  agent_user_authentication_request: {
    label: 'User authentication request',
    variant: 'info',
  },
  agent_user_authentication_approved: {
    label: 'User authentication approved',
    variant: 'success',
  },
  agent_user_authentication_denied: {
    label: 'User authentication denied',
    variant: 'danger',
  },
  agent_user_session_authenticated: {
    label: 'User authentication approved',
    variant: 'success',
  },
  enrollment_requested: {
    label: 'Device enrollment request',
    variant: 'info',
  },
  enrollment_approved: {
    label: 'Device enrollment approved',
    variant: 'success',
  },
  enrollment_revoked: {
    label: 'Device enrollment revoked',
    variant: 'danger',
  },
  enrollment_expired: {
    label: 'Device enrollment expired',
    variant: 'danger',
  },
  agent_access_request: {
    label: 'Resource access request',
    variant: 'resource',
  },
  agent_step_up_required: {
    label: 'Resource step-up required',
    variant: 'warning',
  },
  agent_step_up_denied: {
    label: 'Resource step-up denied',
    variant: 'danger',
  },
  agent_step_up_completed: {
    label: 'Resource step-up completed',
    variant: 'warning',
  },
  device_data_report: {
    label: 'Device data received',
    variant: 'resource',
  },
};

const AUDIT_EVENT_ALIASES = {
  agent_user_session_authenticated: 'agent_user_authentication_approved',
  agent_step_up_request: 'agent_step_up_required',
};

const HIDDEN_AUDIT_EVENTS = new Set([
  'login',
  'admin_login',
  'admin_mfa_completed',
  'admin_passkey_enrolled',
  'admin_passkey_login',
  'federated_login',
  'session_revoked',
  'continuous_access_revoked',
  'device_enrollment_authenticated',
  'agent_mfa_enrolled',
  'agent_mfa_enrollment_reauth',
  'oidc_authorize',
  'oidc_token_exchange',
  'oidc_token_refresh',
  'token_revoked',
]);

function isHiddenAuditEvent(entry) {
  return HIDDEN_AUDIT_EVENTS.has(entry?.event_type) || HIDDEN_AUDIT_EVENTS.has(canonicalAuditEventType(entry?.event_type));
}

function canonicalAuditEventType(type) {
  return AUDIT_EVENT_ALIASES[type] || type;
}

function auditEventLabel(type) {
  const canonicalType = canonicalAuditEventType(type);
  return AUDIT_EVENT_META[canonicalType]?.label || String(canonicalType || 'event').replaceAll('_', ' ');
}

function entryOutcome(entry) {
  const eventType = canonicalAuditEventType(entry?.event_type);
  if (entry.decision === 'deny') return 'denied';
  if (entry.decision === 'step_up' || entry.decision === 'step_up_required' || entry.decision === 'mfa_required') return 'step_up';
  if (entry.decision === 'allow') return 'allowed';
  if (eventType === 'device_data_report') return entry.success ? 'received' : 'denied';
  if (eventType === 'agent_user_authentication_request' || eventType === 'enrollment_requested') {
    return entry.success ? 'requested' : 'denied';
  }
  return entry.success ? 'allowed' : 'denied';
}

function outcomeLabel(outcome) {
  if (outcome === 'allowed') return 'ALLOWED';
  if (outcome === 'denied') return 'DENIED';
  if (outcome === 'step_up') return 'STEP-UP';
  if (outcome === 'requested') return 'REQUESTED';
  if (outcome === 'received') return 'RECEIVED';
  return String(outcome || '-').replaceAll('_', ' ').toUpperCase();
}

function auditDetailsText(details) {
  const text = String(details || '').trim();
  let cleaned = text;
  if (cleaned.startsWith('User authenticated for TrustAgent session via')) cleaned = 'User authenticated via organization sign-in';
  if (cleaned.startsWith('Resource step-up requested')) cleaned = 'Additional verification required for resource access';
  if (cleaned.startsWith('Device enrollment requested:')) cleaned = 'Device enrollment requested';
  if (cleaned.startsWith('Device enrollment expired:')) cleaned = 'Device enrollment expired';
  if (cleaned.startsWith('Approved device')) cleaned = 'Device enrollment approved';
  if (cleaned.startsWith('Revoked device')) cleaned = 'Device enrollment revoked';
  if (cleaned === 'Raw device data reported') cleaned = 'Device data received';

  return cleaned
    .replace(/\bvia\s+https?:\/\/\S+/gi, 'via organization sign-in')
    .replace(/https?:\/\/\S+/gi, 'organization sign-in')
    .replaceAll('PDP ', '')
    .replaceAll(' PDP', '')
    .replaceAll('PDP', '')
    .replaceAll('TOTP', 'Authenticator app')
    .replaceAll('Auth app', 'Authenticator app')
    .replaceAll('WebAuthn', 'Passkey')
    .replaceAll('Federated authentication', 'Organization sign-in')
    .replaceAll('Federated identity', 'Organization sign-in identity')
    .replaceAll('Federated user', 'Organization user')
    .replace(/external idp/gi, 'organization sign-in')
    .replace(/idp/gi, 'organization sign-in')
    .replace(/\s+/g, ' ')
    .trim() || '-';
}

function outcomeTextVariant(outcome) {
  if (outcome === 'allowed') return 'success';
  if (outcome === 'denied') return 'danger';
  if (outcome === 'step_up') return 'warning';
  if (outcome === 'requested' || outcome === 'received') return 'info';
  return 'neutral';
}

function auditTextClass(variant) {
  if (variant === 'success') return 'text-[#638f67]';
  if (variant === 'warning') return 'text-[#c7a23a]';
  if (variant === 'danger') return 'text-[#b46a62]';
  if (variant === 'info') return 'text-info';
  if (variant === 'accent' || variant === 'resource') return 'text-[var(--color-accent)]';
  return 'text-text-muted';
}

function AuditText({ variant = 'neutral', children }) {
  return <span className={`inline-block text-xs font-bold uppercase leading-5 ${auditTextClass(variant)}`}>{children}</span>;
}

export default function Audit() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [limit, setLimit] = useState(50);
  const [query, setQuery] = useState('');
  const [eventFilter, setEventFilter] = useState('all');
  const [outcomeFilter, setOutcomeFilter] = useState('all');

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

  const eventTextVariant = (type) => {
    const canonicalType = canonicalAuditEventType(type);
    if (AUDIT_EVENT_META[canonicalType]?.variant) return AUDIT_EVENT_META[canonicalType].variant;
    if (!type) return 'neutral';
    if (type.includes('login')) return 'info';
    if (type.includes('mfa')) return 'warning';
    if (type.includes('access')) return 'accent';
    return 'neutral';
  };

  const eventOptions = useMemo(() => {
    const values = new Set();
    entries.filter((entry) => !isHiddenAuditEvent(entry)).forEach((entry) => {
      if (entry.event_type) values.add(canonicalAuditEventType(entry.event_type));
    });
    return Array.from(values).sort((a, b) => a.localeCompare(b));
  }, [entries]);

  const visibleEntries = useMemo(
    () => entries.filter((entry) => !isHiddenAuditEvent(entry)),
    [entries]
  );

  const activeEventFilter = eventFilter === 'all' || eventOptions.includes(eventFilter) ? eventFilter : 'all';

  const filteredEntries = useMemo(() => {
    const needle = normalize(query.trim());
    return visibleEntries.filter((entry) => {
      if (activeEventFilter !== 'all' && canonicalAuditEventType(entry.event_type) !== activeEventFilter) return false;
      if (outcomeFilter !== 'all' && entryOutcome(entry) !== outcomeFilter) return false;
      if (!needle) return true;
      return [
        entry.id,
        entry.event_type,
        auditEventLabel(entry.event_type),
        entry.user_id,
        entry.username,
        entry.source_ip,
        entry.resource,
        entry.decision,
        outcomeLabel(entryOutcome(entry)),
        auditDetailsText(entry.details),
        entry.organization_id,
      ].some((value) => normalize(value).includes(needle));
    });
  }, [visibleEntries, query, activeEventFilter, outcomeFilter]);

  const hasFilters = query.trim() || activeEventFilter !== 'all' || outcomeFilter !== 'all';

  const columns = [
    { key: 'timestamp', label: 'Time', render: (v) => <span className="text-mono text-xs whitespace-nowrap">{formatDateTime(v)}</span> },
    { key: 'event_type', label: 'Event', render: (v) => <AuditText variant={eventTextVariant(v)}>{auditEventLabel(v)}</AuditText> },
    { key: 'username', label: 'User', render: (v) => <span>{v || '-'}</span> },
    { key: 'source_ip', label: 'Source IP', render: (v) => <span className="text-mono text-xs">{v || '-'}</span> },
    { key: 'resource', label: 'Resource', render: (v) => <span className="text-xs">{v || '-'}</span> },
    { key: 'decision', label: 'Decision', render: (_, row) => {
      const outcome = entryOutcome(row);
      return <AuditText variant={outcomeTextVariant(outcome)}>{outcomeLabel(outcome)}</AuditText>;
    }},
    { key: 'details', label: 'Details', render: (v) => <span className="mx-auto block max-w-[280px] text-center text-xs leading-5 text-text-muted line-clamp-3">{auditDetailsText(v)}</span> },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <PageHeader title="Audit events" subtitle="Security events and access decisions" />

      <ListToolbar
        query={query}
        onQueryChange={setQuery}
        placeholder="Search event, user, resource, IP, or details"
        summary={`${filteredEntries.length} of ${visibleEntries.length}`}
      >
        <ListToolbarSelect value={activeEventFilter} onChange={setEventFilter} className="sm:w-[190px]">
          <option value="all">All events</option>
          {eventOptions.map((eventType) => (
            <option key={eventType} value={eventType}>{auditEventLabel(eventType)}</option>
          ))}
        </ListToolbarSelect>
        <ListToolbarSelect value={outcomeFilter} onChange={setOutcomeFilter} className="sm:w-[170px]">
          <option value="all">All decisions</option>
          <option value="allowed">Allowed</option>
          <option value="denied">Denied</option>
          <option value="step_up">Step-up</option>
          <option value="requested">Requested</option>
          <option value="received">Received</option>
        </ListToolbarSelect>
        <ListToolbarSelect value={limit} onChange={handleLimitChange} className="sm:w-[150px]">
          <option value={25}>Last 25</option>
          <option value={50}>Last 50</option>
          <option value={100}>Last 100</option>
          <option value={500}>Last 500</option>
        </ListToolbarSelect>
      </ListToolbar>

      <div className="min-h-0 flex-1">
        <DataTable
          columns={columns}
          data={filteredEntries}
          loading={loading}
          emptyIcon={FileText}
          emptyTitle={hasFilters ? 'No audit events match filters' : 'No audit events found'}
          emptyMessage={hasFilters ? 'Adjust search or filters to find audit events.' : ''}
          fillHeight
        />
      </div>
    </div>
  );
}
