import { useEffect, useMemo, useState } from 'react';
import { FileText } from 'lucide-react';
import { getAuditLog, getGateways, getResources } from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable from '../components/ui/DataTable';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import { displayResourceReference } from '../utils/displayNames';
import { formatDateTime } from '../utils/format';

function normalize(value) {
  return String(value || '').toLowerCase();
}

function isInternalIPv4(value) {
  const parts = String(value || '').trim().split('.');
  if (parts.length !== 4) return false;
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet, index) => !Number.isInteger(octet) || String(octet) !== parts[index] || octet < 0 || octet > 255)) {
    return false;
  }
  const [first, second] = octets;
  return (
    first === 10 ||
    first === 127 ||
    first === 0 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}

function isInternalIP(value) {
  const ip = String(value || '').trim().toLowerCase();
  if (!ip) return false;
  if (isInternalIPv4(ip)) return true;
  return ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80:');
}

function auditSourceIPText(value) {
  const ip = String(value || '').trim();
  if (!ip || isInternalIP(ip)) return '-';
  return ip;
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
  agent_resource_access_granted: {
    label: 'Resource access granted',
    variant: 'success',
  },
  agent_resource_access_disconnected: {
    label: 'Resource session ended',
    variant: 'warning',
  },
  agent_resource_session_ended: {
    label: 'Resource session ended',
    variant: 'warning',
  },
  agent_resource_session_revoked: {
    label: 'Resource session revoked',
    variant: 'danger',
  },
  agent_resource_session_expired: {
    label: 'Resource session expired',
    variant: 'warning',
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
  if (eventType === 'agent_resource_access_disconnected' || eventType === 'agent_resource_session_ended') return 'ended';
  if (eventType === 'agent_resource_session_revoked') return 'revoked';
  if (eventType === 'agent_resource_session_expired') return 'expired';
  if (entry.decision === 'deny') return 'denied';
  if (entry.decision === 'revoked') return 'revoked';
  if (entry.decision === 'expired') return 'expired';
  if (entry.decision === 'ended') return 'ended';
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
  if (outcome === 'ended') return 'ENDED';
  if (outcome === 'revoked') return 'REVOKED';
  if (outcome === 'expired') return 'EXPIRED';
  if (outcome === 'requested') return 'REQUESTED';
  if (outcome === 'received') return 'RECEIVED';
  return String(outcome || '-').replaceAll('_', ' ').toUpperCase();
}

const TECHNICAL_DETAIL_FIELD_PATTERN = /\b(request_id|session_id|agent_session_id|challenge_id|gateway_id|resource_id|device_id|user_id|organization_id)=[^\s]+/gi;

function auditRiskReasonLabel(reason) {
  const normalized = String(reason || '').trim().toLowerCase();
  if (normalized === 'impossible_travel' || normalized === 'unrealistic_travel') return 'Additional verification required because impossible travel was detected';
  if (normalized === 'new_location') return 'Additional verification required because a new location was detected';
  if (normalized === 'user_baseline_anomaly' || normalized === 'baseline_anomaly' || normalized === 'user_baseline') {
    return "Additional verification required because the access pattern differs from the user's baseline";
  }
  if (normalized === 'new_device') return 'Additional verification required because a new device was detected';
  if (normalized === 'device_non_compliant' || normalized === 'non_compliant_device' || normalized === 'not_compliant_device') {
    return 'Additional verification required because the device does not satisfy posture requirements';
  }
  return '';
}

function auditDetailsText(details) {
  const text = String(details || '').trim();
  let cleaned = text;
  if (cleaned.startsWith('User authenticated for TrustAgent session via')) cleaned = 'User authenticated via organization sign-in';
  if (cleaned.startsWith('Resource step-up requested')) cleaned = 'Additional verification required for resource access';
  if (cleaned.startsWith('Resource access disconnected after user sign-out')) cleaned = 'Resource session ended after user sign-out';
  if (cleaned.startsWith('Resource access disconnected after policy update')) cleaned = 'Resource session revoked after policy update';
  if (cleaned.startsWith('Resource access disconnected because the device was revoked')) cleaned = 'Resource session revoked because the device was revoked';
  if (cleaned.startsWith('Resource access disconnected because the resource was disabled')) cleaned = 'Resource session revoked because the resource is no longer available';
  if (cleaned.startsWith('Resource access disconnected because the gateway was revoked')) cleaned = 'Resource session revoked because the gateway is no longer available';
  if (cleaned.startsWith('Resource access disconnected after device posture changed')) cleaned = 'Resource session revoked after device posture changed';
  if (cleaned.startsWith('Resource session revoked because source IP changed')) cleaned = 'Resource session revoked because source IP changed';
  if (cleaned === 'Resource access disconnected') cleaned = 'Resource session ended';
  if (cleaned.startsWith('Step-up verification required by')) cleaned = 'Additional verification required for resource access';
  if (cleaned.startsWith('Step-up verification already satisfies')) cleaned = 'Resource access allowed because additional verification is still valid for this context';
  if (cleaned.startsWith('Allowed by')) cleaned = 'Resource access allowed by access policy';
  if (cleaned.startsWith('No matching access rule')) cleaned = 'Resource access denied because no matching access policy was found';
  if (cleaned.startsWith('Device health requirements failed')) cleaned = 'Resource access denied because device posture does not satisfy policy';
  if (cleaned.startsWith('Device enrollment requested:')) cleaned = 'Device enrollment requested';
  if (cleaned.startsWith('Device enrollment expired:')) cleaned = 'Device enrollment expired';
  if (cleaned.startsWith('Approved device')) cleaned = 'Device enrollment approved';
  if (cleaned.startsWith('Revoked device')) cleaned = 'Device enrollment revoked';
  if (cleaned === 'Raw device data reported') cleaned = 'Device data received';
  const riskReason = cleaned.match(/\breason=([^\s]+)/i)?.[1];
  const riskReasonText = auditRiskReasonLabel(riskReason);
  if (riskReasonText) cleaned = riskReasonText;

  return cleaned
    .replace(TECHNICAL_DETAIL_FIELD_PATTERN, '')
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
  if (outcome === 'ended') return 'warning';
  if (outcome === 'revoked') return 'danger';
  if (outcome === 'expired') return 'warning';
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
  const [resources, setResources] = useState([]);
  const [gateways, setGateways] = useState([]);
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
    Promise.all([
      getAuditLog(limit),
      getResources().catch(() => []),
      getGateways().catch(() => []),
    ])
      .then(([auditData, resourceData, gatewayData]) => {
        if (!cancelled) {
          setEntries(Array.isArray(auditData) ? auditData : []);
          setResources(Array.isArray(resourceData) ? resourceData : []);
          setGateways(Array.isArray(gatewayData) ? gatewayData : []);
        }
      })
      .catch(console.error)
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [limit]);

  const resourcesByID = useMemo(() => new Map(resources.map((resource) => [resource.id, resource])), [resources]);
  const gatewaysByID = useMemo(() => new Map(gateways.map((gateway) => [gateway.id, gateway])), [gateways]);
  const auditResourceLabel = (entry) => displayResourceReference(entry?.resource, resourcesByID, gatewaysByID);

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
        auditSourceIPText(entry.source_ip),
        auditResourceLabel(entry),
        entry.decision,
        outcomeLabel(entryOutcome(entry)),
        auditDetailsText(entry.details),
        entry.organization_id,
      ].some((value) => normalize(value).includes(needle));
    }).sort((a, b) => {
      const bTime = new Date(b.timestamp || 0).getTime();
      const aTime = new Date(a.timestamp || 0).getTime();
      if (bTime !== aTime) return bTime - aTime;
      return String(b.id || '').localeCompare(String(a.id || ''));
    });
  }, [visibleEntries, query, activeEventFilter, outcomeFilter, resourcesByID, gatewaysByID]);

  const hasFilters = query.trim() || activeEventFilter !== 'all' || outcomeFilter !== 'all';

  const columns = [
    { key: 'timestamp', label: 'Time', render: (v) => <span className="text-mono text-xs whitespace-nowrap">{formatDateTime(v)}</span> },
    { key: 'event_type', label: 'Event', render: (v) => <AuditText variant={eventTextVariant(v)}>{auditEventLabel(v)}</AuditText> },
    { key: 'username', label: 'User', render: (v) => <span>{v || '-'}</span> },
    { key: 'source_ip', label: 'Source IP', render: (v) => <span className="text-mono text-xs">{auditSourceIPText(v)}</span> },
    { key: 'resource', label: 'Resource', render: (_, row) => <span className="text-xs">{auditResourceLabel(row)}</span> },
    { key: 'decision', label: 'Decision', render: (_, row) => {
      const outcome = entryOutcome(row);
      return <AuditText variant={outcomeTextVariant(outcome)}>{outcomeLabel(outcome)}</AuditText>;
    }},
    { key: 'details', label: 'Details', render: (v) => <span className="mx-auto block max-w-[280px] text-center text-xs leading-5 text-text-muted line-clamp-3">{auditDetailsText(v)}</span> },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <PageHeader
        title="Audit events"
        subtitle="Security events and access decisions"
      />

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
          <option value="ended">Ended</option>
          <option value="revoked">Revoked</option>
          <option value="expired">Expired</option>
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
