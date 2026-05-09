import { useEffect, useMemo, useState } from 'react';
import { GetDashboard, HideWindow } from '../wailsjs/go/tray/GUIApp';
import { EventsOn } from '../wailsjs/runtime/runtime';
import HealthCard from './components/HealthCard.jsx';

const emptyDashboard = {
  connection: { state: 'disconnected', message: 'Loading Agent status' },
  status: {},
  enrollment: {},
  certificate: {},
  user: {},
  posture: { checks: [] },
  resources: [],
  active_sessions: [],
  access_events: []
};

function App() {
  const [dashboard, setDashboard] = useState(emptyDashboard);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastError, setLastError] = useState('');

  const refresh = async (manual = false) => {
    if (manual) setRefreshing(true);
    try {
      const result = await GetDashboard();
      setDashboard(normalizeDashboard(result));
      setLastError('');
    } catch (error) {
      setLastError(error?.message || String(error));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    refresh(false);
    const unsubscribe = EventsOn('dashboard:updated', () => refresh(false));
    const interval = setInterval(() => refresh(false), 15000);
    return () => {
      unsubscribe();
      clearInterval(interval);
    };
  }, []);

  const statusTone = toneForConnection(dashboard.connection?.state);
  const postureSummary = useMemo(() => summarizePosture(dashboard.posture?.checks || []), [dashboard.posture]);

  if (loading) {
    return (
      <main className="loading-shell">
        <div className="spinner" />
      </main>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="identity-block">
          <span className={`status-dot ${statusTone}`} />
          <div>
            <h1>ZTNA Agent</h1>
            <p>{dashboard.connection?.message || 'Agent state unavailable'}</p>
          </div>
        </div>
        <div className="topbar-actions">
          <button className="icon-button" onClick={() => refresh(true)} disabled={refreshing} title="Refresh">
            <span className={refreshing ? 'spin' : ''}>R</span>
          </button>
          <button className="icon-button" onClick={() => HideWindow()} title="Hide">
            <span>_</span>
          </button>
        </div>
      </header>

      {lastError && <div className="inline-alert">{lastError}</div>}

      <section className="status-strip">
        <Metric label="Agent" value={labelCase(dashboard.connection?.state)} tone={statusTone} />
        <Metric label="Enrollment" value={dashboard.enrollment?.state || 'UNKNOWN'} tone={toneForEnrollment(dashboard.enrollment?.state)} />
        <Metric label="Session" value={dashboard.user?.session_state || dashboard.status?.session_state || 'missing'} tone={toneForSession(dashboard.user?.session_state || dashboard.status?.session_state)} />
        <Metric label="Posture" value={postureSummary.label} tone={postureSummary.tone} />
      </section>

      <main className="dashboard-grid">
        <Panel title="Enrollment" className="span-4">
          <KeyValue label="Device ID" value={dashboard.enrollment?.device_id} />
          <KeyValue label="Device ID Source" value={dashboard.enrollment?.device_id_source} />
          <KeyValue label="Key Name" value={dashboard.enrollment?.key_name} />
          <KeyValue label="Key Provider" value={dashboard.enrollment?.key_provider} />
          <KeyValue label="Key Exists" value={dashboard.enrollment?.key_exists ? 'Yes' : 'No'} />
        </Panel>

        <Panel title="Certificate" className="span-4">
          <KeyValue label="Fingerprint" value={shortHash(dashboard.certificate?.sha256)} />
          <KeyValue label="Subject" value={dashboard.certificate?.subject} />
          <KeyValue label="Issuer" value={dashboard.certificate?.issuer} />
          <KeyValue label="Expires" value={formatTime(dashboard.certificate?.expires_at)} />
          <KeyValue label="Valid" value={dashboard.certificate?.valid ? 'Yes' : 'No'} />
        </Panel>

        <Panel title="User" className="span-4">
          <KeyValue label="Identity" value={dashboard.user?.email || dashboard.user?.user_sid} />
          <KeyValue label="User SID" value={dashboard.user?.user_sid} />
          <KeyValue label="Authorized SID" value={dashboard.user?.authorized_user_sid} />
          <KeyValue label="Token Expires" value={formatTime(dashboard.user?.access_token_expires_at)} />
        </Panel>

        <Panel title="Device Security" className="span-6">
          <div className="posture-list">
            {(dashboard.posture?.checks || []).map((check, index) => (
              <HealthCard key={`${check.name}-${index}`} check={check} />
            ))}
          </div>
        </Panel>

        <Panel title="Resources" className="span-6">
          <ResourceTable resources={dashboard.resources || []} />
        </Panel>

        <Panel title="Active Sessions" className="span-6">
          <SessionList sessions={dashboard.active_sessions || []} />
        </Panel>

        <Panel title="Access Messages" className="span-6">
          <AccessList events={dashboard.access_events || []} />
        </Panel>
      </main>
    </div>
  );
}

function normalizeDashboard(value) {
  return {
    ...emptyDashboard,
    ...value,
    connection: { ...emptyDashboard.connection, ...(value?.connection || {}) },
    status: value?.status || {},
    enrollment: value?.enrollment || {},
    certificate: value?.certificate || {},
    user: value?.user || {},
    posture: value?.posture || { checks: [] },
    resources: value?.resources || [],
    active_sessions: value?.active_sessions || [],
    access_events: value?.access_events || []
  };
}

function Metric({ label, value, tone }) {
  return (
    <div className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>{value || 'Unknown'}</strong>
    </div>
  );
}

function Panel({ title, className = '', children }) {
  return (
    <section className={`panel ${className}`}>
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function KeyValue({ label, value }) {
  return (
    <div className="key-value">
      <span>{label}</span>
      <strong title={value || ''}>{value || 'Unavailable'}</strong>
    </div>
  );
}

function ResourceTable({ resources }) {
  if (!resources.length) return <EmptyState title="No resources available" />;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>FQDN</th>
            <th>Protocol</th>
            <th>Port</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {resources.map((resource) => (
            <tr key={`${resource.resource_id || resource.fqdn}-${resource.port || 0}`}>
              <td>{resource.fqdn}</td>
              <td>{resource.protocol || 'tcp'}</td>
              <td>{resource.port || '-'}</td>
              <td><span className="table-pill">{resource.status || 'available'}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SessionList({ sessions }) {
  if (!sessions.length) return <EmptyState title="No active resource sessions" />;
  return (
    <div className="list-stack">
      {sessions.map((session) => (
        <article className="list-row" key={session.id}>
          <div>
            <strong>{session.fqdn || session.resource_id || session.id}</strong>
            <span>{session.protocol || 'tcp'}:{session.port || '-'}</span>
          </div>
          <span className="table-pill">{session.state}</span>
        </article>
      ))}
    </div>
  );
}

function AccessList({ events }) {
  if (!events.length) return <EmptyState title="No access denials recorded" />;
  return (
    <div className="list-stack">
      {events.map((event) => (
        <article className="access-row" key={event.id}>
          <div className="access-header">
            <strong>{labelCase(event.decision || 'deny')}</strong>
            <span>{formatTime(event.occurred_at)}</span>
          </div>
          <p>{event.reason}</p>
          {event.source && <span className="source-label">{event.source}</span>}
        </article>
      ))}
    </div>
  );
}

function EmptyState({ title }) {
  return <div className="empty-state">{title}</div>;
}

function summarizePosture(checks) {
  if (!checks.length) return { label: 'Unavailable', tone: 'muted' };
  if (checks.some((check) => check.status === 'critical')) return { label: 'Critical', tone: 'danger' };
  if (checks.some((check) => check.status === 'warning' || check.status === 'unavailable')) return { label: 'Warning', tone: 'warning' };
  return { label: 'Good', tone: 'success' };
}

function toneForConnection(state) {
  if (state === 'connected') return 'success';
  if (state === 'unenrolled') return 'warning';
  return 'danger';
}

function toneForEnrollment(state) {
  if (state === 'ENROLLED') return 'success';
  if (state === 'PENDING') return 'warning';
  if (state === 'UNENROLLED') return 'warning';
  return 'danger';
}

function toneForSession(state) {
  if (state === 'ready') return 'success';
  if (state === 'missing' || state === 'expired') return 'warning';
  return 'danger';
}

function formatTime(value) {
  if (!value) return 'Unavailable';
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.getFullYear() <= 1) return 'Unavailable';
  return date.toLocaleString();
}

function shortHash(value) {
  if (!value) return '';
  return value.length > 18 ? `${value.slice(0, 12)}...${value.slice(-6)}` : value;
}

function labelCase(value) {
  if (!value) return 'Unknown';
  return String(value).replaceAll('_', ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

export default App;