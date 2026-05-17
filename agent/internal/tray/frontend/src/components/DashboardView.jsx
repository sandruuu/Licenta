import { formatTime } from '../lib/dashboard';
import AccessList from './AccessList';
import HealthCard from './HealthCard';
import { KeyValue, Panel } from './Panels';
import ResourceTable from './ResourceTable';
import SessionList from './SessionList';

function DashboardView({ activeView, dashboard }) {
  return (
    <section className="min-h-0 flex-1 overflow-auto pt-4">
      <div className="grid min-h-0 grid-cols-12 gap-3 pb-1">
        {renderActiveView(activeView, dashboard)}
      </div>
    </section>
  );
}

function renderActiveView(activeView, dashboard) {
  const enrollmentPanel = (
    <Panel title="Enrollment" className={activeView === 'overview' ? 'col-span-4 max-[980px]:col-span-12' : 'col-span-6 max-[980px]:col-span-12'} key="enrollment">
      <KeyValue label="Device ID" value={dashboard.enrollment?.device_id} />
      <KeyValue label="Device ID Source" value={dashboard.enrollment?.device_id_source} />
      <KeyValue label="Key Name" value={dashboard.enrollment?.key_name} />
      <KeyValue label="Key Provider" value={dashboard.enrollment?.key_provider} />
      <KeyValue label="Key Exists" value={dashboard.enrollment?.key_exists ? 'Yes' : 'No'} />
    </Panel>
  );

  const certificatePanel = (
    <Panel title="Certificate" className={activeView === 'overview' ? 'col-span-4 max-[980px]:col-span-12' : 'col-span-6 max-[980px]:col-span-12'} key="certificate">
      <KeyValue label="Fingerprint" value={dashboard.certificate?.sha256} />
      <KeyValue label="Subject" value={dashboard.certificate?.subject} />
      <KeyValue label="Issuer" value={dashboard.certificate?.issuer} />
      <KeyValue label="Expires" value={formatTime(dashboard.certificate?.expires_at)} />
      <KeyValue label="Valid" value={dashboard.certificate?.valid ? 'Yes' : 'No'} />
    </Panel>
  );

  const userPanel = (
    <Panel title="User" className={activeView === 'overview' ? 'col-span-4 max-[980px]:col-span-12' : 'col-span-12'} key="user">
      <KeyValue label="Identity" value={dashboard.user?.email || dashboard.user?.user_sid} />
      <KeyValue label="User SID" value={dashboard.user?.user_sid} />
      <KeyValue label="Authorized SID" value={dashboard.user?.authorized_user_sid} />
      <KeyValue label="Token Expires" value={formatTime(dashboard.user?.access_token_expires_at)} />
    </Panel>
  );

  const posturePanel = (
    <Panel title="Device Security" className={activeView === 'overview' ? 'col-span-6 max-[980px]:col-span-12' : 'col-span-12'} key="security">
      <div className="flex flex-col gap-2">
        {(dashboard.posture?.checks || []).map((check, index) => (
          <HealthCard key={`${check.name}-${index}`} check={check} />
        ))}
      </div>
    </Panel>
  );

  const resourcesPanel = (
    <Panel title="Resources" className={activeView === 'overview' ? 'col-span-6 max-[980px]:col-span-12' : 'col-span-12'} key="resources">
      <ResourceTable resources={dashboard.resources || []} />
    </Panel>
  );

  const sessionsPanel = (
    <Panel title="Active Sessions" className={activeView === 'overview' ? 'col-span-6 max-[980px]:col-span-12' : 'col-span-12'} key="sessions">
      <SessionList sessions={dashboard.active_sessions || []} />
    </Panel>
  );

  const accessPanel = (
    <Panel title="Access Messages" className={activeView === 'overview' ? 'col-span-6 max-[980px]:col-span-12' : 'col-span-12'} key="access">
      <AccessList events={dashboard.access_events || []} />
    </Panel>
  );

  if (activeView === 'enrollment') return [enrollmentPanel, certificatePanel, userPanel];
  if (activeView === 'security') return posturePanel;
  if (activeView === 'resources') return resourcesPanel;
  if (activeView === 'sessions') return sessionsPanel;
  if (activeView === 'access') return accessPanel;
  return [enrollmentPanel, certificatePanel, userPanel, posturePanel, resourcesPanel, sessionsPanel, accessPanel];
}

export default DashboardView;
