import { useEffect, useState } from 'react';
import { GetDashboard, HideWindow, StartEnrollment } from '../wailsjs/go/tray/GUIApp';
import { EventsOn } from '../wailsjs/runtime/runtime';
import AppLayout from './components/AppLayout';
import { EnrollmentBanner, ServiceInstallBanner } from './components/Banners';
import DashboardView from './components/DashboardView';
import LoadingShell from './components/LoadingShell';
import {
  emptyDashboard,
  normalizeDashboard,
} from './lib/dashboard';

function App() {
  const [dashboard, setDashboard] = useState(emptyDashboard);
  const [activeView, setActiveView] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [enrollingDevice, setEnrollingDevice] = useState(false);
  const [enrollmentNotice, setEnrollmentNotice] = useState({ tone: '', message: '' });
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

  const postureStatus = dashboard.status?.device_posture_status || dashboard.posture?.checks?.[0]?.status || 'unavailable';
  const postureTone = postureStatus === 'critical'
    ? 'danger'
    : postureStatus === 'warning' || postureStatus === 'unavailable'
      ? 'warning'
      : 'success';
  const serviceUnavailable = dashboard.status?.service_state === 'unavailable' || dashboard.connection?.service_state === 'unavailable';
  const enrollmentState = dashboard.enrollment?.state || dashboard.status?.enrollment_state || 'UNKNOWN';
  const enrollmentRequired = !serviceUnavailable && ['UNENROLLED', 'PENDING', 'FAILED'].includes(enrollmentState);
  const enrollmentCanStart = !serviceUnavailable && ['UNENROLLED', 'PENDING', 'FAILED'].includes(enrollmentState);

  const startEnrollment = async () => {
    setEnrollingDevice(true);
    setEnrollmentNotice({ tone: 'info', message: 'Opening browser sign-in' });
    setLastError('');
    try {
      const result = await StartEnrollment();
      setEnrollmentNotice({ tone: 'success', message: result?.message || 'Enrollment flow completed' });
      await refresh(false);
    } catch (error) {
      setEnrollmentNotice({ tone: 'danger', message: error?.message || String(error) });
    } finally {
      setEnrollingDevice(false);
    }
  };

  if (loading) {
    return <LoadingShell />;
  }

  return (
    <AppLayout
      activeView={activeView}
      dashboard={dashboard}
      lastError={lastError}
      postureSummary={{ label: postureStatus, tone: postureTone }}
      refreshing={refreshing}
      onNavigate={setActiveView}
      onRefresh={() => refresh(true)}
      onHide={() => HideWindow()}
      banners={(
        <>
          {serviceUnavailable && <ServiceInstallBanner />}

          {enrollmentRequired && (
            <EnrollmentBanner
              state={enrollmentState}
              enrolling={enrollingDevice}
              onStartEnrollment={startEnrollment}
              canStart={enrollmentCanStart}
              notice={enrollmentNotice}
              lastError={dashboard.enrollment?.last_error || dashboard.status?.last_error}
            />
          )}
        </>
      )}
    >
      <DashboardView activeView={activeView} dashboard={dashboard} />
    </AppLayout>
  );
}

export default App;
