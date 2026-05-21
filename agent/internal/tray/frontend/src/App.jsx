import { useCallback, useEffect, useState } from 'react';
import {
  GetDashboard,
  HideWindow,
  LogoutUserSession,
  StartEnrollmentInteractive,
  StartUserLoginInteractive,
} from '../wailsjs/go/tray/GUIApp';
import { BrowserOpenURL, EventsOn } from '../wailsjs/runtime/runtime';
import AppLayout from './components/AppLayout';
import {
  fallbackDashboard,
  isWailsRuntimeReady,
} from './lib/dashboard';

function App() {
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [enrollmentLoading, setEnrollmentLoading] = useState(false);
  const [enrollmentError, setEnrollmentError] = useState('');
  const [loginLoading, setLoginLoading] = useState(false);
  const [loginError, setLoginError] = useState('');

  const loadDashboard = useCallback(async () => {
    if (!isWailsRuntimeReady()) {
      setDashboard(fallbackDashboard);
      setLoading(false);
      setError('');
      return;
    }

    try {
      const nextDashboard = await GetDashboard();
      setDashboard(nextDashboard);
      setError('');
    } catch (err) {
      setError(err?.message || 'Agent dashboard is unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();

    if (!window?.runtime?.EventsOn) {
      return undefined;
    }

    const unsubscribe = EventsOn('dashboard:updated', loadDashboard);
    return () => {
      if (typeof unsubscribe === 'function') {
        unsubscribe();
      }
    };
  }, [loadDashboard]);

  const handleHide = () => {
    if (window?.go?.tray?.GUIApp?.HideWindow) {
      HideWindow();
    }
  };

  const handleStartEnrollment = async () => {
    setEnrollmentLoading(true);
    setEnrollmentError('');
    try {
      const response = await StartEnrollmentInteractive();
      if (response?.auth_url && response.auth_url.startsWith('https://')) {
        BrowserOpenURL(response.auth_url);
      }
      await loadDashboard();
    } catch (err) {
      setEnrollmentError(err?.message || 'Enrollment could not be started');
    } finally {
      setEnrollmentLoading(false);
    }
  };

  const handleStartLogin = async () => {
    setLoginLoading(true);
    setLoginError('');
    try {
      const response = await StartUserLoginInteractive();
      if (response?.auth_url && response.auth_url.startsWith('https://')) {
        BrowserOpenURL(response.auth_url);
      }
      await loadDashboard();
    } catch (err) {
      setLoginError(err?.message || 'Login could not be started');
    } finally {
      setLoginLoading(false);
    }
  };

  const handleLogout = async () => {
    setLoginLoading(true);
    setLoginError('');
    try {
      await LogoutUserSession();
      await loadDashboard();
    } catch (err) {
      setLoginError(err?.message || 'Logout failed');
    } finally {
      setLoginLoading(false);
    }
  };

  return (
    <AppLayout
      dashboard={dashboard}
      dashboardError={error}
      dashboardLoading={loading}
      enrollmentError={enrollmentError}
      enrollmentLoading={enrollmentLoading}
      loginError={loginError}
      loginLoading={loginLoading}
      onHide={handleHide}
      onLogout={handleLogout}
      onStartEnrollment={handleStartEnrollment}
      onStartLogin={handleStartLogin}
    />
  );
}

export default App;
