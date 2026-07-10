import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import {
  clearToken,
  getSessionRefreshDelay,
  getToken,
  logoutAdminSession,
  refreshAdminSession,
  validateAdminSession,
} from './api';
import Layout from './components/Layout';
import LoadingSpinner from './components/ui/LoadingSpinner';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Organizations from './pages/Organizations';
import OrganizationDetail from './pages/OrganizationDetail';
import IdPDetail from './pages/IdPDetail';
import Resources from './pages/Resources';
import ResourceDetail from './pages/ResourceDetail';
import Policies from './pages/Policies';
import Sessions from './pages/Sessions';
import Audit from './pages/Audit';
import DeviceHealth from './pages/DeviceHealth';
import Gateways from './pages/Gateways';
import GatewayDetail from './pages/GatewayDetail';

const DASHBOARD_IDLE_TIMEOUT_MS = 30 * 60 * 1000;

function SessionLoading() {
  return (
    <div className="grid min-h-screen place-items-center bg-surface" role="status" aria-live="polite" aria-label="Loading">
      <LoadingSpinner size="lg" />
    </div>
  );
}

function PrivateRoute({ children }) {
  const [status, setStatus] = useState('checking');

  useEffect(() => {
    let cancelled = false;
    let refreshTimer = null;
    let lastActivity = Date.now();

    function clearRefreshTimer() {
      if (refreshTimer) {
        window.clearTimeout(refreshTimer);
        refreshTimer = null;
      }
    }

    function recordActivity() {
      lastActivity = Date.now();
    }

    function scheduleRefresh() {
      clearRefreshTimer();
      if (cancelled || !getToken()) return;
      refreshTimer = window.setTimeout(() => {
        void refreshSessionIfActive();
      }, getSessionRefreshDelay());
    }

    async function refreshSessionIfActive() {
      if (Date.now() - lastActivity > DASHBOARD_IDLE_TIMEOUT_MS) {
        await logoutAdminSession();
        if (!cancelled) setStatus('guest');
        return;
      }
      try {
        await refreshAdminSession();
        if (!cancelled) {
          setStatus('authenticated');
          scheduleRefresh();
        }
      } catch {
        clearToken();
        clearRefreshTimer();
        if (!cancelled) setStatus('guest');
      }
    }

    async function checkSession(showLoading = true) {
      if (showLoading) setStatus('checking');
      try {
        await validateAdminSession();
        if (!cancelled) {
          setStatus('authenticated');
          scheduleRefresh();
        }
      } catch {
        clearToken();
        clearRefreshTimer();
        if (!cancelled) setStatus('guest');
      }
    }

    const activityEvents = ['pointerdown', 'keydown', 'scroll', 'focus'];
    activityEvents.forEach((eventName) => window.addEventListener(eventName, recordActivity, { passive: true }));
    void checkSession();

    return () => {
      cancelled = true;
      clearRefreshTimer();
      activityEvents.forEach((eventName) => window.removeEventListener(eventName, recordActivity));
    };
  }, []);

  if (status === 'guest') {
    return <Navigate to="/login" replace />;
  }

  if (status === 'checking') {
    return <SessionLoading />;
  }

  return children;
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route index element={<Dashboard />} />
          <Route path="organizations" element={<Organizations />} />
          <Route path="organizations/:organizationId" element={<OrganizationDetail />} />
          <Route path="organizations/:organizationId/idps/:idpId" element={<IdPDetail />} />
          <Route path="resources" element={<Resources />} />
          <Route path="resources/:resourceId" element={<ResourceDetail />} />
          <Route path="policies" element={<Policies />} />
          <Route path="gateways" element={<Gateways />} />
          <Route path="gateways/:gatewayId" element={<GatewayDetail />} />
          <Route path="sessions" element={<Sessions />} />
          <Route path="device-data" element={<DeviceHealth />} />
          <Route path="device-health" element={<Navigate to="/device-data" replace />} />
          <Route path="audit" element={<Audit />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
