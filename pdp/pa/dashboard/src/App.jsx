import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { clearToken, getToken, validateAdminSession } from './api';
import Layout from './components/Layout';
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
import ProtectApp from './pages/ProtectApp';
import Gateways from './pages/Gateways';
import GatewayDetail from './pages/GatewayDetail';

const sessionSpinnerSegments = Array.from({ length: 12 }, (_, index) => index);

function SessionLoading() {
  return (
    <div className="grid min-h-screen place-items-center bg-surface" role="status" aria-live="polite" aria-label="Loading">
      <div className="flex flex-col items-center gap-1.5">
        <div className="session-spinner" aria-hidden="true">
          {sessionSpinnerSegments.map((index) => (
            <span key={index} style={{ '--segment-index': index }} />
          ))}
        </div>
        <span className="text-[10px] font-semibold leading-none text-text-secondary">Loading...</span>
      </div>
    </div>
  );
}

function PrivateRoute({ children }) {
  const [status, setStatus] = useState(() => (getToken() ? 'checking' : 'guest'));

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      if (!getToken()) {
        setStatus('guest');
        return;
      }

      setStatus('checking');
      try {
        await validateAdminSession();
        if (!cancelled) setStatus('authenticated');
      } catch {
        clearToken();
        if (!cancelled) setStatus('guest');
      }
    }

    void checkSession();

    return () => {
      cancelled = true;
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
          <Route path="protect-app" element={<ProtectApp />} />
          <Route path="sessions" element={<Sessions />} />
          <Route path="device-health" element={<DeviceHealth />} />
          <Route path="audit" element={<Audit />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
