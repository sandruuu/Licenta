import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
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

function PrivateRoute({ children }) {
  const token = localStorage.getItem('admin_token');
  if (!token) {
    return <Navigate to="/dashboard/login" replace />;
  }
  return children;
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/dashboard/login" element={<Login />} />
        <Route path="/dashboard" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route index element={<Dashboard />} />
          <Route path="organizations" element={<Organizations />} />
          <Route path="organizations/:organizationId" element={<OrganizationDetail />} />
          <Route path="organizations/:organizationId/idps/:idpId" element={<IdPDetail />} />
          <Route path="tenants" element={<Navigate to="/dashboard/organizations" replace />} />
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
        <Route path="*" element={<Navigate to="/dashboard" />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
