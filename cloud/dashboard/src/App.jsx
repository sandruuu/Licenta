import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Resources from './pages/Resources';
import Policies from './pages/Policies';
import Users from './pages/Users';
import Sessions from './pages/Sessions';
import Audit from './pages/Audit';
import DeviceHealth from './pages/DeviceHealth';
import ProtectApp from './pages/ProtectApp';
import Gateways from './pages/Gateways';
import './App.css';

function PrivateRoute({ children }) {
  const token = localStorage.getItem('admin_token');
  return token ? children : <Navigate to="/dashboard/login" />;
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/dashboard/login" element={<Login />} />
        <Route path="/dashboard" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route index element={<Dashboard />} />
          <Route path="resources" element={<Resources />} />
          <Route path="gateways" element={<Gateways />} />
          <Route path="protect-app" element={<ProtectApp />} />
          <Route path="policies" element={<Policies />} />
          <Route path="users" element={<Users />} />
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
