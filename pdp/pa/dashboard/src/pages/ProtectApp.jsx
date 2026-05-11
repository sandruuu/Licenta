import { Navigate } from 'react-router-dom';

export default function ProtectApp() {
  return <Navigate to="/dashboard/resources" replace />;
}
