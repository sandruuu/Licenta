import { useLocation } from 'react-router-dom';
import AdminLogin from '../components/login/AdminLogin';
import AccessPortalLogin from '../components/login/AccessPortalLogin';

export default function Login() {
  const location = useLocation();
  if (location.pathname === '/auth/login') {
    return <AccessPortalLogin />;
  }
  return <AdminLogin />;
}
