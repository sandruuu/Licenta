import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { clearToken } from '../api';
import {
  LayoutDashboard,
  Server,
  Router,
  Shield,
  Users,
  Radio,
  Activity,
  FileText,
  LogOut,
} from 'lucide-react';

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/dashboard/resources', icon: Server, label: 'Resources' },
  { to: '/dashboard/gateways', icon: Router, label: 'Gateways' },
  { to: '/dashboard/policies', icon: Shield, label: 'Policies' },
  { to: '/dashboard/users', icon: Users, label: 'Users' },
  { to: '/dashboard/sessions', icon: Radio, label: 'Sessions' },
  { to: '/dashboard/device-health', icon: Activity, label: 'Device Health' },
  { to: '/dashboard/audit', icon: FileText, label: 'Audit Log' },
];

export default function Layout() {
  const navigate = useNavigate();

  const handleLogout = () => {
    clearToken();
    navigate('/dashboard/login');
  };

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-inner">
          <div className="sidebar-brand">
            <h1 className="brand-title">SECURE<span className="accent">ALERT</span></h1>
            <span className="brand-sub">Cloud PDP Console</span>
          </div>

          <nav className="sidebar-nav">
            <div className="nav-group">
              <div className="nav-group-label">Overview</div>
              {navItems.filter((x) => x.to === '/dashboard').map(({ to, icon: Icon, label, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                >
                  <Icon />
                  {label}
                </NavLink>
              ))}
            </div>

            <div className="nav-group">
              <div className="nav-group-label">Protect</div>
              {navItems.filter((x) => x.to !== '/dashboard').map(({ to, icon: Icon, label, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                >
                  <Icon />
                  {label}
                </NavLink>
              ))}
            </div>
          </nav>

          <div className="sidebar-footer">
            <button className="logout-btn" onClick={handleLogout}>
              <LogOut size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
              Logout
            </button>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
