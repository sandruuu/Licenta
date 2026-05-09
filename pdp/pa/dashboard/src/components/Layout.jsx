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
  Building2,
} from 'lucide-react';

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/dashboard/tenants', icon: Building2, label: 'Tenants' },
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
    <div className="flex min-h-screen">
      <aside
        className="w-[290px] min-w-[290px] bg-surface-card border-r border-border
                   flex flex-col fixed h-screen z-10"
      >
        {/* Brand */}
        <div className="pt-8 px-6 pb-5 border-b border-border text-center flex-shrink-0">
          <h1 className="text-xl font-bold tracking-[-0.3px] text-text-primary leading-none">
            SECURE<span className="text-accent-orange">ALERT</span>
          </h1>
          <span className="inline-block mt-2 text-[11px] text-text-muted uppercase tracking-[0.08em] font-semibold">
            PDP Console
          </span>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 py-3 overflow-y-auto">
          {navItems.map(({ to, icon: Icon, label, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                [
                  'flex items-center gap-3 px-3.5 py-3 rounded-md no-underline text-sm font-bold transition-all duration-200 mb-0.5',
                  isActive
                    ? 'bg-accent text-white shadow-[0_4px_12px_rgba(15,23,42,0.2)]'
                    : 'text-text-secondary hover:bg-surface-hover hover:text-text-primary',
                ].join(' ')
              }
            >
              <Icon className="w-[18px] h-[18px] flex-shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-border flex-shrink-0">
          <button
            onClick={handleLogout}
            className="w-full py-2.5 px-3 border border-border rounded-md bg-transparent
                       text-text-secondary text-[13px] font-bold cursor-pointer
                       transition-all duration-200
                       hover:bg-danger-muted hover:text-danger hover:border-danger"
          >
            <LogOut size={14} className="inline-block mr-1.5 align-middle" />
            Logout
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 ml-[290px] p-8 min-h-screen">
        <Outlet />
      </main>
    </div>
  );
}
