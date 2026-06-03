import { createElement } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { clearToken } from '../api';
import BrandLogo from './ui/BrandLogo';
import ThemeToggle from './ui/ThemeToggle';
import {
  LayoutDashboard,
  Server,
  Router,
  Radio,
  Activity,
  FileText,
  LogOut,
  Building2,
  ShieldCheck,
} from 'lucide-react';

const navSections = [
  {
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true },
    ],
  },
  {
    items: [
      { to: '/organizations', icon: Building2, label: 'Organizations' },
      { to: '/resources', icon: Server, label: 'Resources' },
      { to: '/policies', icon: ShieldCheck, label: 'Policies' },
      { to: '/gateways', icon: Router, label: 'Gateways' },
    ],
  },
  {
    items: [
      { to: '/sessions', icon: Radio, label: 'Sessions' },
      { to: '/device-health', icon: Activity, label: 'Devices' },
      { to: '/audit', icon: FileText, label: 'Audit' },
    ],
  },
];

export default function Layout() {
  const navigate = useNavigate();

  const handleLogout = () => {
    clearToken();
    navigate('/login');
  };

  return (
    <div className="min-h-screen">
      <aside
        className="sidebar-shell group fixed left-1.5 top-1.5 z-40 flex h-[calc(100vh-12px)] w-[88px] flex-col gap-2 rounded-md p-2 transition-[width] duration-300 ease-out hover:w-[292px]"
      >
        <div className="sidebar-panel flex h-20 shrink-0 items-center justify-center gap-0 rounded-md px-3 transition-colors group-hover:justify-start group-hover:gap-3">
          <BrandLogo
            className="flex w-full items-center justify-center gap-0 group-hover:justify-start group-hover:gap-3"
            textWrapperClassName="w-0 min-w-0 overflow-hidden whitespace-nowrap opacity-0 transition-all duration-200 group-hover:w-auto group-hover:opacity-100"
          />
        </div>

        <div className="sidebar-panel flex min-h-0 flex-1 flex-col overflow-hidden rounded-md">
          <nav className="flex-1 overflow-y-auto px-3 py-4">
            {navSections.map((section, sectionIndex) => (
              <div key={sectionIndex} className="mb-4">
                <div className="space-y-1">
                  {section.items.map(({ to, icon, label, end }) => (
                    <NavLink
                      key={to}
                      to={to}
                      end={end}
                      title={label}
                      className={({ isActive }) =>
                        [
                          'flex h-11 items-center justify-center gap-0 overflow-hidden rounded-md px-3 text-sm font-bold no-underline transition-all duration-200 hover:text-[15px] hover:[&>svg]:h-5 hover:[&>svg]:w-5 group-hover:justify-start group-hover:gap-3',
                          isActive
                            ? 'text-[15px] text-accent [&>svg]:h-5 [&>svg]:w-5'
                            : 'text-text-secondary hover:text-text-primary',
                        ].join(' ')
                      }
                    >
                      {createElement(icon, { className: 'h-[18px] w-[18px] shrink-0 transition-all duration-200' })}
                      <span className="w-0 min-w-0 overflow-hidden whitespace-nowrap opacity-0 transition-all duration-200 group-hover:w-auto group-hover:opacity-100">
                        {label}
                      </span>
                    </NavLink>
                  ))}
                </div>
              </div>
            ))}
          </nav>

          <div className="shrink-0 p-3">
            <ThemeToggle
              showLabel
              borderless
              collapsibleLabel
              className="mb-2 justify-center group-hover:justify-start group-hover:gap-3"
              labelClassName="w-0 opacity-0 group-hover:w-auto group-hover:opacity-100"
            />
            <button
              type="button"
              onClick={handleLogout}
              title="Logout"
              className="flex h-11 w-full items-center justify-center gap-0 overflow-hidden rounded-md bg-transparent px-3 text-sm font-bold text-danger transition-all duration-200 hover:text-[15px] hover:[&>svg]:h-5 hover:[&>svg]:w-5 group-hover:justify-start group-hover:gap-3"
            >
              <LogOut className="h-[18px] w-[18px] shrink-0 transition-all duration-200" />
              <span className="w-0 min-w-0 overflow-hidden whitespace-nowrap opacity-0 transition-all duration-200 group-hover:w-auto group-hover:opacity-100">
                Logout
              </span>
            </button>
          </div>
        </div>
      </aside>

      <main className="min-h-screen pl-[96px]">
        <div className="p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
