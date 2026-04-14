import { useState, useEffect } from 'react';
import { getDashboardStats, getAuditLog } from '../api';
import {
  Users,
  Radio,
  Server,
  Shield,
  AlertTriangle,
  Activity,
  Monitor,
  TrendingUp,
} from 'lucide-react';

const iconMap = {
  users: { icon: Users, color: 'blue' },
  sessions: { icon: Radio, color: 'green' },
  resources: { icon: Server, color: 'purple' },
  policies: { icon: Shield, color: 'orange' },
  denials: { icon: AlertTriangle, color: 'red' },
  risk: { icon: TrendingUp, color: 'orange' },
  healthy: { icon: Monitor, color: 'green' },
  devices: { icon: Activity, color: 'blue' },
};

function StatCard({ label, value, type }) {
  const { icon: Icon, color } = iconMap[type] || iconMap.users;
  return (
    <div className="stat-card">
      <div className="stat-card-header">
        <span>{label}</span>
        <div className={`stat-card-icon ${color}`}>
          <Icon />
        </div>
      </div>
      <div className="stat-card-value">{value}</div>
    </div>
  );
}

function formatTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleString('ro-RO', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [audit, setAudit] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getDashboardStats(), getAuditLog(10)])
      .then(([s, a]) => {
        setStats(s);
        setAudit(Array.isArray(a) ? a : []);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="loading"><div className="spinner" /> Loading dashboard...</div>;
  }

  return (
    <>
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>Zero Trust Network Access — Overview</p>
      </div>

      <div className="stats-grid">
        <StatCard label="Total Users" value={stats?.total_users ?? 0} type="users" />
        <StatCard label="Active Sessions" value={stats?.active_sessions ?? 0} type="sessions" />
        <StatCard label="Resources" value={stats?.total_resources ?? 0} type="resources" />
        <StatCard label="Policies" value={stats?.total_policies ?? 0} type="policies" />
        <StatCard label="Recent Denials" value={stats?.recent_denials ?? 0} type="denials" />
        <StatCard label="Avg Risk Score" value={stats?.average_risk ?? 0} type="risk" />
        <StatCard label="Healthy Devices" value={stats?.healthy_devices ?? 0} type="healthy" />
        <StatCard label="Total Devices" value={stats?.total_devices ?? 0} type="devices" />
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Recent Activity</h3>
        </div>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>User</th>
                <th>Decision</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {audit.length === 0 ? (
                <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No recent activity</td></tr>
              ) : (
                audit.map((entry) => (
                  <tr key={entry.id}>
                    <td className="text-mono">{formatTime(entry.timestamp)}</td>
                    <td>{entry.event_type}</td>
                    <td>{entry.username || '—'}</td>
                    <td>
                      {entry.decision && (
                        <span className={`badge badge-${entry.decision === 'allow' ? 'allow' : entry.decision === 'deny' ? 'deny' : 'mfa'}`}>
                          {entry.decision}
                        </span>
                      )}
                    </td>
                    <td className="text-sm text-muted">{entry.details}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
