import { useState, useEffect } from 'react';
import { getDashboardStats, getAuditLog } from '../api';
import PageHeader from '../components/ui/PageHeader';
import StatCard from '../components/ui/StatCard';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import {
  Users, Radio, Server, AlertTriangle, Monitor, Activity, FileText,
} from 'lucide-react';

const statCards = [
  { key: 'total_users', label: 'Total Users', icon: Users, color: 'blue' },
  { key: 'active_sessions', label: 'Active Sessions', icon: Radio, color: 'green' },
  { key: 'total_resources', label: 'Resources', icon: Server, color: 'purple' },
  { key: 'recent_denials', label: 'Recent Denials', icon: AlertTriangle, color: 'red' },
  { key: 'healthy_devices', label: 'Healthy Devices', icon: Monitor, color: 'green' },
  { key: 'total_devices', label: 'Total Devices', icon: Activity, color: 'blue' },
];

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  return d.toLocaleString('ro-RO', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
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

  const auditColumns = [
    { key: 'timestamp', label: 'Time', render: (v) => <span className="text-mono whitespace-nowrap">{formatTime(v)}</span> },
    { key: 'event_type', label: 'Event' },
    { key: 'username', label: 'User', render: (v) => v || '-' },
    { key: 'decision', label: 'Decision', render: (v) => v ? (
      <Badge variant={v === 'allow' ? 'success' : v === 'deny' ? 'danger' : 'warning'}>{v}</Badge>
    ) : '-' },
    { key: 'details', label: 'Details', render: (v) => <span className="block max-w-[250px] truncate text-xs text-text-muted">{v || '-'}</span> },
  ];

  return (
    <>
      <PageHeader title="Dashboard" subtitle="Overview of users, sessions, resources, devices, and recent audit events" />

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {statCards.map((card) => (
          <StatCard
            key={card.key}
            label={card.label}
            value={stats?.[card.key] ?? 0}
            icon={card.icon}
            color={card.color}
          />
        ))}
      </div>

      <DataTable
        columns={auditColumns}
        data={audit}
        loading={false}
        emptyIcon={FileText}
        emptyTitle="No audit events found"
      />
    </>
  );
}
