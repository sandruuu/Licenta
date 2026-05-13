import { useState, useEffect } from 'react';
import { getUsers } from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import { Users as UsersIcon, ShieldCheck } from 'lucide-react';

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('ro-RO', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function Users() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getUsers()
      .then((data) => setUsers(Array.isArray(data) ? data : []))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const columns = [
    { key: 'username', label: 'Username', render: (v) => <span className="font-medium text-text-primary">{v}</span> },
    { key: 'email', label: 'Email', render: (v) => v || '—' },
    { key: 'role', label: 'Role', render: (v) => <Badge variant={v === 'admin' ? 'info' : 'accent'}>{v || 'user'}</Badge> },
    { key: 'mfa_enabled', label: 'MFA', render: (v) =>
      v ? <ShieldCheck size={16} className="text-success" /> : <span className="text-text-muted text-xs">Off</span>
    },
    { key: 'disabled', label: 'Status', render: (v) => <Badge variant={v ? 'danger' : 'success'}>{v ? 'Disabled' : 'Active'}</Badge> },
    { key: 'created_at', label: 'Created', render: (v) => <span className="text-mono text-xs">{formatDate(v)}</span> },
    { key: 'last_login', label: 'Last Login', render: (v) => <span className="text-mono text-xs">{formatDate(v)}</span> },
  ];

  return (
    <>
      <PageHeader title="Users" subtitle="Identity Provider — Registered users" />
      <DataTable columns={columns} data={users} loading={loading} emptyIcon={UsersIcon} emptyTitle="No users registered" />
    </>
  );
}