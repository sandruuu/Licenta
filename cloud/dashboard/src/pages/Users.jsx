import { useState, useEffect } from 'react';
import { getUsers } from '../api';
import { Users as UsersIcon, ShieldCheck } from 'lucide-react';

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('ro-RO', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
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

  if (loading) return <div className="loading"><div className="spinner" /> Loading users...</div>;

  return (
    <>
      <div className="page-header">
        <h2>Users</h2>
        <p>Identity Provider — Registered users</p>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{users.length} User{users.length !== 1 ? 's' : ''}</h3>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>MFA</th>
                <th>Status</th>
                <th>Created</th>
                <th>Last Login</th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 ? (
                <tr>
                  <td colSpan={7}>
                    <div className="empty-state">
                      <UsersIcon size={40} />
                      <p>No users registered.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                users.map((user) => (
                  <tr key={user.id}>
                    <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{user.username}</td>
                    <td>{user.email || '—'}</td>
                    <td>
                      <span className={`badge ${user.role === 'admin' ? 'badge-ssh' : 'badge-web'}`}>
                        {user.role || 'user'}
                      </span>
                    </td>
                    <td>
                      {user.mfa_enabled ? (
                        <ShieldCheck size={16} color="var(--success)" />
                      ) : (
                        <span className="text-muted text-sm">Off</span>
                      )}
                    </td>
                    <td>
                      <span className={`badge badge-${user.disabled ? 'disabled' : 'enabled'}`}>
                        {user.disabled ? 'Disabled' : 'Active'}
                      </span>
                    </td>
                    <td className="text-mono text-sm">{formatDate(user.created_at)}</td>
                    <td className="text-mono text-sm">{formatDate(user.last_login)}</td>
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
