import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Globe,
  Key,
  Shield,
  UserRoundCheck,
  Users,
} from 'lucide-react';
import { getDirectoryGroups, getDirectoryUsers, getIdPs, getTenants } from '../api';
import Badge from '../components/ui/Badge';

function formatDate(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString('ro-RO', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function EmptyState({ icon: Icon, title, message }) {
  return (
    <div className="py-8 text-center text-text-muted">
      <Icon size={32} className="mx-auto mb-3 opacity-35" />
      <p className="text-sm font-semibold text-text-primary">{title}</p>
      {message && <p className="mt-1 text-xs">{message}</p>}
    </div>
  );
}

function CollapsibleSection({ icon: Icon, title, subtitle, count, open, onToggle, children }) {
  return (
    <section className="border-b border-border-light pb-5">
      <button type="button" onClick={onToggle} className="group flex w-full items-start gap-3 bg-transparent p-0 text-left">
        <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-surface-secondary text-text-secondary group-hover:bg-[rgba(255,95,31,0.12)] group-hover:text-accent-orange">
          <Icon size={17} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2 text-base font-semibold text-text-primary">
            {title}
            {typeof count === 'number' && <Badge variant="neutral">{count}</Badge>}
            {open ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
          </span>
          {subtitle && <span className="mt-1 block text-xs text-text-muted">{subtitle}</span>}
        </span>
      </button>
      {open && <div className="mt-4">{children}</div>}
    </section>
  );
}

function FieldLine({ label, value, mono = false }) {
  const displayValue = value === 0 || value === false ? String(value) : value || '-';
  return (
    <div className="min-w-0">
      <div className="text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">{label}</div>
      <div className={`mt-1 truncate text-sm font-medium text-text-primary ${mono ? 'text-mono' : ''}`}>{displayValue}</div>
    </div>
  );
}

function DataRow({ children, className = '' }) {
  return (
    <div className={`grid items-center gap-4 rounded-md border border-border-light bg-surface-card px-4 py-3 ${className}`}>
      {children}
    </div>
  );
}

export default function IdPDetail() {
  const { organizationId = '', idpId = '' } = useParams();
  const organizationID = decodeURIComponent(organizationId);
  const idpID = decodeURIComponent(idpId);
  const navigate = useNavigate();

  const [organization, setOrganization] = useState(null);
  const [idp, setIdP] = useState(null);
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [openSections, setOpenSections] = useState({ config: true, groups: true, users: true });

  const toggleSection = (key) => {
    setOpenSections((current) => ({ ...current, [key]: !current[key] }));
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [tenantData, idpData, userData, groupData] = await Promise.all([
        getTenants(),
        getIdPs(organizationID),
        getDirectoryUsers(organizationID, idpID),
        getDirectoryGroups(organizationID, idpID),
      ]);
      const tenants = Array.isArray(tenantData) ? tenantData : [];
      const idps = Array.isArray(idpData) ? idpData : [];
      setOrganization(tenants.find((tenant) => tenant.id === organizationID) || null);
      setIdP(idps.find((provider) => provider.id === idpID) || null);
      setUsers(Array.isArray(userData) ? userData : []);
      setGroups(Array.isArray(groupData) ? groupData : []);
    } catch (e) {
      setError(e.message || 'Failed to load IdP data');
    } finally {
      setLoading(false);
    }
  }, [organizationID, idpID]);

  useEffect(() => {
    load();
  }, [load]);

  const groupsByUserID = useMemo(() => {
    const map = new Map();
    groups.forEach((group) => {
      (group.member_ids || []).forEach((memberID) => {
        if (!map.has(memberID)) map.set(memberID, []);
        map.get(memberID).push(group.display_name || group.id);
      });
    });
    return map;
  }, [groups]);

  if (loading) {
    return (
      <div className="py-16 text-center text-text-muted">
        <span className="spinner mr-2" />
        Loading IdP...
      </div>
    );
  }

  if (!idp) {
    return (
      <div className="space-y-4">
        <button
          type="button"
          onClick={() => navigate(`/dashboard/organizations/${encodeURIComponent(organizationID)}`)}
          className="inline-flex items-center gap-2 rounded-md bg-transparent px-0 py-0 text-sm font-semibold text-text-secondary hover:text-accent-orange"
        >
          <ArrowLeft size={15} />
          Organization
        </button>
        <EmptyState icon={Key} title="IdP not found" message={error || 'The selected identity provider no longer exists.'} />
      </div>
    );
  }

  return (
    <div className="space-y-7">
      {error && <div className="rounded-md border border-danger bg-danger-muted p-3 text-sm text-danger">{error}</div>}

      <header className="flex flex-col gap-4 border-b border-border-light pb-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <button
            type="button"
            title="Back to organization"
            onClick={() => navigate(`/dashboard/organizations/${encodeURIComponent(organizationID)}`)}
            className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-surface-card text-text-secondary shadow-sm transition-colors hover:border-accent-orange hover:bg-[rgba(255,95,31,0.08)] hover:text-accent-orange"
          >
            <ArrowLeft size={16} />
          </button>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-bold leading-tight text-text-primary">{idp.name || idp.id}</h1>
              <Badge variant={idp.enabled === false ? 'danger' : 'success'}>{idp.enabled === false ? 'Disabled' : 'Enabled'}</Badge>
              {idp.is_default && <Badge variant="info">Default</Badge>}
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
              <span className="inline-flex items-center gap-1">
                <Globe size={13} />
                {organization?.name || organizationID}
              </span>
              <span className="text-mono">{idp.id}</span>
            </div>
          </div>
        </div>
      </header>

      <CollapsibleSection
        icon={Shield}
        title="Configuration"
        subtitle="OIDC and SCIM settings exposed to the administrator"
        open={openSections.config}
        onToggle={() => toggleSection('config')}
      >
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <FieldLine label="Issuer" value={idp.issuer} mono />
          <FieldLine label="Client ID" value={idp.client_id} mono />
          <FieldLine label="Type" value={(idp.type || 'oidc').toUpperCase()} />
          <FieldLine label="Scopes" value={idp.scopes || 'openid profile email groups'} mono />
          <FieldLine label="SCIM token" value={idp.has_scim_token ? 'Configured' : 'Not configured'} />
          <FieldLine label="Updated" value={formatDate(idp.updated_at)} />
        </div>
      </CollapsibleSection>

      <CollapsibleSection
        icon={Users}
        title="SCIM Groups"
        subtitle="Groups provisioned by this IdP"
        count={groups.length}
        open={openSections.groups}
        onToggle={() => toggleSection('groups')}
      >
        {groups.length === 0 ? (
          <EmptyState icon={Users} title="No groups" message="When the IdP provisions groups through SCIM, they appear here." />
        ) : (
          <div className="space-y-2">
            {groups.map((group) => (
              <DataRow key={group.id} className="md:grid-cols-[1.4fr_0.7fr_1.2fr_0.9fr]">
                <FieldLine label="Group" value={group.display_name || group.id} />
                <Badge variant="accent">{(group.member_ids || []).length} members</Badge>
                <FieldLine label="External ID" value={group.external_id || group.id} mono />
                <FieldLine label="Updated" value={formatDate(group.updated_at)} />
              </DataRow>
            ))}
          </div>
        )}
      </CollapsibleSection>

      <CollapsibleSection
        icon={UserRoundCheck}
        title="SCIM Users"
        subtitle="Users provisioned by this IdP"
        count={users.length}
        open={openSections.users}
        onToggle={() => toggleSection('users')}
      >
        {users.length === 0 ? (
          <EmptyState icon={UserRoundCheck} title="No users" message="When the IdP provisions users through SCIM, they appear here." />
        ) : (
          <div className="space-y-2">
            {users.map((user) => (
              <DataRow key={user.id} className="md:grid-cols-[1.2fr_1.3fr_1fr_0.7fr]">
                <FieldLine label="User" value={user.display_name || user.user_name || user.id} />
                <FieldLine label="Email" value={user.email || user.user_name} />
                <FieldLine label="Groups" value={(groupsByUserID.get(user.id) || []).join(', ') || '-'} />
                <Badge variant={user.active ? 'success' : 'danger'}>{user.active ? 'Active' : 'Disabled'}</Badge>
              </DataRow>
            ))}
          </div>
        )}
      </CollapsibleSection>
    </div>
  );
}
