import { useCallback, useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Building2,
  Edit2,
  Key,
  Search,
  UserRoundCheck,
  Users,
} from 'lucide-react';
import { getDirectoryGroups, getDirectoryUsers, getIdPs, getOrganizations, updateIdP } from '../api';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Modal from '../components/ui/Modal';
import FormField, { FormCheckbox, FormInput } from '../components/ui/FormField';
import {
  BackIconButton,
  DetailDivider,
  DetailEmptyState as EmptyState,
  DetailSummaryItem,
  detailSectionTitleClass,
  InlineBackButton,
} from '../components/ui/Detail';
import { formatDateTime } from '../utils/format';
import { navigateBack } from '../utils/navigation';

function DetailValue({ label, value, mono = false }) {
  return (
    <DetailSummaryItem>
      <span className="block text-[10px] font-semibold uppercase tracking-[0.08em] text-text-muted">{label}</span>
      <span className={`mt-1 block truncate text-base font-semibold text-text-primary ${mono ? 'text-mono' : ''}`}>
        {value || '-'}
      </span>
    </DetailSummaryItem>
  );
}

function SearchField({ value, onChange, placeholder }) {
  return (
    <div className="relative">
      <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-10 w-full rounded-md border border-border bg-surface pl-9 pr-3 text-sm font-bold text-text-primary shadow-sm placeholder:text-text-muted transition-colors hover:border-text-muted focus:border-accent focus:outline-none focus:ring-[3px] focus:ring-accent-muted"
      />
    </div>
  );
}

export default function IdPDetail() {
  const { organizationId = '', idpId = '' } = useParams();
  const organizationID = decodeURIComponent(organizationId);
  const idpID = decodeURIComponent(idpId);
  const navigate = useNavigate();
  const location = useLocation();
  const backTarget = `/organizations/${encodeURIComponent(organizationID)}`;

  const [organization, setOrganization] = useState(null);
  const [idp, setIdP] = useState(null);
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [groupQuery, setGroupQuery] = useState('');
  const [userQuery, setUserQuery] = useState('');
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState({});
  const [editSaving, setEditSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [organizationData, idpData, userData, groupData] = await Promise.all([
        getOrganizations(),
        getIdPs(organizationID),
        getDirectoryUsers(organizationID, idpID),
        getDirectoryGroups(organizationID, idpID),
      ]);
      const organizations = Array.isArray(organizationData) ? organizationData : [];
      const idps = Array.isArray(idpData) ? idpData : [];
      setOrganization(organizations.find((item) => item.id === organizationID) || null);
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

  const filteredGroups = useMemo(() => {
    const needle = groupQuery.trim().toLowerCase();
    if (!needle) return groups;

    return groups.filter((group) => [
      group.display_name,
      group.external_id,
      group.id,
      `${(group.member_ids || []).length} members`,
    ].some((value) => String(value || '').toLowerCase().includes(needle)));
  }, [groups, groupQuery]);

  const filteredUsers = useMemo(() => {
    const needle = userQuery.trim().toLowerCase();
    if (!needle) return users;

    return users.filter((user) => [
      user.display_name,
      user.user_name,
      user.email,
      user.id,
      ...(groupsByUserID.get(user.id) || []),
      user.active ? 'active' : 'disabled',
    ].some((value) => String(value || '').toLowerCase().includes(needle)));
  }, [users, userQuery, groupsByUserID]);

  const openEdit = () => {
    setEditForm({
      ...idp,
      claim_username: idp.claim_mapping?.username || '',
      claim_email: idp.claim_mapping?.email || '',
      claim_groups: idp.claim_mapping?.groups || '',
      client_secret: '',
      scim_token: '',
    });
    setEditOpen(true);
  };

  const saveEdit = async () => {
    setEditSaving(true);
    setError('');
    try {
      await updateIdP(idp.id, {
        name: editForm.name?.trim(),
        type: editForm.type || idp.type || 'oidc',
        issuer: editForm.issuer?.trim(),
        client_id: editForm.client_id?.trim(),
        client_secret: editForm.client_secret || undefined,
        scim_token: editForm.scim_token || undefined,
        scopes: (editForm.scopes || '').trim(),
        enabled: editForm.enabled !== false,
        auto_discovery: editForm.auto_discovery !== false,
        claim_mapping: {
          username: (editForm.claim_username || '').trim(),
          email: (editForm.claim_email || '').trim(),
          groups: (editForm.claim_groups || '').trim(),
        },
        group_role_mapping: editForm.group_role_mapping || [],
        is_default: editForm.is_default === true,
      });
      setEditOpen(false);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to update IdP');
    } finally {
      setEditSaving(false);
    }
  };

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
        <InlineBackButton onClick={() => navigateBack(navigate, backTarget, location)}>
          <ArrowLeft size={15} />
          Organization
        </InlineBackButton>
        <EmptyState icon={Key} title="IdP not found" message={error || 'The selected identity provider no longer exists.'} />
      </div>
    );
  }

  return (
    <div className="space-y-7">
      {error && <div className="rounded-md border border-danger bg-danger-muted p-3 text-sm text-danger">{error}</div>}

      <section className="p-5">
        <div className="space-y-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-start gap-3">
                <BackIconButton compact title="Back to organization" onClick={() => navigateBack(navigate, backTarget, location)}>
                  <ArrowLeft size={16} />
                </BackIconButton>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-3">
                    <h1 className="text-2xl font-bold leading-tight text-text-primary">{idp.name}</h1>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
                    <span>{organization?.name || organizationID}</span>
                  </div>
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 lg:justify-end">
              <Button onClick={openEdit}>
                <Edit2 size={14} />
              </Button>
            </div>
          </div>

          <DetailDivider />

          <div>
            <p className={detailSectionTitleClass}>Configuration</p>
            <div className="mt-2 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              <DetailValue label="Issuer" value={idp.issuer} mono />
              <DetailValue label="Client ID" value={idp.client_id} mono />
              <DetailValue label="Type" value={(idp.type || 'oidc').toUpperCase()} />
              <DetailValue label="Scopes" value={idp.scopes || 'openid profile email groups'} mono />
              <DetailValue label="SCIM token" value={idp.has_scim_token ? 'Configured' : 'Not configured'} />
              <DetailValue label="Updated" value={formatDateTime(idp.updated_at)} />
            </div>
          </div>

          <DetailDivider />

          <div className="grid gap-5 xl:grid-cols-2">
            <div className="rounded-md border border-border bg-surface-card p-4 shadow-surface">
              <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className={detailSectionTitleClass}>Groups ({filteredGroups.length} of {groups.length})</p>
                <div className="w-full sm:max-w-[260px]">
                  <SearchField value={groupQuery} onChange={setGroupQuery} placeholder="Search groups" />
                </div>
              </div>
              {groups.length === 0 ? (
                <EmptyState icon={Users} title="No groups" message="When the IdP provisions groups through SCIM, they appear here." />
              ) : filteredGroups.length === 0 ? (
                <EmptyState icon={Users} title="No groups match" message="Adjust search to find a SCIM group." />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[520px] border-collapse">
                    <thead>
                      <tr className="border-b border-border text-left text-[10px] font-bold uppercase tracking-[0.12em] text-text-muted">
                        <th className="px-3 py-3">Group</th>
                        <th className="px-3 py-3">Members</th>
                        <th className="px-3 py-3">Updated</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredGroups.map((group) => (
                        <tr key={group.id} className="border-b border-border-light last:border-b-0">
                          <td className="px-3 py-3 align-top">
                            <p className="truncate text-sm font-semibold text-text-primary">{group.display_name || group.id}</p>
                            <p className="mt-1 truncate text-xs text-text-secondary">{group.external_id || group.id}</p>
                          </td>
                          <td className="px-3 py-3 align-top">
                            <Badge variant="accent">{(group.member_ids || []).length} members</Badge>
                          </td>
                          <td className="px-3 py-3 align-top text-xs font-semibold text-text-secondary">
                            {formatDateTime(group.updated_at)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-border bg-surface-card p-4 shadow-surface">
              <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className={detailSectionTitleClass}>Users ({filteredUsers.length} of {users.length})</p>
                <div className="w-full sm:max-w-[260px]">
                  <SearchField value={userQuery} onChange={setUserQuery} placeholder="Search users" />
                </div>
              </div>
              {users.length === 0 ? (
                <EmptyState icon={UserRoundCheck} title="No users" message="When the IdP provisions users through SCIM, they appear here." />
              ) : filteredUsers.length === 0 ? (
                <EmptyState icon={UserRoundCheck} title="No users match" message="Adjust search to find a SCIM user." />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[560px] border-collapse">
                    <thead>
                      <tr className="border-b border-border text-left text-[10px] font-bold uppercase tracking-[0.12em] text-text-muted">
                        <th className="px-3 py-3">User</th>
                        <th className="px-3 py-3">Groups</th>
                        <th className="px-3 py-3">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredUsers.map((user) => (
                        <tr key={user.id} className="border-b border-border-light last:border-b-0">
                          <td className="px-3 py-3 align-top">
                            <p className="truncate text-sm font-semibold text-text-primary">{user.display_name || user.user_name || user.id}</p>
                            <p className="mt-1 truncate text-xs text-text-secondary">{user.email || user.user_name || '-'}</p>
                          </td>
                          <td className="px-3 py-3 align-top text-xs font-semibold text-text-secondary">
                            <span className="line-clamp-2">{(groupsByUserID.get(user.id) || []).join(', ') || 'No groups'}</span>
                          </td>
                          <td className="px-3 py-3 align-top">
                            <Badge variant={user.active ? 'success' : 'danger'}>{user.active ? 'Active' : 'Disabled'}</Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title="Edit Primary Authenticator"
        size="2xl"
        footer={(
          <>
            <Button variant="secondary" onClick={() => setEditOpen(false)}>Cancel</Button>
            <Button onClick={saveEdit} disabled={editSaving || !editForm.name?.trim() || !editForm.issuer?.trim() || !editForm.client_id?.trim()}>
              {editSaving ? 'Saving...' : 'Save Changes'}
            </Button>
          </>
        )}
      >
        <div className="grid gap-x-4 gap-y-1 md:grid-cols-2">
          <FormField label="Provider name" className="mb-3">
            <FormInput value={editForm.name || ''} onChange={(event) => setEditForm({ ...editForm, name: event.target.value })} />
          </FormField>
          <FormField label="OIDC client ID" className="mb-3">
            <FormInput value={editForm.client_id || ''} onChange={(event) => setEditForm({ ...editForm, client_id: event.target.value })} className="font-mono" />
          </FormField>
          <FormField label="Issuer URL" className="mb-3 md:col-span-2">
            <FormInput value={editForm.issuer || ''} onChange={(event) => setEditForm({ ...editForm, issuer: event.target.value })} className="font-mono" />
          </FormField>
          <FormField label="OIDC client secret" className="mb-3">
            <FormInput type="password" value={editForm.client_secret || ''} onChange={(event) => setEditForm({ ...editForm, client_secret: event.target.value })} placeholder="Leave blank to keep unchanged" />
          </FormField>
          <FormField label="SCIM provisioning token" className="mb-3">
            <FormInput type="password" value={editForm.scim_token || ''} onChange={(event) => setEditForm({ ...editForm, scim_token: event.target.value })} placeholder="Leave blank to keep unchanged" />
          </FormField>
          <FormField label="Scopes" className="mb-3 md:col-span-2">
            <FormInput value={editForm.scopes || ''} onChange={(event) => setEditForm({ ...editForm, scopes: event.target.value })} className="font-mono" />
          </FormField>
        </div>

        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-y border-border-light py-3">
          <FormCheckbox id="idp-detail-enabled" checked={editForm.enabled !== false} onChange={(event) => setEditForm({ ...editForm, enabled: event.target.checked })} label="Enabled" />
          <FormCheckbox id="idp-detail-discovery" checked={editForm.auto_discovery !== false} onChange={(event) => setEditForm({ ...editForm, auto_discovery: event.target.checked })} label="Auto-discovery" />
        </div>

        <div className="grid gap-x-4 gap-y-1 md:grid-cols-3">
          <FormField label="Username claim" className="mb-3">
            <FormInput value={editForm.claim_username || ''} onChange={(event) => setEditForm({ ...editForm, claim_username: event.target.value })} className="font-mono" />
          </FormField>
          <FormField label="Email claim" className="mb-3">
            <FormInput value={editForm.claim_email || ''} onChange={(event) => setEditForm({ ...editForm, claim_email: event.target.value })} className="font-mono" />
          </FormField>
          <FormField label="Groups claim" className="mb-3">
            <FormInput value={editForm.claim_groups || ''} onChange={(event) => setEditForm({ ...editForm, claim_groups: event.target.value })} className="font-mono" />
          </FormField>
        </div>
      </Modal>
    </div>
  );
}
