import { useCallback, useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  ChevronLeft,
  Edit2,
  Key,
  RotateCcw,
  Search,
  UserRoundCheck,
  Users,
} from 'lucide-react';
import { getDirectoryGroups, getDirectoryUsers, getIdPs, getOrganizations, updateIdP } from '../api';
import Button from '../components/ui/Button';
import PageLoading from '../components/ui/PageLoading';
import Modal from '../components/ui/Modal';
import GatewayTokenModal from '../components/organizations/GatewayTokenModal';
import FormField, { FormCheckbox, FormInput } from '../components/ui/FormField';
import StatusText from '../components/ui/StatusText';
import {
  DetailEmptyState as EmptyState,
  InlineBackButton,
} from '../components/ui/Detail';
import { formatDateTime } from '../utils/format';
import { navigateBack } from '../utils/navigation';

const detailPanelClass = 'rounded-md border border-border bg-transparent';
const tableRowClass = 'min-h-[92px] rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] shadow-[0_8px_16px_rgba(42,42,42,0.12)] transition-[border-color,background-color,box-shadow] duration-150 hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.14)]';
const panelTitleClass = 'text-[20px] font-bold leading-tight text-text-primary';
const panelCountClass = 'text-sm font-bold text-text-muted';
const tableHeaderWrapClass = 'relative px-2 pr-5';
const tableHeaderCellClass = "relative flex min-w-0 items-center justify-center px-4 py-4 text-center text-[11px] font-bold uppercase tracking-[0.14em] text-text-muted after:absolute after:bottom-[2px] after:right-0 after:h-5 after:w-[2px] after:bg-border after:content-[''] last:after:hidden";
const tableScrollClass = 'mt-3 h-[312px] overflow-y-auto px-2 pr-4 [scrollbar-gutter:stable]';

function DetailField({ label, value, mono = false, children }) {
  return (
    <div className="min-w-0">
      <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-text-muted">{label}</p>
      {children || (
        <p className={`mt-2 truncate text-sm font-semibold text-text-primary ${mono ? 'text-mono' : ''}`}>
          {value === undefined || value === null || value === '' ? '-' : value}
        </p>
      )}
    </div>
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
  const [regeneratingSCIMToken, setRegeneratingSCIMToken] = useState(false);
  const [scimTokenModal, setScimTokenModal] = useState(null);

  const load = useCallback(async ({ showLoading = true } = {}) => {
    if (showLoading) setLoading(true);
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
      if (showLoading) setLoading(false);
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
    });
    setEditOpen(true);
  };

  const showSCIMToken = (token, providerName) => {
    setScimTokenModal({ token, providerName, organizationID });
  };

  const closeSCIMTokenModal = () => {
    setScimTokenModal(null);
    load({ showLoading: false });
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

  const regenerateSCIMToken = async () => {
    setRegeneratingSCIMToken(true);
    setError('');
    try {
      const updatedIdP = await updateIdP(idp.id, { regenerate_scim_token: true });
      setEditOpen(false);
      if (updatedIdP?.scim_token) {
        showSCIMToken(updatedIdP.scim_token, updatedIdP.name || idp.name);
      }
      await load({ showLoading: false });
    } catch (e) {
      setError(e.message || 'Failed to regenerate SCIM token');
    } finally {
      setRegeneratingSCIMToken(false);
    }
  };

  if (loading) {
    return <PageLoading label="Loading..." />;
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

      <section className="space-y-5 pb-5 pr-3 pt-1">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                aria-label="Back to organization"
                onClick={() => navigateBack(navigate, backTarget, location)}
                className="-ml-2 inline-flex h-11 w-11 shrink-0 items-center justify-center text-text-primary transition-colors hover:text-accent focus-visible:text-accent active:text-accent-hover"
              >
                <ChevronLeft size={34} strokeWidth={3} />
              </button>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-3">
                  <h1 className="text-2xl font-bold leading-tight text-text-primary">{idp.name}</h1>
                  <StatusText variant={idp.enabled === false ? 'danger' : 'success'}>
                    {idp.enabled === false ? 'Disabled' : 'Enabled'}
                  </StatusText>
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
              Edit
            </Button>
          </div>
        </div>

        <div className="border-t border-border" />

        <section className={`${detailPanelClass} p-5`}>
          <h2 className={panelTitleClass}>Configuration data</h2>
          <div className="mt-5 grid gap-x-8 gap-y-5 md:grid-cols-2 xl:grid-cols-3">
            <DetailField label="Name" value={idp.name} />
            <DetailField label="Issuer" value={idp.issuer} mono />
            <DetailField label="Client ID" value={idp.client_id} mono />
            <DetailField label="Type" value={(idp.type || 'oidc').toUpperCase()} />
            <DetailField label="Scopes" value={idp.scopes || 'openid profile email groups'} mono />
            <DetailField label="SCIM token">
              <p className={`mt-2 text-sm font-bold uppercase ${idp.has_scim_token ? 'text-[#638f67]' : 'text-[#b46a62]'}`}>
                {idp.has_scim_token ? 'CONFIGURED' : 'NOT CONFIGURED'}
              </p>
            </DetailField>
            <DetailField label="Groups" value={groups.length} />
            <DetailField label="Users" value={users.length} />
            <DetailField label="Updated" value={formatDateTime(idp.updated_at)} />
          </div>
        </section>

        <div className="grid gap-5 xl:grid-cols-2">
          <section className={`${detailPanelClass} p-5`}>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h2 className={panelTitleClass}>
                Groups <span className={panelCountClass}>({filteredGroups.length} of {groups.length})</span>
              </h2>
              <div className="w-full sm:max-w-[260px]">
                <SearchField value={groupQuery} onChange={setGroupQuery} placeholder="Search groups" />
              </div>
            </div>

            {groups.length === 0 ? (
              <EmptyState icon={Users} title="No groups" message="When the IdP provisions groups through SCIM, they appear here." />
            ) : filteredGroups.length === 0 ? (
              <EmptyState icon={Users} title="No groups match" message="Adjust search to find a SCIM group." />
            ) : (
              <div className="mt-4 min-w-0">
                <div className={tableHeaderWrapClass}>
                  <div aria-hidden="true" className="pointer-events-none absolute bottom-0 left-2 right-5 h-[2px] bg-border" />
                  <div className="grid grid-cols-[minmax(0,1.35fr)_110px_minmax(0,0.85fr)]">
                    <div className={tableHeaderCellClass}>Group</div>
                    <div className={tableHeaderCellClass}>Members</div>
                    <div className={tableHeaderCellClass}>Updated</div>
                  </div>
                </div>
                <div className={tableScrollClass}>
                  <div className="space-y-3 pb-1">
                    {filteredGroups.map((group) => (
                      <div key={group.id} className={`${tableRowClass} grid grid-cols-[minmax(0,1.35fr)_110px_minmax(0,0.85fr)] items-stretch`}>
                        <div className="flex min-w-0 flex-col items-center justify-center px-4 py-4 text-center">
                          <p className="truncate text-sm font-semibold text-text-primary">{group.display_name || group.id}</p>
                          <p className="mt-1 truncate text-xs text-text-secondary">{group.external_id || group.id}</p>
                        </div>
                        <p className="flex items-center justify-center px-4 py-4 text-center text-xs font-bold text-text-secondary">{(group.member_ids || []).length}</p>
                        <p className="flex items-center justify-center px-4 py-4 text-center text-xs font-semibold text-text-secondary">{formatDateTime(group.updated_at)}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </section>

          <section className={`${detailPanelClass} p-5`}>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h2 className={panelTitleClass}>
                Users <span className={panelCountClass}>({filteredUsers.length} of {users.length})</span>
              </h2>
              <div className="w-full sm:max-w-[260px]">
                <SearchField value={userQuery} onChange={setUserQuery} placeholder="Search users" />
              </div>
            </div>

            {users.length === 0 ? (
              <EmptyState icon={UserRoundCheck} title="No users" message="When the IdP provisions users through SCIM, they appear here." />
            ) : filteredUsers.length === 0 ? (
              <EmptyState icon={UserRoundCheck} title="No users match" message="Adjust search to find a SCIM user." />
            ) : (
              <div className="mt-4 min-w-0">
                <div className={tableHeaderWrapClass}>
                  <div aria-hidden="true" className="pointer-events-none absolute bottom-0 left-2 right-5 h-[2px] bg-border" />
                  <div className="grid grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_90px]">
                    <div className={tableHeaderCellClass}>User</div>
                    <div className={tableHeaderCellClass}>Groups</div>
                    <div className={tableHeaderCellClass}>Status</div>
                  </div>
                </div>
                <div className={tableScrollClass}>
                  <div className="space-y-3 pb-1">
                    {filteredUsers.map((user) => (
                      <div key={user.id} className={`${tableRowClass} grid grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_90px] items-stretch`}>
                        <div className="flex min-w-0 flex-col items-center justify-center px-4 py-4 text-center">
                          <p className="truncate text-sm font-semibold text-text-primary">{user.display_name || user.user_name || user.id}</p>
                          <p className="mt-1 truncate text-xs text-text-secondary">{user.email || user.user_name || '-'}</p>
                        </div>
                        <p className="flex items-center justify-center px-4 py-4 text-center text-xs font-semibold text-text-secondary">{(groupsByUserID.get(user.id) || []).join(', ') || 'No groups'}</p>
                        <div className="flex items-center justify-center px-4 py-4 text-center">
                          <StatusText variant={user.active ? 'success' : 'danger'}>{user.active ? 'Active' : 'Disabled'}</StatusText>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </section>
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
          <div className="mb-3 rounded-md border border-border bg-surface-secondary px-4 py-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.2px] text-text-secondary">SCIM provisioning token</p>
            <p className="mt-2 text-sm font-semibold text-text-secondary">
              {idp.has_scim_token ? 'A token is configured. Regenerate it only when rotating connector or IdP credentials.' : 'No token is configured.'}
            </p>
            <Button type="button" variant="secondary" className="mt-3" onClick={regenerateSCIMToken} disabled={regeneratingSCIMToken}>
              <RotateCcw size={14} />
              {regeneratingSCIMToken ? 'Generating...' : 'Regenerate token'}
            </Button>
          </div>
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

      <GatewayTokenModal
        open={!!scimTokenModal}
        tokenInfo={scimTokenModal}
        title="SCIM provisioning token"
        tokenLabel={scimTokenModal?.providerName ? `Token for ${scimTokenModal.providerName}` : 'SCIM token'}
        warningText="Use these values in the SCIM connector. The token will not be shown again."
        copyTitle="Copy SCIM token"
        fields={[
          {
            key: 'organization-id',
            label: 'Organization ID',
            value: scimTokenModal?.organizationID || organizationID,
            copyTitle: 'Copy organization ID',
          },
        ]}
        onClose={closeSCIMTokenModal}
      />
    </div>
  );
}
