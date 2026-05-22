import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Edit2,
  Server,
  ShieldCheck,
} from 'lucide-react';
import {
  getDirectoryGroups,
  getDirectoryUsers,
  getGateways,
  getOrganizations,
  getPolicies,
  getPolicyAssignments,
  getResources,
  updateResource,
} from '../api';
import Badge from '../components/ui/Badge';
import {
  BackIconButton,
  DetailDivider,
  DetailEmptyState as EmptyState,
  DetailSummaryItem,
  detailSectionTitleClass,
  InlineBackButton,
} from '../components/ui/Detail';
import Button from '../components/ui/Button';
import Modal from '../components/ui/Modal';
import FormField, { FormCheckbox, FormInput, FormSelect, FormTextarea } from '../components/ui/FormField';
import OrganizationHierarchyFlow from '../components/organization/OrganizationHierarchyFlow';
import { formatDateTime } from '../utils/format';
import { actionMeta } from '../components/policies/policyModel';

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

function arrayFrom(value) {
  return Array.isArray(value) ? value : [];
}

function sameID(left, right) {
  return String(left || '').trim().toLowerCase() === String(right || '').trim().toLowerCase();
}

function groupMatchesAssignment(group, assignment) {
  if (!group || !assignment) return false;
  return [group.id, group.external_id, group.display_name].some((value) => (
    sameID(value, assignment.group_id) || sameID(value, assignment.group_name)
  ));
}

function usersForGroup(group, usersByID) {
  return arrayFrom(group?.member_ids)
    .map((userID) => usersByID.get(userID))
    .filter(Boolean)
    .sort((left, right) => String(left.display_name || left.user_name || '').localeCompare(String(right.display_name || right.user_name || '')));
}

function policyVariant(action) {
  if (action === 'deny') return 'danger';
  if (action === 'mfa_required') return 'warning';
  return 'success';
}

function externalHost(resource) {
  const externalURL = resource?.external_url || '';
  if (externalURL.includes('://')) {
    try {
      return new URL(externalURL).hostname || externalURL;
    } catch {
      return externalURL;
    }
  }
  return externalURL || resource?.host || '';
}

export default function ResourceDetail() {
  const { resourceId = '' } = useParams();
  const resourceID = decodeURIComponent(resourceId);
  const navigate = useNavigate();

  const [resource, setResource] = useState(null);
  const [gateway, setGateway] = useState(null);
  const [organization, setOrganization] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [assignments, setAssignments] = useState([]);
  const [directoryGroups, setDirectoryGroups] = useState([]);
  const [directoryUsers, setDirectoryUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState({});
  const [editSaving, setEditSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [resourceData, gatewayData, organizationData] = await Promise.all([
        getResources(),
        getGateways(),
        getOrganizations(),
      ]);
      const resourceList = Array.isArray(resourceData) ? resourceData : [];
      const gatewayList = Array.isArray(gatewayData) ? gatewayData : [];
      const organizations = Array.isArray(organizationData) ? organizationData : [];
      const selectedResource = resourceList.find((item) => item.id === resourceID) || null;
      const selectedGateway = gatewayList.find((item) => item.id === selectedResource?.gateway_id) || null;
      const organizationID = selectedResource?.tenant_id || selectedGateway?.tenant_id || selectedGateway?.tenant_ids?.[0] || '';
      const [policyData, assignmentData, groupData, userData] = organizationID ? await Promise.all([
        getPolicies().catch(() => []),
        getPolicyAssignments().catch(() => []),
        getDirectoryGroups(organizationID).catch(() => []),
        getDirectoryUsers(organizationID).catch(() => []),
      ]) : [[], [], [], []];

      setResource(selectedResource);
      setGateway(selectedGateway);
      setOrganization(organizations.find((item) => item.id === organizationID) || null);
      setPolicies(arrayFrom(policyData));
      setAssignments(arrayFrom(assignmentData));
      setDirectoryGroups(arrayFrom(groupData));
      setDirectoryUsers(arrayFrom(userData));
    } catch (e) {
      setError(e.message || 'Failed to load resource data');
    } finally {
      setLoading(false);
    }
  }, [resourceID]);

  useEffect(() => {
    load();
  }, [load]);

  const backTarget = gateway?.id
    ? `/dashboard/gateways/${encodeURIComponent(gateway.id)}`
    : organization?.id
      ? `/dashboard/organizations/${encodeURIComponent(organization.id)}`
      : '/dashboard/resources';

  const openEdit = () => {
    setEditForm({ ...resource });
    setEditOpen(true);
  };

  const saveEdit = async () => {
    setEditSaving(true);
    setError('');
    const metadata = { ...(editForm.metadata || {}) };
    delete metadata.catalog_fqdn;

    try {
      await updateResource(resource.id, {
        name: editForm.name?.trim(),
        description: editForm.description?.trim(),
        type: editForm.type,
        tenant_id: editForm.tenant_id,
        gateway_id: editForm.gateway_id,
        host: editForm.host?.trim(),
        port: parseInt(editForm.port, 10) || 0,
        external_url: editForm.external_url?.trim(),
        enabled: editForm.enabled !== false,
        metadata,
      });
      setEditOpen(false);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to update resource');
    } finally {
      setEditSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="py-16 text-center text-text-muted">
        <span className="spinner mr-2" />
        Loading resource...
      </div>
    );
  }

  if (!resource) {
    return (
      <div className="space-y-4">
        <InlineBackButton onClick={() => navigate('/dashboard/resources')}>
          <ArrowLeft size={15} />
          Resources
        </InlineBackButton>
        <EmptyState icon={Server} title="Resource not found" message={error || 'The selected resource no longer exists.'} />
      </div>
    );
  }

  const target = `${resource.host || '-'}${resource.port ? `:${resource.port}` : ''}`;
  const catalogFQDN = externalHost(resource);
  const policiesByID = new Map(policies.map((policy) => [policy.id, policy]));
  const usersByID = new Map(directoryUsers.map((user) => [user.id, user]));
  const resourceAssignments = assignments
    .filter((assignment) => assignment?.enabled !== false)
    .filter((assignment) => sameID(assignment.tenant_id, resource.tenant_id))
    .filter((assignment) => ['resource', 'resource_group'].includes(assignment.level))
    .filter((assignment) => sameID(assignment.resource_id, resource.id));
  const groupAccess = resourceAssignments
    .filter((assignment) => assignment.level === 'resource_group')
    .map((assignment) => {
      const group = directoryGroups.find((item) => groupMatchesAssignment(item, assignment)) || null;
      const policy = policiesByID.get(assignment.policy_id);
      return {
        assignment,
        group,
        policy,
        users: usersForGroup(group, usersByID),
      };
    });
  const resourceWideAccess = resourceAssignments
    .filter((assignment) => assignment.level === 'resource')
    .map((assignment) => ({
      assignment,
      policy: policiesByID.get(assignment.policy_id),
    }));
  const hasExplicitAccessPolicy = resourceAssignments.length > 0;

  return (
    <div className="space-y-7">
      {error && <div className="rounded-md border border-danger bg-danger-muted p-3 text-sm text-danger">{error}</div>}

      <section className="p-5">
        <div className="space-y-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-start gap-3">
                <BackIconButton compact title="Back" onClick={() => navigate(backTarget)}>
                  <ArrowLeft size={16} />
                </BackIconButton>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-3">
                    <h1 className="text-2xl font-bold leading-tight text-text-primary">{resource.name || resource.id}</h1>
                    <Badge variant="info">{(resource.type || '-').toUpperCase()}</Badge>
                    <Badge variant={resource.enabled ? 'success' : 'danger'}>{resource.enabled ? 'Enabled' : 'Disabled'}</Badge>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
                    <span>{gateway?.name}</span>
                  </div>
                </div>
              </div>
              {resource.description && <p className="mt-4 max-w-3xl text-sm text-text-secondary">{resource.description}</p>}
            </div>
            <div className="flex flex-wrap items-center gap-2 lg:justify-end">
              <Button onClick={openEdit}>
                <Edit2 size={14} />
              </Button>
            </div>
          </div>
          <DetailDivider />

          <div>
            <p className={detailSectionTitleClass}>Resource Configuration</p>
            <div className="mt-2 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              <DetailValue label="Target" value={target} mono />
              <DetailValue label="External FQDN" value={catalogFQDN} mono />
              <DetailValue label="Certificate Mode" value={resource.cert_mode} />
              <DetailValue label="Certificate Domain" value={resource.cert_domain} mono />
              <DetailValue label="Certificate Expiry" value={formatDateTime(resource.cert_expiry)} />
            </div>
          </div>
          <DetailDivider />

          <div>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className={detailSectionTitleClass}>Access Policies</p>
              <Badge variant={hasExplicitAccessPolicy ? 'success' : 'danger'}>
                {hasExplicitAccessPolicy ? 'Explicit' : 'Deny Default'}
              </Badge>
            </div>

            {!hasExplicitAccessPolicy ? (
              <div className="mt-4">
                <EmptyState
                  icon={ShieldCheck}
                  title="No access policy assigned"
                  message="Access is denied by default for this resource."
                />
              </div>
            ) : (
              <div className="mt-4 space-y-3">
                {groupAccess.map(({ assignment, group, policy, users }) => (
                  <div key={assignment.id} className="rounded-md border border-border bg-surface-card p-4 shadow-surface">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-bold text-text-primary">{group?.display_name || assignment.group_name || assignment.group_id || 'Group'}</p>
                        <p className="mt-1 text-xs font-semibold text-text-muted">{policy?.name || assignment.policy_id}</p>
                      </div>
                      <Badge variant={policyVariant(policy?.action)}>{actionMeta(policy?.action).short}</Badge>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {users.length ? users.slice(0, 10).map((user) => (
                        <Badge key={user.id} variant={user.active === false ? 'danger' : 'neutral'} className="normal-case tracking-normal">
                          {user.display_name || user.user_name || user.email || user.id}
                        </Badge>
                      )) : (
                        <span className="text-xs font-semibold text-text-muted">No directory users in this group</span>
                      )}
                      {users.length > 10 && <Badge variant="neutral">+{users.length - 10}</Badge>}
                    </div>
                  </div>
                ))}

                {resourceWideAccess.map(({ assignment, policy }) => (
                  <div key={assignment.id} className="rounded-md border border-border bg-surface-card p-4 shadow-surface">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-bold text-text-primary">All eligible organization users</p>
                        <p className="mt-1 text-xs font-semibold text-text-muted">{policy?.name || assignment.policy_id}</p>
                      </div>
                      <Badge variant={policyVariant(policy?.action)}>{actionMeta(policy?.action).short}</Badge>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          <DetailDivider />

              <div>
                <h2 className={detailSectionTitleClass}>Resource Infrastructure</h2>
                <div className="mt-4">
                  <OrganizationHierarchyFlow
                    organization={organization}
                    gateways={gateway ? [gateway] : []}
                    resources={[resource]}
                  />
                </div>
              </div>
        </div>
      </section>

      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title="Edit Resource"
        size="2xl"
        footer={(
          <>
            <Button variant="secondary" onClick={() => setEditOpen(false)}>Cancel</Button>
            <Button onClick={saveEdit} disabled={editSaving || !editForm.name?.trim() || !editForm.gateway_id}>
              {editSaving ? 'Saving...' : 'Save Changes'}
            </Button>
          </>
        )}
      >
        <div className="grid gap-x-4 gap-y-3 md:grid-cols-2">
          <FormField label="Name" className="mb-0">
            <FormInput value={editForm.name || ''} onChange={(event) => setEditForm({ ...editForm, name: event.target.value })} />
          </FormField>
          <FormField label="Type" className="mb-0">
            <FormSelect value={editForm.type || 'web'} onChange={(event) => setEditForm({ ...editForm, type: event.target.value })}>
              <option value="web">WEB</option>
              <option value="ssh">SSH</option>
              <option value="rdp">RDP</option>
            </FormSelect>
          </FormField>
          <FormField label="Description" className="mb-0 md:col-span-2">
            <FormTextarea value={editForm.description || ''} onChange={(event) => setEditForm({ ...editForm, description: event.target.value })} />
          </FormField>
          <FormField label="Internal Host" className="mb-0">
            <FormInput value={editForm.host || ''} onChange={(event) => setEditForm({ ...editForm, host: event.target.value })} />
          </FormField>
          <FormField label="Port" className="mb-0">
            <FormInput type="number" value={editForm.port || ''} onChange={(event) => setEditForm({ ...editForm, port: event.target.value })} />
          </FormField>
          <FormField label="External URL" className="mb-0 md:col-span-2">
            <FormInput value={editForm.external_url || ''} onChange={(event) => setEditForm({ ...editForm, external_url: event.target.value })} />
          </FormField>
          <div className="md:col-span-2">
            <FormCheckbox id="resource-detail-enabled" checked={editForm.enabled !== false} onChange={(event) => setEditForm({ ...editForm, enabled: event.target.checked })} label="Enabled" />
          </div>
        </div>
      </Modal>
    </div>
  );
}
