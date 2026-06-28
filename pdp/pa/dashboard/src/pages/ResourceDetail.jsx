import { useCallback, useEffect, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  AlertCircle,
  ArrowLeft,
  ChevronLeft,
  Edit2,
  Server,
  ShieldCheck,
} from 'lucide-react';
import {
  getDirectoryGroups,
  getGateways,
  getOrganizations,
  getPolicies,
  getPolicyAssignments,
  getResources,
  updateResource,
} from '../api';
import PageLoading from '../components/ui/PageLoading';
import {
  DetailEmptyState as EmptyState,
  InlineBackButton,
} from '../components/ui/Detail';
import Button from '../components/ui/Button';
import Modal from '../components/ui/Modal';
import FormField, { FormCheckbox, FormInput, FormSelect, FormTextarea } from '../components/ui/FormField';
import StatusText from '../components/ui/StatusText';
import OrganizationHierarchyFlow from '../components/organization/OrganizationHierarchyFlow';
import { layerIcons } from '../components/policies/policyIcons';
import { displayGatewayName, displayOrganizationName, displayResourceName } from '../utils/displayNames';
import { navigateBack } from '../utils/navigation';

const detailPanelClass = 'rounded-md border border-border bg-transparent';
const summaryItemClass = 'block w-full rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-4 py-4 text-left shadow-[0_8px_16px_rgba(42,42,42,0.12)] transition-[border-color,background-color,box-shadow] duration-150 hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.14)]';
const relatedSectionTitleClass = 'text-[20px] font-bold leading-tight text-text-primary';
const relatedSectionCountClass = 'text-sm font-bold text-text-muted';

function DetailField({ label, value, mono = false }) {
  return (
    <div className="min-w-0">
      <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-text-muted">{label}</p>
      <p className={`mt-2 truncate text-sm font-semibold text-text-primary ${mono ? 'text-mono' : ''}`}>
        {value === undefined || value === null || value === '' ? '-' : value}
      </p>
    </div>
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

function assignmentTypeLabel(assignment) {
  if (assignment?.level === 'resource_group') return 'Resource + Group';
  if (assignment?.level === 'resource') return 'Resource';
  return 'Policy';
}

function assignmentTargetText(resource, assignment, group) {
  if (assignment?.level === 'resource_group') {
    return `${displayResourceName(resource)} + ${group?.display_name || assignment.group_name || 'Group'}`;
  }
  return displayResourceName(resource);
}

function externalHost(resource) {
  return resource?.external_url || resource?.host || '';
}

function resourceExternalPort(resource) {
  return resource?.external_port || '';
}

function resourceInternalPort(resource) {
  return resource?.internal_port || '';
}

export default function ResourceDetail() {
  const { resourceId = '' } = useParams();
  const resourceID = decodeURIComponent(resourceId);
  const navigate = useNavigate();
  const location = useLocation();

  const [resource, setResource] = useState(null);
  const [gateway, setGateway] = useState(null);
  const [organization, setOrganization] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [assignments, setAssignments] = useState([]);
  const [directoryGroups, setDirectoryGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState({});
  const [editError, setEditError] = useState('');
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
      const organizationID = selectedResource?.organization_id || selectedGateway?.organization_id || selectedGateway?.organization_ids?.[0] || '';
      const [policyData, assignmentData, groupData] = organizationID ? await Promise.all([
        getPolicies().catch(() => []),
        getPolicyAssignments().catch(() => []),
        getDirectoryGroups(organizationID).catch(() => []),
      ]) : [[], [], []];

      setResource(selectedResource);
      setGateway(selectedGateway);
      setOrganization(organizations.find((item) => item.id === organizationID) || null);
      setPolicies(arrayFrom(policyData));
      setAssignments(arrayFrom(assignmentData));
      setDirectoryGroups(arrayFrom(groupData));
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
    ? `/gateways/${encodeURIComponent(gateway.id)}`
    : organization?.id
      ? `/organizations/${encodeURIComponent(organization.id)}`
      : '/resources';
  const handleBack = () => navigateBack(navigate, backTarget, location);

  const openEdit = () => {
    setEditError('');
    setEditForm({
      ...resource,
      external_port: resourceExternalPort(resource),
      internal_port: resourceInternalPort(resource),
    });
    setEditOpen(true);
  };

  const saveEdit = async () => {
    setEditSaving(true);
    setEditError('');
    const metadata = { ...(editForm.metadata || {}) };

    try {
      await updateResource(resource.id, {
        name: editForm.name?.trim(),
        description: editForm.description?.trim(),
        type: editForm.type,
        organization_id: editForm.organization_id,
        gateway_id: editForm.gateway_id,
        host: editForm.host?.trim(),
        external_port: parseInt(editForm.external_port, 10) || 0,
        internal_port: parseInt(editForm.internal_port, 10) || 0,
        external_url: editForm.external_url?.trim(),
        enabled: editForm.enabled !== false,
        metadata,
      });
      setEditOpen(false);
      await load();
    } catch (e) {
      setEditError(e.message || 'Failed to update resource');
    } finally {
      setEditSaving(false);
    }
  };

  if (loading) {
    return <PageLoading />;
  }

  if (!resource) {
    return (
      <div className="space-y-4">
        <InlineBackButton onClick={() => navigateBack(navigate, '/resources', location)}>
          <ArrowLeft size={15} />
          Resources
        </InlineBackButton>
        <EmptyState icon={Server} title="Resource not found" message={error || 'The selected resource no longer exists.'} />
      </div>
    );
  }

  const catalogFQDN = externalHost(resource);
  const externalPort = resourceExternalPort(resource);
  const internalPort = resourceInternalPort(resource);
  const policiesByID = new Map(policies.map((policy) => [policy.id, policy]));
  const resourceAssignments = assignments
    .filter((assignment) => assignment?.enabled !== false)
    .filter((assignment) => sameID(assignment.organization_id, resource.organization_id))
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
      };
    });
  const resourceWideAccess = resourceAssignments
    .filter((assignment) => assignment.level === 'resource')
    .map((assignment) => ({
      assignment,
      policy: policiesByID.get(assignment.policy_id),
    }));
  const hasExplicitAccessPolicy = resourceAssignments.length > 0;
  const policyCards = [
    ...groupAccess.map(({ assignment, group, policy }) => ({
      id: assignment.id,
      level: assignment.level,
      type: assignmentTypeLabel(assignment),
      policyName: policy?.name || assignment.policy_id || 'Policy',
      target: assignmentTargetText(resource, assignment, group),
    })),
    ...resourceWideAccess.map(({ assignment, policy }) => ({
      id: assignment.id,
      level: assignment.level,
      type: assignmentTypeLabel(assignment),
      policyName: policy?.name || assignment.policy_id || 'Policy',
      target: assignmentTargetText(resource, assignment, null),
    })),
  ];

  return (
    <div className="space-y-7">
      {error && <div className="rounded-md border border-danger bg-danger-muted p-3 text-sm text-danger">{error}</div>}

      <section className="space-y-5 pb-5 pr-3 pt-1">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                aria-label="Back"
                onClick={handleBack}
                className="-ml-2 inline-flex h-11 w-11 shrink-0 items-center justify-center text-text-primary transition-colors hover:text-accent focus-visible:text-accent active:text-accent-hover"
              >
                <ChevronLeft size={34} strokeWidth={3} />
              </button>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-3">
                  <h1 className="text-2xl font-bold leading-tight text-text-primary">{displayResourceName(resource)}</h1>
                  <StatusText variant={resource.enabled ? 'success' : 'danger'}>{resource.enabled ? 'Enabled' : 'Disabled'}</StatusText>
                </div>
              </div>
            </div>
            {resource.description && <p className="mt-4 max-w-3xl text-sm text-text-secondary">{resource.description}</p>}
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
          <h2 className={relatedSectionTitleClass}>Resources configuration</h2>
          <div className="mt-5 grid gap-x-8 gap-y-5 md:grid-cols-2 xl:grid-cols-3">
            <DetailField label="Type" value={String(resource.type || '-').toUpperCase()} />
            <DetailField label="External Host" value={catalogFQDN} mono />
            <DetailField label="External port" value={externalPort} mono />
            <DetailField label="Internal host" value={resource.host} mono />
            <DetailField label="Internal port" value={internalPort} mono />
            <DetailField label="Organization" value={displayOrganizationName(organization)} />
            <DetailField label="Gateway" value={gateway ? displayGatewayName(gateway) : '-'} />
          </div>
        </section>

        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
          <section className={`${detailPanelClass} min-h-[460px] overflow-hidden`} aria-label="Resource infrastructure">
            {organization?.id ? (
              <OrganizationHierarchyFlow
                organization={organization}
                gateways={gateway ? [gateway] : []}
                resources={[resource]}
                className="h-full min-h-[460px]"
              />
            ) : (
              <EmptyState icon={Server} title="No organization" message="This resource is not assigned to an organization." />
            )}
          </section>

          <aside className={`${detailPanelClass} min-h-[460px] p-5`}>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h2 className={relatedSectionTitleClass}>
                Policies <span className={relatedSectionCountClass}>({resourceAssignments.length})</span>
              </h2>
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
              <div className="mt-4 grid gap-3">
                {policyCards.map((card) => {
                  const TypeIcon = layerIcons[card.level] || ShieldCheck;
                  return (
                    <div key={card.id} className={summaryItemClass}>
                      <p className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.12em] text-accent">
                        <TypeIcon size={13} className="shrink-0" aria-hidden="true" />
                        <span>{card.type}</span>
                      </p>
                      <p className="mt-3 truncate text-base font-bold text-text-primary">{card.policyName}</p>
                      <p className="mt-2 truncate text-sm font-semibold text-text-secondary">{card.target}</p>
                    </div>
                  );
                })}
              </div>
            )}
          </aside>
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
        <div className="mb-4 min-h-6">
          {editError ? (
            <div className="flex items-center gap-2 text-sm font-semibold text-danger">
              <AlertCircle size={17} />
              <span>{editError}</span>
            </div>
          ) : null}
        </div>
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
          <FormField label="External Port" className="mb-0">
            <FormInput type="number" value={editForm.external_port || ''} onChange={(event) => setEditForm({ ...editForm, external_port: event.target.value })} />
          </FormField>
          <FormField label="Internal Port" className="mb-0">
            <FormInput type="number" value={editForm.internal_port || ''} onChange={(event) => setEditForm({ ...editForm, internal_port: event.target.value })} />
          </FormField>
          <FormField label="External Host" className="mb-0 md:col-span-2">
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
