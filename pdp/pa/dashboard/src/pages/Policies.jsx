import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  createPolicy,
  createPolicyAssignment,
  deletePolicy,
  deletePolicyAssignment,
  getDirectoryGroups,
  getDeviceDataReports,
  getIdPs,
  getOrganizations,
  getPolicies,
  getPolicyAssignments,
  getResources,
  updatePolicy,
} from '../api';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import PageHeader from '../components/ui/PageHeader';
import Pagination from '../components/ui/Pagination';
import ConfirmDialog from '../components/ui/ConfirmDialog';
import PolicyApplyModal from '../components/policies/PolicyApplyModal';
import PolicyEditor from '../components/policies/PolicyEditor';
import PolicyList from '../components/policies/PolicyList';
import PolicyUnassignModal from '../components/policies/PolicyUnassignModal';
import { usePaginatedTable } from '../components/ui/usePaginatedTable';
import {
  EMPTY_ASSIGNMENT_FORM,
  EMPTY_POLICY_FORM,
  LAYERS,
  actionFromAuthenticationPolicy,
  conditionSummary,
  conditionsFromForm,
  createUserLocationRule,
  deviceCheckOptionsFromReports,
  inferEnabledSections,
  policyFormFromRule,
} from '../components/policies/policyModel';

function formAfterSectionToggle(form, sectionID, enabled) {
  if (enabled) {
    if (sectionID === 'newuser') {
      return { ...form, new_user_policy: form.new_user_policy || 'require_enrollment' };
    }
    if (sectionID === 'riskbasedauth') {
      return { ...form, risk_auth_enabled: true };
    }
    if (sectionID === 'devicehealth') {
      return { ...form, required_check_status: form.required_check_status || 'good' };
    }
    return form;
  }

  switch (sectionID) {
    case 'newuser':
      return { ...form, new_user_policy: '' };
    case 'riskbasedauth':
      return { ...form, risk_auth_enabled: false };
    case 'location':
      return {
        ...form,
        user_location_rules: [createUserLocationRule()],
        user_location_default_action: 'allow',
        user_location_unknown_action: 'allow',
        user_location_check_mode: 'access_device_only',
        access_new_location: false,
        access_impossible_travel: false,
      };
    case 'devicehealth':
      return {
        ...form,
        required_checks: '',
        required_check_status: 'good',
      };
    case 'authorizednetworks':
      return {
        ...form,
        network_allowed_cidrs: [],
        network_skip_mfa_cidrs: [],
        network_require_mfa_cidrs: [],
        network_blocked_cidrs: [],
        network_deny_other: false,
      };
    default:
      return form;
  }
}

export default function Policies() {
  const [searchParams] = useSearchParams();
  const [policies, setPolicies] = useState([]);
  const [assignments, setAssignments] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [idps, setIdPs] = useState([]);
  const [resources, setResources] = useState([]);
  const [groups, setGroups] = useState([]);
  const [deviceCheckOptions, setDeviceCheckOptions] = useState(deviceCheckOptionsFromReports());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [levelFilter, setLevelFilter] = useState('all');
  const [editor, setEditor] = useState(null);
  const [assignmentModal, setAssignmentModal] = useState(null);
  const [deletePolicyTarget, setDeletePolicyTarget] = useState(null);
  const [unassignPolicyTarget, setUnassignPolicyTarget] = useState(null);
  const [policyForm, setPolicyForm] = useState(EMPTY_POLICY_FORM);
  const [assignmentForm, setAssignmentForm] = useState(EMPTY_ASSIGNMENT_FORM);

  const maps = useMemo(() => ({
    policies: new Map(policies.map((policy) => [policy.id, policy])),
    organizations: new Map(organizations.map((organization) => [organization.id, organization])),
    idps: new Map(idps.map((idp) => [idp.id, idp])),
    resources: new Map(resources.map((resource) => [resource.id, resource])),
    groups: new Map(groups.map((group) => [group.id, group])),
  }), [policies, organizations, idps, resources, groups]);

  const defaultOrganizationID = useMemo(
    () => searchParams.get('organization_id') || organizations[0]?.id || '',
    [organizations, searchParams],
  );

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [policyData, assignmentData, organizationData, resourceData, groupData, deviceData] = await Promise.all([
        getPolicies(),
        getPolicyAssignments(),
        getOrganizations(),
        getResources(),
        getDirectoryGroups(),
        getDeviceDataReports().catch(() => []),
      ]);
      const organizationList = Array.isArray(organizationData) ? organizationData : [];
      const idpLists = await Promise.all(
        organizationList.map((organization) => (
          getIdPs(organization.id).catch(() => [])
        )),
      );
      setPolicies(Array.isArray(policyData) ? policyData : []);
      setAssignments(Array.isArray(assignmentData) ? assignmentData : []);
      setOrganizations(organizationList);
      setIdPs(idpLists.flat().filter(Boolean));
      setResources(Array.isArray(resourceData) ? resourceData : []);
      setGroups(Array.isArray(groupData) ? groupData : []);
      setDeviceCheckOptions(deviceCheckOptionsFromReports(Array.isArray(deviceData) ? deviceData : []));
    } catch (e) {
      setError(e.message || 'Failed to load policies');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const assignmentsForPolicy = useCallback(
    (policyID) => assignments.filter((assignment) => assignment.policy_id === policyID),
    [assignments],
  );

  const filteredPolicies = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return policies
      .filter((policy) => {
        const policyAssignments = assignmentsForPolicy(policy.id);
        if (levelFilter !== 'all' && !policyAssignments.some((assignment) => assignment.level === levelFilter)) return false;
        if (!needle) return true;
        return [
          policy.name,
          policy.description,
          policy.action,
          ...conditionSummary(policy),
        ].some((value) => String(value || '').toLowerCase().includes(needle));
      })
      .sort((left, right) => String(left.name || '').localeCompare(String(right.name || '')));
  }, [policies, assignmentsForPolicy, query, levelFilter]);

  const openPolicyEditor = (mode, policy = null) => {
    const form = policy ? policyFormFromRule(policy) : EMPTY_POLICY_FORM;
    setPolicyForm(form);
    setEditor({
      mode,
      policyID: policy?.id || '',
      activeSection: 'details',
      enabledSections: inferEnabledSections(form),
    });
  };

  const toggleEditorSection = (sectionID, value) => {
    setPolicyForm((current) => formAfterSectionToggle(current, sectionID, !!value));
    setEditor((current) => ({
      ...current,
      enabledSections: {
        ...current.enabledSections,
        [sectionID]: value,
      },
    }));
  };

  const handleSavePolicy = async () => {
    setSaving(true);
    setError('');
    const payload = {
      name: policyForm.name.trim(),
      description: policyForm.description.trim(),
      enabled: policyForm.enabled !== false,
      action: actionFromAuthenticationPolicy(policyForm.authentication_policy || 'enforce_mfa'),
      conditions: conditionsFromForm(policyForm),
    };
    try {
      if (editor?.mode === 'edit') {
        await updatePolicy(policyForm.id, payload);
      } else {
        await createPolicy(payload);
      }
      setEditor(null);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to save policy');
    } finally {
      setSaving(false);
    }
  };

  const handleDuplicatePolicy = async (policy) => {
    setError('');
    try {
      await createPolicy({
        name: `${policy.name} copy`,
        description: policy.description || '',
        enabled: false,
        action: policy.action || 'allow',
        conditions: policy.conditions || {},
      });
      await load();
    } catch (e) {
      setError(e.message || 'Failed to duplicate policy');
    }
  };

  const openAssignmentCreate = (policy = null) => {
    setAssignmentForm({
      ...EMPTY_ASSIGNMENT_FORM,
      policy_id: policy?.id || policies[0]?.id || '',
      tenant_id: defaultOrganizationID,
      resource_ids: [],
      group_ids: [],
    });
    setAssignmentModal('create');
  };

  const handleSaveAssignment = async () => {
    setSaving(true);
    setError('');
    const selectedResourceIDs = assignmentForm.resource_ids?.length
      ? assignmentForm.resource_ids
      : (assignmentForm.resource_id ? [assignmentForm.resource_id] : []);
    const selectedGroupIDs = assignmentForm.group_ids?.length
      ? assignmentForm.group_ids
      : (assignmentForm.group_id ? [assignmentForm.group_id] : []);
    const groupTargets = selectedGroupIDs.map((groupID) => {
      const group = groups.find((item) => item.id === groupID);
      return { id: groupID, name: group?.display_name || assignmentForm.group_name || groupID };
    });
    if (!groupTargets.length && assignmentForm.group_name?.trim()) {
      groupTargets.push({ id: '', name: assignmentForm.group_name.trim() });
    }
    const resourceTargets = selectedResourceIDs.map((resourceID) => ({ id: resourceID }));

    if (['resource', 'resource_group'].includes(assignmentForm.level) && !resourceTargets.length) {
      setError('Select at least one resource.');
      setSaving(false);
      return;
    }
    if (['group', 'resource_group'].includes(assignmentForm.level) && !groupTargets.length) {
      setError('Select at least one group.');
      setSaving(false);
      return;
    }

    const makePayload = ({ resourceID = '', groupID = '', groupName = '' } = {}) => ({
      policy_id: assignmentForm.policy_id,
      organization_id: assignmentForm.tenant_id,
      level: assignmentForm.level,
      resource_id: ['resource', 'resource_group'].includes(assignmentForm.level) ? resourceID : '',
      group_id: ['group', 'resource_group'].includes(assignmentForm.level) ? groupID : '',
      group_name: ['group', 'resource_group'].includes(assignmentForm.level) ? groupName : '',
      order_placement: '',
      enabled: assignmentForm.enabled !== false,
    });

    let payloads = [makePayload()];
    if (assignmentForm.level === 'resource') {
      payloads = resourceTargets.map((resource) => makePayload({ resourceID: resource.id }));
    } else if (assignmentForm.level === 'group') {
      payloads = groupTargets.map((group) => makePayload({ groupID: group.id, groupName: group.name }));
    } else if (assignmentForm.level === 'resource_group') {
      payloads = resourceTargets.flatMap((resource) => groupTargets.map((group) => (
        makePayload({ resourceID: resource.id, groupID: group.id, groupName: group.name })
      )));
    }

    try {
      await Promise.all(payloads.map((payload) => createPolicyAssignment(payload)));
      setAssignmentModal(null);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to save policy assignment');
    } finally {
      setSaving(false);
    }
  };

  const confirmDeletePolicy = async () => {
    if (!deletePolicyTarget) return;
    setError('');
    setSaving(true);
    try {
      await deletePolicy(deletePolicyTarget.id);
      setDeletePolicyTarget(null);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to delete policy');
    } finally {
      setSaving(false);
    }
  };

  const handleUnassignAssignment = async (assignment) => {
    if (!assignment) return;
    setError('');
    setSaving(true);
    try {
      await deletePolicyAssignment(assignment.id);
      await load();
    } catch (e) {
      setError(e.message || 'Failed to unassign policy');
    } finally {
      setSaving(false);
    }
  };

  const resourcesForAssignment = resources.filter((resource) => resource.tenant_id === assignmentForm.tenant_id);
  const groupsForAssignment = groups.filter((group) => group.tenant_id === assignmentForm.tenant_id);
  const policyPagination = usePaginatedTable(filteredPolicies);
  const compactCount = `${filteredPolicies.length} ${filteredPolicies.length === 1 ? 'policy' : 'policies'}`;

  const handleQueryChange = (value) => {
    setQuery(value);
    policyPagination.resetPage();
  };

  const handleLevelFilterChange = (value) => {
    setLevelFilter(value);
    policyPagination.resetPage();
  };

  if (editor) {
    return (
      <PolicyEditor
        editor={editor}
        form={policyForm}
        setForm={setPolicyForm}
        assignments={assignmentsForPolicy(editor.policyID)}
        maps={maps}
        deviceCheckOptions={deviceCheckOptions}
        saving={saving}
        onBack={() => setEditor(null)}
        onSave={handleSavePolicy}
        onToggleSection={toggleEditorSection}
        onSelectSection={(activeSection) => setEditor((current) => ({ ...current, activeSection }))}
      />
    );
  }

  return (
    <div className="space-y-4 pb-8">
      <PageHeader
        title="Policies"
        subtitle="Manage access control policies and their assignments"
        createLabel="Add Policy"
        onCreate={() => openPolicyEditor('create')}
      />

      {error && (
        <div className="rounded-md border border-danger bg-danger-muted px-4 py-3 text-sm font-semibold text-danger">
          {error}
        </div>
      )}

      <ListToolbar
        query={query}
        onQueryChange={handleQueryChange}
        placeholder="Search policy, rule, application, or group"
        summary={compactCount}
      >
        <ListToolbarSelect value={levelFilter} onChange={handleLevelFilterChange} className="lg:min-w-[230px]">
          <option value="all">Policy apply type</option>
          {LAYERS.map((layer) => (
            <option key={layer.value} value={layer.value}>{layer.label}</option>
          ))}
        </ListToolbarSelect>
      </ListToolbar>

      <PolicyList
        policies={policyPagination.pageItems}
        loading={loading}
        pageSize={policyPagination.pageSize}
        assignmentsForPolicy={assignmentsForPolicy}
        maps={maps}
        onEdit={(policy) => openPolicyEditor('edit', policy)}
        onApply={openAssignmentCreate}
        onDuplicate={handleDuplicatePolicy}
        onUnassign={setUnassignPolicyTarget}
        onDelete={setDeletePolicyTarget}
      />

      {/* <div className="pt-2">
        <Pagination
          currentPage={policyPagination.currentPage}
          totalPages={policyPagination.totalPages}
          onPageChange={policyPagination.setCurrentPage}
        />
      </div> */}

      <PolicyApplyModal
        open={!!assignmentModal}
        mode={assignmentModal}
        form={assignmentForm}
        setForm={setAssignmentForm}
        policies={policies}
        organizations={organizations}
        resourcesForAssignment={resourcesForAssignment}
        groupsForAssignment={groupsForAssignment}
        assignments={assignments}
        maps={maps}
        saving={saving}
        onClose={() => setAssignmentModal(null)}
        onSave={handleSaveAssignment}
      />

      <PolicyUnassignModal
        open={!!unassignPolicyTarget}
        policy={unassignPolicyTarget}
        assignments={unassignPolicyTarget ? assignmentsForPolicy(unassignPolicyTarget.id) : []}
        maps={maps}
        saving={saving}
        onClose={() => setUnassignPolicyTarget(null)}
        onUnassign={handleUnassignAssignment}
      />

      <ConfirmDialog
        open={!!deletePolicyTarget}
        onClose={() => setDeletePolicyTarget(null)}
        onConfirm={confirmDeletePolicy}
        title="Delete policy"
        message={deletePolicyTarget ? `Delete "${deletePolicyTarget.name}" and all of its assignments? This cannot be undone.` : ''}
        confirmLabel="Delete policy"
        loading={saving}
      />
    </div>
  );
}
