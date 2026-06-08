import { useEffect, useState } from 'react';
import { Check, Info } from 'lucide-react';
import Button from '../ui/Button';
import FormField, { FormCheckbox, FormInput, FormSelect } from '../ui/FormField';
import Modal from '../ui/Modal';
import { layerIcons } from './policyIcons';
import {
  LAYERS,
  selectedCountForLayer,
  toggleListValue,
} from './policyModel';

function normalizedGroupName(group) {
  return String(group?.display_name || '').trim().toLowerCase();
}

function normalizedAssignmentGroupName(assignment, maps) {
  const group = assignment.group_id ? maps.groups?.get(assignment.group_id) : null;
  return String(group?.display_name || assignment.group_name || '').trim().toLowerCase();
}

function assignmentMatchesScope(assignment, form) {
  return assignment.policy_id === form.policy_id && assignment.tenant_id === form.tenant_id;
}

function repeatedGroupNames(groups) {
  const counts = new Map();
  groups.forEach((group) => {
    const name = normalizedGroupName(group);
    if (name) counts.set(name, (counts.get(name) || 0) + 1);
  });
  return new Set([...counts.entries()].filter(([, count]) => count > 1).map(([name]) => name));
}

function PolicyPrecedenceNote() {
  return (
    <section className="rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] p-4 shadow-[0_8px_16px_rgba(42,42,42,0.10)]">
      <div className="min-w-0">
        <h3 className="flex items-center gap-2 text-sm font-bold text-text-primary">
          <Info size={16} className="shrink-0 text-accent" />
          <span>Multiple policy evaluation</span>
        </h3>
        <p className="mt-1 text-sm leading-6 text-text-secondary">
          When multiple policies apply to the same access request, all matching policies are evaluated together.
          Final decision priority is Block access, then Require MFA, then Skip MFA, then Allow access.
        </p>
      </div>
    </section>
  );
}

function AssignmentTypeCard({ layer, selected, disabled = false, disabledReason = '', onSelect }) {
  const Icon = layerIcons[layer.value];
  return (
    <button
      type="button"
      disabled={disabled}
      title={disabledReason || layer.label}
      onClick={onSelect}
      className={`flex min-h-[150px] flex-col justify-between overflow-hidden rounded-md border text-left transition-[border-color,background-color,box-shadow,opacity] duration-150 ${
        selected
          ? 'border-accent bg-[rgba(44,97,100,0.12)] shadow-[0_10px_18px_rgba(42,42,42,0.14)]'
          : 'border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] shadow-[0_8px_16px_rgba(42,42,42,0.10)] hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.12)]'
      } ${
        disabled ? 'cursor-not-allowed opacity-55 hover:border-[rgba(44,97,100,0.55)] hover:bg-[rgba(44,97,100,0.045)] hover:shadow-[0_8px_16px_rgba(42,42,42,0.10)]' : ''
      }`}
    >
      <div className="p-4">
        <Icon size={28} className={selected ? 'text-accent' : 'text-text-secondary'} />
        <h4 className="mt-4 text-sm font-bold text-text-primary">{layer.label}</h4>
        <p className="mt-1 text-xs leading-5 text-text-secondary">{layer.description}</p>
      </div>
      <div className={`grid h-10 place-items-center border-t ${selected ? 'border-accent bg-[rgba(44,97,100,0.16)]' : 'border-[rgba(44,97,100,0.30)] bg-[rgba(44,97,100,0.08)]'}`}>
        <span className={`grid h-5 w-5 place-items-center rounded-full border ${selected ? 'border-accent bg-accent text-white-smoke' : 'border-border bg-surface-card'}`}>
          {selected && <Check size={13} strokeWidth={3} />}
        </span>
      </div>
    </button>
  );
}

const selectableTableRowClass = 'min-h-[72px] rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] shadow-[0_8px_16px_rgba(42,42,42,0.12)] transition-[border-color,background-color,box-shadow,opacity] duration-150 hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.14)]';
const selectableTableHeaderWrapClass = 'relative px-2 pr-5';
const selectableTableHeaderCellClass = "relative flex min-w-0 items-center justify-center px-4 py-4 text-center text-[11px] font-bold uppercase tracking-[0.14em] text-text-muted after:absolute after:bottom-[2px] after:right-0 after:h-5 after:w-[2px] after:bg-border after:content-[''] last:after:hidden";
const selectableTableScrollBaseClass = 'mt-3 overflow-y-scroll px-3 pb-5 pr-5 pt-1 [scrollbar-gutter:stable]';

function SelectableTable({
  title,
  countLabel,
  searchPlaceholder,
  items,
  selectedIDs,
  onToggle,
  columns,
  emptyMessage = 'No matches.',
  getDisabledReason = () => '',
  scrollHeightClass = 'h-[276px]',
}) {
  const [query, setQuery] = useState('');
  const filtered = items.filter((item) => {
    const needle = query.trim().toLowerCase();
    if (!needle) return true;
    return columns.some((column) => String(column.value(item) || '').toLowerCase().includes(needle));
  });
  const gridTemplateColumns = columns.map((column) => column.width || 'minmax(0, 1fr)').join(' ');

  return (
    <section className="rounded-md border border-[rgba(44,97,100,0.55)] bg-transparent p-4 shadow-[0_8px_16px_rgba(42,42,42,0.10)]">
      <div className="flex flex-wrap items-center gap-2">
        <h4 className="text-sm font-bold text-text-primary">{title}</h4>
        <span className="text-sm font-bold text-text-muted">({countLabel(selectedIDs.length)})</span>
      </div>

      <div className="mt-3">
        <FormInput
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={searchPlaceholder}
          className="border-border bg-surface font-bold shadow-sm hover:border-text-muted focus:ring-[3px]"
        />
      </div>

      <div className="mt-4 min-w-0">
        <div className={selectableTableHeaderWrapClass}>
          <div aria-hidden="true" className="pointer-events-none absolute bottom-0 left-2 right-5 h-[2px] bg-border" />
          <div className="grid" style={{ gridTemplateColumns }}>
            {columns.map((column) => (
              <div key={column.key} className={selectableTableHeaderCellClass}>
                {column.label}
              </div>
            ))}
          </div>
        </div>

        <div className={`${selectableTableScrollBaseClass} ${scrollHeightClass}`}>
          <div className="space-y-3 pb-1 pl-1">
            {filtered.map((item) => {
              const selected = selectedIDs.includes(item.id);
              const disabledReason = getDisabledReason(item);
              const disabled = !!disabledReason;
              return (
                <div
                  key={item.id}
                  className={`relative grid items-stretch ${selectableTableRowClass} ${
                    selected ? 'border-accent bg-[rgba(44,97,100,0.12)] shadow-[0_10px_18px_rgba(42,42,42,0.14)]' : ''
                  } ${
                    disabled ? 'cursor-not-allowed opacity-55 hover:border-[rgba(44,97,100,0.55)] hover:bg-[rgba(44,97,100,0.045)] hover:shadow-[0_8px_16px_rgba(42,42,42,0.12)]' : ''
                  }`}
                  style={{ gridTemplateColumns }}
                  title={disabledReason}
                >
                  <button
                    type="button"
                    disabled={disabled}
                    onClick={() => onToggle(item.id)}
                    aria-label={disabledReason || `Select ${item.id}`}
                    className={`absolute left-5 top-1/2 z-10 grid h-6 w-6 -translate-y-1/2 place-items-center rounded-full border transition-colors ${
                      selected ? 'border-accent bg-accent text-white-smoke' : 'border-border bg-surface-card text-transparent hover:border-accent'
                    } ${disabled ? 'cursor-not-allowed hover:border-border' : ''}`}
                  >
                    <Check size={13} strokeWidth={3} />
                  </button>
                  {columns.map((column) => (
                    <div key={column.key} className="flex min-w-0 items-center justify-center px-4 py-4 text-center text-xs font-semibold text-text-secondary first:pl-12">
                      {column.render ? column.render(item) : column.value(item)}
                    </div>
                  ))}
                </div>
              );
            })}
            {!filtered.length && (
              <div className={`${selectableTableRowClass} flex items-center justify-center px-4 py-8 text-center text-xs font-medium text-text-muted`}>
                {items.length ? 'No matches.' : emptyMessage}
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

export default function PolicyApplyModal({
  open,
  mode,
  form,
  setForm,
  policies,
  organizations,
  resourcesForAssignment,
  groupsForAssignment,
  assignments,
  maps,
  saving,
  onClose,
  onSave,
}) {
  const selectedPolicyID = form.policy_id || policies[0]?.id || '';
  const repeatedNames = repeatedGroupNames(groupsForAssignment);
  const policyScopedForm = { ...form, policy_id: selectedPolicyID };
  const selectedPolicyAssignments = assignments.filter((assignment) => assignment.policy_id === selectedPolicyID);
  const currentPolicyAssignments = selectedPolicyAssignments.filter((assignment) => assignmentMatchesScope(assignment, policyScopedForm));
  const selectedResourceIDs = form.resource_ids || [];
  const selectedGroupIDs = form.group_ids || [];
  const isOrganizationAssigned = currentPolicyAssignments.some((assignment) => assignment.level === 'organization');
  const isResourceAssigned = (resourceID) => currentPolicyAssignments.some((assignment) => (
    assignment.level === 'resource' && assignment.resource_id === resourceID
  ));
  const isGroupAssigned = (groupID) => currentPolicyAssignments.some((assignment) => (
    assignment.level === 'group' && assignment.group_id === groupID
  ));
  const isManualGroupAssigned = (groupName) => {
    const normalized = String(groupName || '').trim().toLowerCase();
    if (!normalized) return false;
    return currentPolicyAssignments.some((assignment) => (
      assignment.level === 'group' && normalizedAssignmentGroupName(assignment, maps) === normalized
    ));
  };
  const isResourceGroupAssigned = (resourceID, groupID) => currentPolicyAssignments.some((assignment) => (
    assignment.level === 'resource_group' &&
    assignment.resource_id === resourceID &&
    assignment.group_id === groupID
  ));
  const isManualResourceGroupAssigned = (resourceID, groupName) => {
    const normalized = String(groupName || '').trim().toLowerCase();
    if (!normalized) return false;
    return currentPolicyAssignments.some((assignment) => (
      assignment.level === 'resource_group' &&
      assignment.resource_id === resourceID &&
      normalizedAssignmentGroupName(assignment, maps) === normalized
    ));
  };
  const resourceDisabledReason = (resource) => {
    if (form.level === 'resource' && isResourceAssigned(resource.id)) {
      return 'This policy is already applied to this application.';
    }
    if (form.level === 'resource_group' && selectedGroupIDs.some((groupID) => isResourceGroupAssigned(resource.id, groupID))) {
      return 'This policy is already applied to this application-group combination.';
    }
    return '';
  };
  const groupDisabledReason = (group) => {
    if (form.level === 'group' && isGroupAssigned(group.id)) {
      return 'This policy is already applied to this user group.';
    }
    if (form.level === 'resource_group' && selectedResourceIDs.some((resourceID) => isResourceGroupAssigned(resourceID, group.id))) {
      return 'This policy is already applied to this application-group combination.';
    }
    return '';
  };
  const selectionBlocked =
    (form.level === 'organization' && isOrganizationAssigned) ||
    (form.level === 'resource' && selectedResourceIDs.some((resourceID) => isResourceAssigned(resourceID))) ||
    (form.level === 'group' && (
      selectedGroupIDs.some((groupID) => isGroupAssigned(groupID)) ||
      (!selectedGroupIDs.length && isManualGroupAssigned(form.group_name))
    )) ||
    (form.level === 'resource_group' && selectedResourceIDs.some((resourceID) => (
      selectedGroupIDs.some((groupID) => isResourceGroupAssigned(resourceID, groupID)) ||
      (!selectedGroupIDs.length && isManualResourceGroupAssigned(resourceID, form.group_name))
    )));
  const applyDisabled = saving || !selectedPolicyID || !form.tenant_id || selectedCountForLayer(form) === 0 || selectionBlocked;

  useEffect(() => {
    if (open && !form.policy_id && selectedPolicyID) {
      setForm((current) => current.policy_id ? current : { ...current, policy_id: selectedPolicyID });
    }
  }, [form.policy_id, open, selectedPolicyID, setForm]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={mode === 'edit' ? 'Replace Policy Assignment' : 'Apply Policy'}
      size="3xl"
      footer={(
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={onSave} disabled={applyDisabled}>
            {saving ? 'Saving...' : 'Apply Policy'}
          </Button>
        </>
      )}
    >
      <div className="grid gap-4 lg:grid-cols-2">
        <FormField label="Policy">
          <FormSelect
            value={selectedPolicyID}
            onChange={(event) => setForm({
              ...form,
              policy_id: event.target.value,
              resource_id: '',
              resource_ids: [],
              group_id: '',
              group_ids: [],
              group_name: '',
            })}
          >
            {policies.map((policy) => (
              <option key={policy.id} value={policy.id}>{policy.name}</option>
            ))}
          </FormSelect>
        </FormField>
        <FormField label="Organization">
          <FormSelect
            value={form.tenant_id}
            onChange={(event) => setForm({
              ...form,
              tenant_id: event.target.value,
              resource_id: '',
              resource_ids: [],
              group_id: '',
              group_ids: [],
              group_name: '',
            })}
          >
            <option value="">Select organization</option>
            {organizations.map((organization) => (
              <option key={organization.id} value={organization.id}>{organization.name}</option>
            ))}
          </FormSelect>
        </FormField>
      </div>

      <PolicyPrecedenceNote />

      <section className="rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] p-4 shadow-[0_8px_16px_rgba(42,42,42,0.10)]">
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <h3 className="text-base font-bold text-text-primary">Specify type</h3>
        </div>
        <div className="grid gap-4 lg:grid-cols-4">
          {LAYERS.map((layer) => (
            <AssignmentTypeCard
              key={layer.value}
              layer={layer}
              selected={form.level === layer.value}
              disabled={layer.value === 'organization' && isOrganizationAssigned}
              disabledReason={layer.value === 'organization' && isOrganizationAssigned ? 'This policy is already applied globally to this organization.' : ''}
              onSelect={() => setForm({
                ...form,
                level: layer.value,
                resource_id: '',
                resource_ids: [],
                group_id: '',
                group_ids: [],
                group_name: '',
              })}
            />
          ))}
        </div>
      </section>

      {['resource', 'resource_group'].includes(form.level) && (
        <SelectableTable
          title="Select Application"
          countLabel={(count) => `${count} APPLICATION${count === 1 ? '' : 'S'} SELECTED`}
          searchPlaceholder="Search by name"
          items={resourcesForAssignment}
          selectedIDs={form.resource_ids || []}
          getDisabledReason={resourceDisabledReason}
          onToggle={(resourceID) => {
            const nextIDs = toggleListValue(form.resource_ids, resourceID);
            setForm({ ...form, resource_ids: nextIDs, resource_id: nextIDs[0] || '' });
          }}
          emptyMessage={form.tenant_id ? 'No applications in this organization.' : 'Select an organization to list applications.'}
          columns={[
            {
              key: 'name',
              label: 'Name',
              width: 'minmax(0, 1.25fr)',
              value: (resource) => resource.name,
              render: (resource) => <span className="truncate font-bold text-accent">{resource.name}</span>,
            },
            {
              key: 'type',
              label: 'Type',
              width: '110px',
              value: (resource) => resource.type || 'resource',
            },
            {
              key: 'policy',
              label: 'Application policy',
              width: 'minmax(0, 1fr)',
              value: (resource) => {
                if (resourceDisabledReason(resource)) return 'Already applied';
                const existing = assignments.filter((assignment) => assignment.resource_id === resource.id && assignment.level === 'resource');
                return existing.length ? `${existing.length} assigned` : 'New policy';
              },
            },
          ]}
        />
      )}

      {['group', 'resource_group'].includes(form.level) && (
        <>
          <SelectableTable
            title="Select user groups"
            countLabel={(count) => `${count} GROUP${count === 1 ? '' : 'S'} SELECTED`}
            searchPlaceholder="Search groups"
            items={groupsForAssignment}
            selectedIDs={form.group_ids || []}
            getDisabledReason={groupDisabledReason}
            scrollHeightClass="h-[316px]"
            onToggle={(groupID) => {
              const nextIDs = toggleListValue(form.group_ids, groupID);
              const firstSelectedGroup = groupsForAssignment.find((group) => group.id === nextIDs[0]);
              setForm({
                ...form,
                group_ids: nextIDs,
                group_id: nextIDs[0] || '',
                group_name: nextIDs.length ? firstSelectedGroup?.display_name || form.group_name : '',
              });
            }}
            emptyMessage={form.tenant_id ? 'No synchronized groups in this organization.' : 'Select an organization to list groups.'}
            columns={[
              {
                key: 'name',
                label: 'Group',
                width: 'minmax(0, 1.6fr)',
                value: (group) => `${group.display_name || ''} ${group.external_id || ''} ${group.id || ''}`,
                render: (group) => (
                  <span className="block min-w-0">
                    <span className="flex min-w-0 flex-wrap items-center gap-2">
                      <span className="truncate font-bold text-accent">{group.display_name || group.id}</span>
                      {repeatedNames.has(normalizedGroupName(group)) && (
                        <span className="text-[10px] font-bold uppercase tracking-[0.08em] text-warning">
                          Same name
                        </span>
                      )}
                    </span>
                    <span className="mt-1 block truncate text-[11px] font-medium text-text-muted">
                      {group.external_id || group.id}
                    </span>
                  </span>
                ),
              },
              {
                key: 'members',
                label: 'Members',
                width: '120px',
                value: (group) => group.member_ids?.length || 0,
              },
              {
                key: 'policy',
                label: 'User-Group policy',
                width: 'minmax(0, 1.2fr)',
                value: (group) => {
                  if (groupDisabledReason(group)) return 'Already applied';
                  const existing = assignments.filter((assignment) => assignment.group_id === group.id && assignment.level === 'group');
                  return existing.length ? `${existing.length} assigned` : 'New policy';
                },
              },
            ]}
          />
        </>
      )}

      <FormCheckbox id="assignment-enabled" checked={form.enabled !== false} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} label="Assignment enabled" />
    </Modal>
  );
}
