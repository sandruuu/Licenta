import { createElement, useState } from 'react';
import { Building2, CheckCircle2, Info, KeyRound, Users } from 'lucide-react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import FormField, { FormCheckbox, FormInput, FormSelect } from '../ui/FormField';
import Modal from '../ui/Modal';
import { layerIcons } from './policyIcons';
import {
  LAYERS,
  layerMeta,
  selectedCountForLayer,
  toggleListValue,
} from './policyModel';

function normalizedGroupName(group) {
  return String(group?.display_name || '').trim().toLowerCase();
}

function repeatedGroupNames(groups) {
  const counts = new Map();
  groups.forEach((group) => {
    const name = normalizedGroupName(group);
    if (name) counts.set(name, (counts.get(name) || 0) + 1);
  });
  return new Set([...counts.entries()].filter(([, count]) => count > 1).map(([name]) => name));
}

function idpsForOrganization(maps, tenantID) {
  return Array.from(maps.idps?.values?.() || []).filter((idp) => idp.tenant_id === tenantID);
}

function idpForGroup(group, maps) {
  return group?.idp_id ? maps.idps?.get(group.idp_id) : null;
}

function defaultIdPForSelection(form, maps, groupsForAssignment) {
  const organization = maps.organizations.get(form.tenant_id);
  const configured = organization?.default_idp_id ? maps.idps?.get(organization.default_idp_id) : null;
  if (configured) return configured;
  const organizationIdPs = idpsForOrganization(maps, form.tenant_id);
  if (organizationIdPs.length === 1) return organizationIdPs[0];
  const firstGroupIdP = groupsForAssignment[0]?.idp_id ? maps.idps?.get(groupsForAssignment[0].idp_id) : null;
  return firstGroupIdP || null;
}

function ContextItem({ icon, label, value, detail }) {
  return (
    <div className="flex min-w-0 items-start gap-3 rounded-md border border-border-light bg-surface-card px-4 py-3">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md bg-surface-secondary text-text-secondary">
        {createElement(icon, { size: 16 })}
      </span>
      <span className="min-w-0">
        <span className="block text-[10px] font-bold uppercase tracking-[0.12em] text-text-muted">{label}</span>
        <span className="mt-1 block truncate text-sm font-bold text-text-primary">{value || '-'}</span>
        {detail && <span className="mt-0.5 block truncate text-xs text-text-secondary">{detail}</span>}
      </span>
    </div>
  );
}

function ScopeContext({ form, maps, groupsForAssignment }) {
  const organization = maps.organizations.get(form.tenant_id);
  const organizationIdPs = idpsForOrganization(maps, form.tenant_id);
  const selectedIdP = defaultIdPForSelection(form, maps, groupsForAssignment);
  const idpValue = organizationIdPs.length > 1
    ? `${organizationIdPs.length} identity providers`
    : selectedIdP?.name || groupsForAssignment[0]?.idp_id || 'No IdP configured';
  const idpDetail = organizationIdPs.length > 1
    ? organizationIdPs.map((idp) => idp.name || idp.id).join(', ')
    : selectedIdP?.issuer || selectedIdP?.id || '';

  return (
    <section className="rounded-md border border-border bg-surface p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <h3 className="text-base font-bold text-text-primary">Assignment context</h3>
        <Badge variant={form.tenant_id ? 'accent' : 'neutral'}>{form.tenant_id ? 'Scoped' : 'No organization'}</Badge>
      </div>
      <div className="grid gap-3 lg:grid-cols-3">
        <ContextItem
          icon={Building2}
          label="Organization"
          value={organization?.name || form.tenant_id || 'Select organization'}
          detail={organization?.domain || organization?.id || ''}
        />
        <ContextItem
          icon={KeyRound}
          label="Identity provider"
          value={idpValue}
          detail={idpDetail}
        />
        <ContextItem
          icon={Users}
          label="Directory groups"
          value={`${groupsForAssignment.length} synced group${groupsForAssignment.length === 1 ? '' : 's'}`}
          detail={groupsForAssignment[0]?.idp_id ? 'SCIM directory' : ''}
        />
      </div>
    </section>
  );
}

function PolicyPrecedenceNote() {
  return (
    <section className="flex items-start gap-3 rounded-md border border-border bg-surface p-4">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md bg-accent-muted text-accent">
        <Info size={16} />
      </span>
      <div className="min-w-0">
        <h3 className="text-sm font-bold text-text-primary">Multiple policy evaluation</h3>
        <p className="mt-1 text-sm leading-6 text-text-secondary">
          When multiple policies apply to the same access request, all matching policies are evaluated together.
          Final decision priority is Block access, then Require MFA, then Skip MFA, then Allow access.
        </p>
      </div>
    </section>
  );
}

function AssignmentTypeCard({ layer, selected, onSelect }) {
  const Icon = layerIcons[layer.value];
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`flex min-h-[150px] flex-col justify-between rounded-md border text-left transition-colors ${
        selected ? 'border-accent bg-accent-muted shadow-accent' : 'border-border bg-surface-card hover:border-accent hover:bg-surface-hover'
      }`}
    >
      <div className="p-4">
        <Icon size={28} className={selected ? 'text-accent' : 'text-text-secondary'} />
        <h4 className="mt-4 text-sm font-bold text-text-primary">{layer.label}</h4>
        <p className="mt-1 text-xs leading-5 text-text-secondary">{layer.description}</p>
      </div>
      <div className={`grid h-10 place-items-center border-t ${selected ? 'border-accent bg-accent-muted' : 'border-border bg-surface-secondary'}`}>
        <span className={`grid h-5 w-5 place-items-center rounded-full border ${selected ? 'border-accent bg-accent text-white-smoke' : 'border-border bg-surface-card'}`}>
          {selected && <CheckCircle2 size={13} />}
        </span>
      </div>
    </button>
  );
}

function SelectableTable({ title, countLabel, searchPlaceholder, items, selectedIDs, onToggle, columns, emptyMessage = 'No matches.' }) {
  const [query, setQuery] = useState('');
  const filtered = items.filter((item) => {
    const needle = query.trim().toLowerCase();
    if (!needle) return true;
    return columns.some((column) => String(column.value(item) || '').toLowerCase().includes(needle));
  });

  return (
    <div className="rounded-md border border-border bg-surface-card">
      <div className="border-b border-border p-4">
        <div className="flex flex-wrap items-center gap-2">
          <h4 className="text-sm font-bold text-text-primary">{title}</h4>
          <Badge variant={selectedIDs.length ? 'accent' : 'neutral'}>{countLabel(selectedIDs.length)}</Badge>
        </div>
        <div className="mt-3">
          <FormInput
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={searchPlaceholder}
            className="border-border bg-surface font-bold shadow-sm hover:border-text-muted focus:ring-[3px]"
          />
        </div>
      </div>
      <div className="max-h-[280px] overflow-y-auto">
        <table className="w-full">
          <thead className="sticky top-0 bg-surface-secondary">
            <tr className="border-b border-border">
              <th className="w-12 px-4 py-3 text-left">
                <span className="sr-only">Select</span>
              </th>
              {columns.map((column) => (
                <th key={column.key} className="px-4 py-3 text-left text-[10px] font-bold uppercase tracking-[0.12em] text-text-muted">
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((item) => {
              const selected = selectedIDs.includes(item.id);
              return (
                <tr key={item.id} className={`border-b border-border last:border-b-0 ${selected ? 'bg-accent-muted' : 'hover:bg-surface-hover'}`}>
                  <td className="px-4 py-3">
                    <button
                      type="button"
                      onClick={() => onToggle(item.id)}
                      className={`grid h-5 w-5 place-items-center rounded border ${
                        selected ? 'border-accent bg-accent text-white-smoke' : 'border-border bg-surface-card text-transparent'
                      }`}
                    >
                      <CheckCircle2 size={13} />
                    </button>
                  </td>
                  {columns.map((column) => (
                    <td key={column.key} className="px-4 py-3 text-xs font-semibold text-text-secondary">
                      {column.render ? column.render(item) : column.value(item)}
                    </td>
                  ))}
                </tr>
              );
            })}
            {!filtered.length && (
              <tr>
                <td colSpan={columns.length + 1} className="px-4 py-8 text-center text-xs font-medium text-text-muted">
                  {items.length ? 'No matches.' : emptyMessage}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
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
  const repeatedNames = repeatedGroupNames(groupsForAssignment);
  const selectedOrganization = maps.organizations.get(form.tenant_id);
  const selectedIdP = defaultIdPForSelection(form, maps, groupsForAssignment);
  const manualGroupScope = form.tenant_id
    ? [selectedOrganization?.name || form.tenant_id, selectedIdP?.name || selectedIdP?.id].filter(Boolean).join(' / ')
    : '';

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={mode === 'edit' ? 'Replace Policy Assignment' : 'Apply Policy'}
      size="3xl"
      footer={(
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={onSave} disabled={saving || !form.policy_id || !form.tenant_id || selectedCountForLayer(form) === 0}>
            {saving ? 'Saving...' : 'Apply Policy'}
          </Button>
        </>
      )}
    >
      <div className="grid gap-4 lg:grid-cols-2">
        <FormField label="Policy">
          <FormSelect value={form.policy_id} onChange={(event) => setForm({ ...form, policy_id: event.target.value })}>
            <option value="">Select policy</option>
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

      <ScopeContext form={form} maps={maps} groupsForAssignment={groupsForAssignment} />

      <PolicyPrecedenceNote />

      <section className="rounded-md border border-border bg-surface p-4">
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <h3 className="text-base font-bold text-text-primary">Specify type</h3>
          <Badge variant="neutral">{layerMeta(form.level).label}</Badge>
        </div>
        <div className="grid gap-4 lg:grid-cols-4">
          {LAYERS.map((layer) => (
            <AssignmentTypeCard
              key={layer.value}
              layer={layer}
              selected={form.level === layer.value}
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

      <FormField label="Selected targets">
        <div className="flex h-[38px] items-center rounded-md border border-border bg-surface px-3 text-sm font-bold text-text-primary">
          {selectedCountForLayer(form)} selected
        </div>
      </FormField>

      {['resource', 'resource_group'].includes(form.level) && (
        <SelectableTable
          title="Select Application"
          countLabel={(count) => `${count} application${count === 1 ? '' : 's'} selected`}
          searchPlaceholder="Search by name or key"
          items={resourcesForAssignment}
          selectedIDs={form.resource_ids || []}
          onToggle={(resourceID) => {
            const nextIDs = toggleListValue(form.resource_ids, resourceID);
            setForm({ ...form, resource_ids: nextIDs, resource_id: nextIDs[0] || '' });
          }}
          emptyMessage={form.tenant_id ? 'No applications in this organization.' : 'Select an organization to list applications.'}
          columns={[
            { key: 'name', label: 'Name', value: (resource) => resource.name, render: (resource) => <span className="font-bold text-accent">{resource.name}</span> },
            { key: 'type', label: 'Type', value: (resource) => resource.type || 'resource' },
            {
              key: 'policy',
              label: 'Application policy',
              value: (resource) => {
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
            countLabel={(count) => `${count} group${count === 1 ? '' : 's'} selected`}
            searchPlaceholder="Search groups"
            items={groupsForAssignment}
            selectedIDs={form.group_ids || []}
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
                value: (group) => `${group.display_name || ''} ${group.external_id || ''} ${group.id || ''}`,
                render: (group) => (
                  <span className="block min-w-0">
                    <span className="flex min-w-0 flex-wrap items-center gap-2">
                      <span className="truncate font-bold text-accent">{group.display_name || group.id}</span>
                      {repeatedNames.has(normalizedGroupName(group)) && <Badge variant="warning">Same name</Badge>}
                    </span>
                    <span className="mt-1 block truncate text-[11px] font-medium text-text-muted">
                      {group.external_id || group.id}
                    </span>
                  </span>
                ),
              },
              {
                key: 'source',
                label: 'Organization / IdP',
                value: (group) => {
                  const idp = idpForGroup(group, maps);
                  const organization = maps.organizations.get(group.tenant_id);
                  return `${organization?.name || group.tenant_id || ''} ${idp?.name || group.idp_id || ''} ${idp?.issuer || ''}`;
                },
                render: (group) => {
                  const idp = idpForGroup(group, maps);
                  const organization = maps.organizations.get(group.tenant_id);
                  return (
                    <span className="block min-w-0">
                      <span className="block truncate font-semibold text-text-primary">{organization?.name || group.tenant_id || '-'}</span>
                      <span className="mt-1 block truncate text-[11px] text-text-secondary">{idp?.name || group.idp_id || 'Identity provider'}</span>
                    </span>
                  );
                },
              },
              { key: 'members', label: 'Members', value: (group) => group.member_ids?.length || 0 },
              {
                key: 'policy',
                label: 'User-Group policy',
                value: (group) => {
                  const existing = assignments.filter((assignment) => assignment.group_id === group.id && assignment.level === 'group');
                  return existing.length ? `${existing.length} assigned` : 'New policy';
                },
              },
            ]}
          />
          <FormField
            label="Manual group name"
            hint={manualGroupScope ? `Scoped to ${manualGroupScope}.` : 'Scoped after an organization is selected.'}
          >
            <FormInput value={form.group_name} onChange={(event) => setForm({ ...form, group_name: event.target.value })} placeholder="Finance" />
          </FormField>
        </>
      )}

      <FormCheckbox id="assignment-enabled" checked={form.enabled !== false} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} label="Assignment enabled" />
    </Modal>
  );
}
