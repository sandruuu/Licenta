import { Layers3 } from 'lucide-react';
import FormField, { FormSelect } from '../ui/FormField';
import { ActionBadge, LayerBadge, PolicySentence } from './PolicyBadges';
import { targetLabel } from './policyModel';

export default function PolicyCalculator({
  organizationID,
  organizations,
  resources,
  groups,
  resourceID,
  groupID,
  assignments,
  maps,
  onOrganizationChange,
  onResourceChange,
  onGroupChange,
}) {
  return (
    <section className="grid gap-5 xl:grid-cols-[380px_1fr]">
      <div className="rounded-md border border-border bg-surface-card p-5 shadow-surface">
        <h2 className="text-base font-bold text-text-primary">Policy Calculator</h2>
        <p className="mt-1 text-xs text-text-secondary">
          Select context to see which assignments would be evaluated first.
        </p>
        <div className="mt-5 space-y-4">
          <FormField label="Organization">
            <FormSelect value={organizationID} onChange={(event) => onOrganizationChange(event.target.value || 'all')}>
              {organizations.map((organization) => (
                <option key={organization.id} value={organization.id}>{organization.name}</option>
              ))}
            </FormSelect>
          </FormField>
          <FormField label="Resource">
            <FormSelect value={resourceID} onChange={(event) => onResourceChange(event.target.value)}>
              <option value="">Any resource</option>
              {resources.map((resource) => (
                <option key={resource.id} value={resource.id}>{resource.name}</option>
              ))}
            </FormSelect>
          </FormField>
          <FormField label="Group">
            <FormSelect value={groupID} onChange={(event) => onGroupChange(event.target.value)}>
              <option value="">Any group</option>
              {groups.map((group) => (
                <option key={group.id} value={group.id}>{group.display_name}</option>
              ))}
            </FormSelect>
          </FormField>
        </div>
      </div>
      <div className="rounded-md border border-border bg-surface-card p-5 shadow-surface">
        <h2 className="text-base font-bold text-text-primary">Effective policy stack</h2>
        <div className="mt-4 space-y-3">
          {assignments.length ? assignments.map((assignment, index) => {
            const policy = maps.policies.get(assignment.policy_id);
            return (
              <div key={assignment.id} className="flex items-start gap-4 rounded-md border border-border bg-surface px-4 py-3">
                <div className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-accent text-sm font-bold text-white-smoke">{index + 1}</div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <LayerBadge level={assignment.level} />
                    {policy && <ActionBadge action={policy.action} />}
                  </div>
                  <p className="mt-2 text-sm font-bold text-text-primary">{policy?.name || assignment.policy_id}</p>
                  <p className="mt-1 text-xs text-text-secondary">{targetLabel(assignment, maps)}</p>
                  {policy && <div className="mt-2"><PolicySentence policy={policy} /></div>}
                </div>
              </div>
            );
          }) : (
            <div className="py-12 text-center text-text-secondary">
              <Layers3 size={40} className="mx-auto mb-3 opacity-50" />
              <p className="text-sm font-bold text-text-primary">No matching assignments</p>
              <p className="text-xs">The default zero-trust decision remains deny until a matching policy is assigned.</p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
