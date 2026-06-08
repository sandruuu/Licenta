import { FileText, Unlink } from 'lucide-react';
import Button from '../ui/Button';
import Modal from '../ui/Modal';
import { layerIcons } from './policyIcons';
import { assignmentTargetLabel, isDefaultGlobalAssignment, layerMeta } from './policyModel';

const unassignAssignmentCardClass = 'block w-full rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-3 py-3 text-left shadow-[0_6px_14px_rgba(42,42,42,0.10)] transition-[border-color,background-color,box-shadow] duration-150 hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_8px_16px_rgba(42,42,42,0.12)]';

function assignmentLocationLabel(assignment, maps) {
  const resource = maps.resources?.get(assignment.resource_id);
  const gateway = maps.gateways?.get(resource?.gateway_id || assignment.gateway_id);
  const organization = maps.organizations?.get(assignment.tenant_id);
  return [gateway?.name || resource?.gateway_id, organization?.name || assignment.tenant_id].filter(Boolean).join(' / ');
}

export default function PolicyUnassignModal({
  open,
  policy,
  assignments,
  maps,
  saving,
  onClose,
  onUnassign,
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={policy ? `Unassign ${policy.name}` : 'Unassign policy'}
      size="2xl"
      footer={(
        <Button variant="secondary" onClick={onClose} disabled={saving}>Close</Button>
      )}
    >
      <p className="text-sm leading-6 text-text-secondary">
        Remove this policy only from the selected application, group, or application-group assignment.
      </p>

      <div className="grid gap-2 px-2 pb-2 pt-1">
        {assignments.length ? assignments.map((assignment) => {
          const defaultAssignment = isDefaultGlobalAssignment(assignment);
          const meta = layerMeta(assignment.level);
          const Icon = layerIcons[assignment.level] || FileText;
          const target = assignmentTargetLabel(assignment, maps);
          return (
            <div
              key={assignment.id}
              className={unassignAssignmentCardClass}
            >
              <div className="min-w-0">
                <div className="flex min-w-0 items-center justify-between gap-2">
                  <p className="inline-flex min-w-0 items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.1em] text-accent">
                    <Icon size={12} className="shrink-0" />
                    <span className="truncate">{meta.shortLabel}</span>
                  </p>
                  <button
                    type="button"
                    disabled={saving || defaultAssignment}
                    onClick={() => onUnassign(assignment)}
                    className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-danger transition-colors hover:bg-danger-muted disabled:cursor-not-allowed disabled:text-text-muted disabled:opacity-60 disabled:hover:bg-transparent"
                    title={defaultAssignment ? 'Default assignment cannot be removed' : 'Unassign'}
                    aria-label={`Unassign ${target}`}
                  >
                    <Unlink size={14} />
                  </button>
                </div>
                <div className="min-w-0">
                  <p className="mt-2 truncate text-sm font-semibold text-text-primary">{target}</p>
                  <p className="mt-1 truncate text-xs font-semibold text-text-secondary">
                    {defaultAssignment ? 'System default assignment' : assignmentLocationLabel(assignment, maps) || '-'}
                  </p>
                </div>
              </div>
            </div>
          );
        }) : (
          <div className="rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-4 py-8 text-center shadow-[0_6px_14px_rgba(42,42,42,0.10)]">
            <p className="text-sm font-bold text-text-primary">No assignments</p>
            <p className="mt-1 text-xs text-text-secondary">This policy is not applied to any target.</p>
          </div>
        )}
      </div>
    </Modal>
  );
}
