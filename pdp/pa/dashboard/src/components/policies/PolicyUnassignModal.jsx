import { Unlink } from 'lucide-react';
import Button from '../ui/Button';
import Modal from '../ui/Modal';
import { LayerBadge } from './PolicyBadges';
import { assignmentContextLabel, assignmentTargetLabel, isDefaultGlobalAssignment } from './policyModel';

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

      <div className="overflow-hidden rounded-md border border-border bg-surface">
        {assignments.length ? assignments.map((assignment) => {
          const defaultAssignment = isDefaultGlobalAssignment(assignment);
          return (
            <div
              key={assignment.id}
              className="grid gap-3 border-b border-border px-4 py-3 last:border-b-0 md:grid-cols-[150px_minmax(0,1fr)_auto] md:items-center"
            >
              <div>
                <LayerBadge level={assignment.level} />
              </div>
              <div className="min-w-0">
                <p className="truncate text-sm font-bold text-text-primary">{assignmentTargetLabel(assignment, maps)}</p>
                <p className="mt-1 truncate text-xs font-semibold text-text-secondary">
                  {defaultAssignment ? 'System default assignment' : assignmentContextLabel(assignment, maps)}
                </p>
              </div>
              <Button
                variant="danger"
                className="justify-center"
                disabled={saving || defaultAssignment}
                onClick={() => onUnassign(assignment)}
              >
                <Unlink size={14} />
                {saving ? 'Unassigning...' : 'Unassign'}
              </Button>
            </div>
          );
        }) : (
          <div className="px-4 py-8 text-center">
            <p className="text-sm font-bold text-text-primary">No assignments</p>
            <p className="mt-1 text-xs text-text-secondary">This policy is not applied to any target.</p>
          </div>
        )}
      </div>
    </Modal>
  );
}
