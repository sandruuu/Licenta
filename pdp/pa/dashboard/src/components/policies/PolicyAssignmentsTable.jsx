import { Edit2, Trash2 } from 'lucide-react';
import Badge from '../ui/Badge';
import { LayerBadge } from './PolicyBadges';
import { actionMeta, assignmentContextLabel, assignmentTargetLabel } from './policyModel';

export default function PolicyAssignmentsTable({ assignments, maps, onEdit, onDelete }) {
  return (
    <section className="rounded-md border border-border bg-surface-card shadow-surface">
      <div className="grid grid-cols-[190px_1.5fr_1.4fr_1.4fr_120px] gap-4 border-b border-border bg-surface-secondary px-5 py-3 text-[10px] font-bold uppercase tracking-[0.14em] text-text-muted">
        <span>Type</span>
        <span>Policy</span>
        <span>Organization</span>
        <span>Target</span>
        <span className="text-right">Actions</span>
      </div>
      {assignments.length ? assignments.map((assignment) => {
        const policy = maps.policies.get(assignment.policy_id);
        return (
          <div key={assignment.id} className="grid grid-cols-[190px_1.5fr_1.4fr_1.4fr_120px] gap-4 border-b border-border px-5 py-4 last:border-b-0 hover:bg-surface-hover/60">
            <div><LayerBadge level={assignment.level} /></div>
            <div>
              <p className="text-sm font-bold text-text-primary">{policy?.name || assignment.policy_id}</p>
              <p className="mt-1 text-xs text-text-secondary">{policy ? actionMeta(policy.action).label : 'Unknown action'}</p>
            </div>
            <div className="text-sm font-semibold text-text-secondary">{maps.organizations.get(assignment.tenant_id)?.name || assignment.tenant_id}</div>
            <div>
              <p className="text-sm font-semibold text-text-primary">{assignmentTargetLabel(assignment, maps)}</p>
              <p className="mt-1 truncate text-xs font-semibold text-text-muted">{assignmentContextLabel(assignment, maps)}</p>
            </div>
            <div className="flex justify-end gap-1">
              <Badge variant={assignment.enabled === false ? 'danger' : 'success'}>{assignment.enabled === false ? 'Disabled' : 'Active'}</Badge>
              <button onClick={() => onEdit(assignment)} className="rounded-md p-2 text-text-secondary hover:bg-surface-secondary hover:text-accent" title="Replace">
                <Edit2 size={16} />
              </button>
              <button onClick={() => onDelete(assignment)} className="rounded-md p-2 text-text-secondary hover:bg-danger-muted hover:text-danger" title="Unassign">
                <Trash2 size={16} />
              </button>
            </div>
          </div>
        );
      }) : (
        <div className="py-16 text-center">
          <p className="mt-3 text-sm font-bold text-text-primary">No policy assignments</p>
          <p className="text-xs text-text-secondary">Apply a reusable policy to a Duo-style layer.</p>
        </div>
      )}
    </section>
  );
}
