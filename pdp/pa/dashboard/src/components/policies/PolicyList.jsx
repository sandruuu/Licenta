import { ChevronDown, Copy, Edit2, Globe2, Link2, Shield, ShieldCheck, Trash2, Unlink, Users } from 'lucide-react';
import Badge from '../ui/Badge';
import DataTable from '../ui/DataTable';
import { assignmentScopeLabel, conditionSummary, targetLabel } from './policyModel';

function formatTimestamp(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(date);
}

function countRules(policy) {
  return Math.max(1, conditionSummary(policy).length);
}

function assignmentLabel(assignment, maps) {
  if (assignment.level === 'organization') return 'All applications';
  if (assignment.level === 'resource_group') {
    const resource = maps.resources.get(assignment.resource_id)?.name || assignment.resource_id || 'Application';
    const group = maps.groups.get(assignment.group_id)?.display_name || assignment.group_name || assignment.group_id || 'Group';
    return `${resource}: ${group}`;
  }
  return targetLabel(assignment, maps);
}

function AssignmentPill({ assignment, maps }) {
  const global = assignment.level === 'organization';
  const groupOnly = assignment.level === 'group';
  const resourceGroup = assignment.level === 'resource_group';
  const Icon = global ? Globe2 : groupOnly || resourceGroup ? Users : Shield;
  const scope = assignmentScopeLabel(assignment, maps);
  const tone = resourceGroup
    ? 'bg-accent-muted text-accent'
    : groupOnly
      ? 'bg-warning-muted text-warning'
      : 'bg-info-muted text-info';

  if (global) {
    return (
      <span className="text-sm font-semibold text-text-secondary">
        All applications
      </span>
    );
  }

  return (
    <span className="inline-flex max-w-full items-start gap-2 rounded-md px-2.5 py-1 text-xs font-bold text-text-primary">
      <span className={`grid h-5 w-5 shrink-0 place-items-center rounded-full ${tone}`}>
        <Icon size={12} />
      </span>
      <span className="min-w-0">
        <span className="block truncate">{assignmentLabel(assignment, maps)}</span>
        {scope && <span className="mt-0.5 block truncate text-[11px] font-semibold text-text-muted">{scope}</span>}
      </span>
    </span>
  );
}

function ActionItem({ children, danger, disabled, onClick }) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={`flex w-full items-center gap-2 px-3 py-2 text-left text-xs font-bold transition-colors ${
        danger
          ? 'text-danger hover:bg-danger-muted'
          : 'text-text-secondary hover:bg-surface-hover hover:text-accent'
      } disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-text-secondary`}
    >
      {children}
    </button>
  );
}

export default function PolicyList({
  policies,
  loading,
  pageSize,
  assignmentsForPolicy,
  maps,
  onEdit,
  onApply,
  onDuplicate,
  onUnassign,
  onDelete,
}) {
  const columns = [
    {
      key: 'name',
      label: 'Name',
      render: (_, policy) => {
        const policyAssignments = assignmentsForPolicy(policy.id);
        const hasGlobalAssignment = policyAssignments.some((assignment) => assignment.level === 'organization');
        return (
          <div className="flex justify-center text-center">
            <button type="button" onClick={() => onEdit(policy)} className="inline-flex items-center justify-center gap-1.5 text-center font-bold text-accent hover:text-accent-hover">
              <span>{policy.name}</span>
              {hasGlobalAssignment && <Globe2 size={14} />}
            </button>
          </div>
        );
      },
    },
    {
      key: 'assignments',
      label: (
        <span className="inline-flex items-center gap-1">
          Applications and Groups
        </span>
      ),
      render: (_, policy) => {
        const policyAssignments = assignmentsForPolicy(policy.id);
        const visibleAssignments = policyAssignments.slice(0, 2);
        const extraAssignments = Math.max(0, policyAssignments.length - visibleAssignments.length);
        if (!visibleAssignments.length) {
          return <span className="font-semibold text-text-muted">No applications or groups</span>;
        }
        return (
          <div className="mx-auto flex max-w-[360px] flex-col items-start justify-center gap-2 text-left">
            {visibleAssignments.map((assignment, index) => (
              <div key={assignment.id} className="flex max-w-full items-center gap-2">
                <AssignmentPill assignment={assignment} maps={maps} />
                {extraAssignments > 0 && index === visibleAssignments.length - 1 && (
                  <span className="shrink-0 text-xs font-bold text-accent">+{extraAssignments}</span>
                )}
              </div>
            ))}
          </div>
        );
      },
    },
    {
      key: 'summary',
      label: 'Summary',
      render: (_, policy) => (
        <button type="button" onClick={() => onEdit(policy)} className="font-bold text-accent hover:text-accent-hover">
          Rules ({countRules(policy)})
        </button>
      ),
    },
    {
      key: 'timestamp',
      label: (
        <span className="inline-flex items-center gap-1">
          Timestamp
        </span>
      ),
      render: (_, policy) => formatTimestamp(policy.updated_at || policy.created_at),
    },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      render: (_, policy) => {
        const policyAssignments = assignmentsForPolicy(policy.id);
        return (
          <details className="group relative mx-auto w-fit">
            <summary className="flex cursor-pointer list-none items-center justify-center gap-1 font-bold text-accent hover:text-accent-hover">
              Actions
              <ChevronDown size={15} className="transition-transform group-open:rotate-180" />
            </summary>
            <div className="absolute left-1/2 z-20 mt-2 w-44 -translate-x-1/2 overflow-hidden rounded-md border border-border bg-surface-card py-1 shadow-panel">
              <ActionItem onClick={() => onEdit(policy)}>
                <Edit2 size={14} />
                Edit
              </ActionItem>
              <ActionItem onClick={() => onDuplicate(policy)}>
                <Copy size={14} />
                Duplicate
              </ActionItem>
              <ActionItem onClick={() => onApply(policy)}>
                <Link2 size={14} />
                Apply
              </ActionItem>
              <ActionItem disabled={!policyAssignments.length} onClick={() => onUnassign(policy)}>
                <Unlink size={14} />
                Unassign
              </ActionItem>
              <div className="my-1 border-t border-border" />
              <ActionItem danger onClick={() => onDelete(policy)}>
                <Trash2 size={14} />
                Delete policy
              </ActionItem>
            </div>
          </details>
        );
      },
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={policies}
      loading={loading}
      emptyIcon={ShieldCheck}
      emptyTitle="No policies match filters"
      emptyMessage="Add a policy or adjust the filters."
      minRows={pageSize}
    />
  );
}
