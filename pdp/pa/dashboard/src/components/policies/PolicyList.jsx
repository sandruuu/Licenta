import { useEffect, useRef, useState } from 'react';
import { ChevronDown, Copy, Edit2, Globe2, Link2, Shield, ShieldCheck, Trash2, Unlink, Users } from 'lucide-react';
import DataTable from '../ui/DataTable';
import {
  assignmentContextLabel,
  assignmentTargetLabel,
  conditionSummary,
  isDefaultGlobalPolicy,
} from './policyModel';

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

function AssignmentRow({ assignment, maps, extraCount = 0 }) {
  const global = assignment.level === 'organization';
  const groupOnly = assignment.level === 'group';
  const resourceGroup = assignment.level === 'resource_group';
  const Icon = global ? Globe2 : groupOnly || resourceGroup ? Users : Shield;
  const target = assignmentTargetLabel(assignment, maps);
  const context = assignmentContextLabel(assignment, maps);
  const tone = resourceGroup
    ? 'bg-accent-muted text-accent'
    : groupOnly
      ? 'bg-warning-muted text-warning'
      : 'bg-info-muted text-info';

  return (
    <div className="grid w-full min-w-0 grid-cols-[20px_minmax(0,1fr)_32px] items-center gap-x-3 text-left">
      <span className={`grid h-5 w-5 justify-self-start place-items-center rounded-full ${tone}`}>
        <Icon size={12} />
      </span>
      <span className="block min-w-0 text-left text-xs font-bold text-text-primary">
        <span className="block truncate">{target}</span>
        {context && <span className="mt-0.5 block truncate text-[11px] font-semibold text-text-muted">{context}</span>}
      </span>
      {extraCount > 0 && (
        <span className="justify-self-end text-xs font-bold text-accent">
          +{extraCount}
        </span>
      )}
    </div>
  );
}

function ActionItem({ children, danger, disabled, onClick }) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={(event) => {
        event.stopPropagation();
        onClick?.(event);
      }}
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

function ActionMenu({
  policy,
  policyAssignments,
  onEdit,
  onApply,
  onDuplicate,
  onUnassign,
  onDelete,
}) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);
  const defaultGlobal = isDefaultGlobalPolicy(policy);

  useEffect(() => {
    if (!open) return undefined;

    const closeOnOutsideClick = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setOpen(false);
      }
    };
    const closeOnEscape = (event) => {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    };

    document.addEventListener('pointerdown', closeOnOutsideClick);
    document.addEventListener('keydown', closeOnEscape);
    return () => {
      document.removeEventListener('pointerdown', closeOnOutsideClick);
      document.removeEventListener('keydown', closeOnEscape);
    };
  }, [open]);

  const runAction = (action) => {
    setOpen(false);
    action(policy);
  };

  return (
    <div ref={menuRef} className="relative mx-auto w-fit">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={(event) => {
          event.stopPropagation();
          setOpen((value) => !value);
        }}
        className="flex items-center justify-center gap-1 font-bold text-accent hover:text-accent-hover"
      >
        Actions
        <ChevronDown size={15} className={`transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div
          className="absolute left-1/2 z-20 mt-2 w-44 -translate-x-1/2 overflow-hidden rounded-md border border-border bg-surface-card py-1 shadow-panel"
          role="menu"
          onClick={(event) => event.stopPropagation()}
        >
          <ActionItem onClick={() => runAction(onEdit)}>
            <Edit2 size={14} />
            Edit
          </ActionItem>
          <ActionItem onClick={() => runAction(onDuplicate)}>
            <Copy size={14} />
            Duplicate
          </ActionItem>
          <ActionItem disabled={defaultGlobal} onClick={() => runAction(onApply)}>
            <Link2 size={14} />
            Apply
          </ActionItem>
          <ActionItem disabled={defaultGlobal || !policyAssignments.length} onClick={() => runAction(onUnassign)}>
            <Unlink size={14} />
            Unassign
          </ActionItem>
          <div className="my-1 border-t border-border" />
          <ActionItem danger disabled={defaultGlobal} onClick={() => runAction(onDelete)}>
            <Trash2 size={14} />
            Delete policy
          </ActionItem>
        </div>
      )}
    </div>
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
      width: 'minmax(180px, 0.95fr)',
      render: (_, policy) => {
        return (
          <div className="flex justify-center text-center">
            <button
              type="button"
              onClick={(event) => {
                event.stopPropagation();
                onEdit(policy);
              }}
              className="inline-flex items-center justify-center gap-1.5 text-center font-bold text-accent hover:text-accent-hover"
            >
              <span className="flex min-w-0 flex-col items-center gap-1">
                <span className="inline-flex items-center justify-center gap-1.5">
                  <span>{policy.name}</span>
                </span>
                {isDefaultGlobalPolicy(policy) && (
                  <span className="text-xs font-bold text-text-muted">Default policy</span>
                )}
              </span>
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
      align: 'left',
      width: 'minmax(360px, 1.35fr)',
      cellClassName: '!justify-start !px-6 !text-left',
      render: (_, policy) => {
        const policyAssignments = assignmentsForPolicy(policy.id);
        const visibleAssignments = policyAssignments.slice(0, 2);
        const extraAssignments = Math.max(0, policyAssignments.length - visibleAssignments.length);
        if (!visibleAssignments.length) {
          return <span className="block text-left font-semibold text-text-muted">No applications or groups</span>;
        }
        return (
          <div className="flex h-[76px] w-full min-w-0 flex-col justify-center gap-3 text-left">
            {visibleAssignments.map((assignment, index) => (
              <AssignmentRow
                key={assignment.id}
                assignment={assignment}
                maps={maps}
                extraCount={extraAssignments > 0 && index === visibleAssignments.length - 1 ? extraAssignments : 0}
              />
            ))}
          </div>
        );
      },
    },
    {
      key: 'summary',
      label: 'Summary',
      width: 'minmax(130px, 0.75fr)',
      render: (_, policy) => (
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            onEdit(policy);
          }}
          className="inline-flex w-full items-center justify-center text-center font-bold text-accent hover:text-accent-hover"
        >
          Rules ({countRules(policy)})
        </button>
      ),
      cellClassName: 'text-center',
    },
    {
      key: 'timestamp',
      label: (
        <span className="inline-flex items-center gap-1">
          Last updated
        </span>
      ),
      width: 'minmax(190px, 0.95fr)',
      render: (_, policy) => (
        <span className="block w-full text-center">{formatTimestamp(policy.updated_at || policy.created_at)}</span>
      ),
      cellClassName: 'text-center',
    },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      width: 'minmax(130px, 0.7fr)',
      render: (_, policy) => {
        const policyAssignments = assignmentsForPolicy(policy.id);
        return (
          <ActionMenu
            policy={policy}
            policyAssignments={policyAssignments}
            onEdit={onEdit}
            onApply={onApply}
            onDuplicate={onDuplicate}
            onUnassign={onUnassign}
            onDelete={onDelete}
          />
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
      rowClassName="h-[112px]"
      fillHeight
      onRowClick={onEdit}
    />
  );
}
