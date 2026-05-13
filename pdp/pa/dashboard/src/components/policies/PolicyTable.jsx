import { Edit, Link2, Shield, Trash2 } from 'lucide-react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import DataTable from '../ui/DataTable';
import { actionVariant, assignmentScopeLabel, assignmentScopeVariant } from './policyHelpers';

export default function PolicyTable({
  policies,
  loading,
  tenantByID,
  gatewayByID,
  resourceByID,
  assignmentsByPolicy,
  onEdit,
  onAssign,
  onDelete,
}) {
  const assignmentTarget = (assignment) => {
    if (!assignment) return '-';
    if (assignment.resource_id) return resourceByID.get(assignment.resource_id)?.name || assignment.resource_id;
    if (assignment.gateway_id) return gatewayByID.get(assignment.gateway_id)?.name || assignment.gateway_id;
    return tenantByID.get(assignment.tenant_id)?.name || assignment.tenant_id || '-';
  };

  const columns = [
    { key: 'priority', label: 'Priority', render: (value) => <span className="text-mono text-xs">{value}</span> },
    {
      key: 'name',
      label: 'Policy',
      render: (_, row) => (
        <div>
          <span className="font-semibold text-text-primary text-xs">{row.name}</span>
          {row.description && <div className="text-xs text-text-muted">{row.description}</div>}
        </div>
      ),
    },
    { key: 'action', label: 'Action', render: (value) => <Badge variant={actionVariant(value)}>{value}</Badge> },
    {
      key: 'assignments',
      label: 'Assignments',
      render: (_, row) => {
        const assignments = assignmentsByPolicy.get(row.id) || [];
        if (assignments.length === 0) return <Badge variant="neutral">Unassigned</Badge>;
        const enabled = assignments.filter((assignment) => assignment.enabled !== false).length;
        return <Badge variant={enabled > 0 ? 'success' : 'warning'}>{enabled}/{assignments.length} active</Badge>;
      },
    },
    {
      key: 'target',
      label: 'Applied to',
      render: (_, row) => {
        const assignments = assignmentsByPolicy.get(row.id) || [];
        if (assignments.length === 0) return <span className="text-text-muted">No target</span>;
        const first = assignments[0];
        const extra = assignments.length > 1 ? ` +${assignments.length - 1}` : '';
        return (
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge variant={assignmentScopeVariant(first)}>{assignmentScopeLabel(first)}</Badge>
            <span className="text-xs text-text-secondary">{assignmentTarget(first)}{extra}</span>
          </div>
        );
      },
    },
    { key: 'enabled', label: 'Status', render: (value) => <Badge variant={value ? 'success' : 'danger'}>{value ? 'Active' : 'Disabled'}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      render: (_, row) => (
        <div className="flex items-center justify-end gap-1">
          <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => onEdit(row)} title="Edit policy">
            <Edit size={12} />
          </Button>
          <Button variant="ghost" className="!p-1.5 !shadow-none" onClick={() => onAssign(row)} title="Assign policy">
            <Link2 size={12} />
          </Button>
          <Button variant="ghost" className="!p-1.5 !shadow-none !text-danger hover:!bg-danger-muted" onClick={() => onDelete(row.id)} title="Delete policy">
            <Trash2 size={12} />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={policies}
      loading={loading}
      emptyIcon={Shield}
      emptyTitle="No policies found"
      emptyMessage="Adjust filters or create a reusable policy definition."
    />
  );
}
