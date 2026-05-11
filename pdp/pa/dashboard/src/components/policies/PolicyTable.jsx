import { Edit, Shield, Trash2 } from 'lucide-react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import DataTable from '../ui/DataTable';
import { actionVariant, ruleScopeMode, scopeLabel, scopeVariant } from './policyHelpers';

export default function PolicyTable({
  policies,
  loading,
  tenantByID,
  gatewayByID,
  resourceByID,
  onEdit,
  onDelete,
}) {
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
    { key: 'scope', label: 'Scope', render: (_, row) => <Badge variant={scopeVariant(row)}>{scopeLabel(row)}</Badge> },
    {
      key: 'tenant_id',
      label: 'Tenant',
      render: (_, row) => tenantByID.get(row.tenant_id)?.name || (ruleScopeMode(row) === 'global' ? 'All tenants' : row.tenant_id || '-'),
    },
    {
      key: 'target',
      label: 'Target',
      render: (_, row) => {
        const resource = resourceByID.get(row.resource_id);
        const gateway = gatewayByID.get(row.gateway_id || resource?.gateway_id);
        const mode = ruleScopeMode(row);
        if (mode === 'resource') return resource?.name || row.resource_id || '-';
        if (mode === 'gateway') return gateway?.name || row.gateway_id || '-';
        if (mode === 'tenant') return 'Tenant-wide';
        return 'All infrastructure';
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
      emptyTitle="No policy rules found"
      emptyMessage="Adjust filters or add a scoped access rule."
    />
  );
}
