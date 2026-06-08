import { Ban, Building2, Edit2, RotateCcw, Trash2 } from 'lucide-react';
import DataTable, { TableActions, TableIconButton } from '../ui/DataTable';
import StatusBadge from './StatusBadge';

export default function OrganizationTable({
  loading,
  organizations,
  onOpen,
  onEdit,
  onRevoke,
  onReactivate,
  onDelete,
  pageSize,
  emptyTitle = 'No organizations yet',
  emptyMessage = 'Create the first organization to start managing gateways and resources.',
}) {
  const columns = [
    {
      key: 'name',
      label: 'Name',
      render: (_, organization) => (
        <div className="flex min-w-0 items-center justify-center gap-3 text-center">
          <div className="min-w-0">
            <p className="inline-flex items-center justify-center gap-1.5 font-bold text-text-primary">
              <span className="truncate">{organization.name}</span>
            </p>
          </div>
        </div>
      ),
    },
    {
      key: 'domain',
      label: 'Domain',
      render: (value) => (
        <span className="inline-flex min-w-0 items-center gap-2">
          <span className="truncate font-mono text-sm">{value || '-'}</span>
        </span>
      ),
    },
    {
      key: 'enabled',
      label: 'Status',
      render: (value) => <StatusBadge enabled={value} />,
    },
    {
      key: 'actions',
      label: 'Actions',
      align: 'right',
      render: (_, organization) => (
        <TableActions>
          <TableIconButton
            icon={Edit2}
            label="Edit organization"
            onClick={(event) => {
              event.stopPropagation();
              onEdit?.(organization);
            }}
          />
          {organization.enabled !== false ? (
            <TableIconButton
              icon={Ban}
              label="Revoke organization"
              onClick={(event) => {
                event.stopPropagation();
                onRevoke?.(organization);
              }}
            />
          ) : (
            <TableIconButton
              icon={RotateCcw}
              label="Reactivate organization"
              onClick={(event) => {
                event.stopPropagation();
                onReactivate?.(organization);
              }}
            />
          )}
          <TableIconButton
            icon={Trash2}
            label="Delete organization"
            danger
            onClick={(event) => {
              event.stopPropagation();
              onDelete?.(organization);
            }}
          />
        </TableActions>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={organizations}
      loading={loading}
      emptyIcon={Building2}
      emptyTitle={emptyTitle}
      emptyMessage={emptyMessage}
      minRows={pageSize}
      fillHeight
      onRowClick={onOpen}
    />
  );
}
