import { EmptyState } from './Panels';

const cellClass = 'border-t border-[var(--border-light)] px-2 py-2.5 text-left align-middle text-xs font-bold text-[var(--text-primary)]';
const headingClass = 'border-t-0 px-2 py-2.5 text-left align-middle text-[11px] font-extrabold text-[var(--text-muted)]';
const pillClass = 'shrink-0 rounded-full bg-[color-mix(in_srgb,var(--cool-steel)_22%,transparent)] px-2 py-1 text-[11px] font-extrabold text-[var(--text-secondary)]';

function ResourceTable({ resources }) {
  if (!resources.length) return <EmptyState title="No resources available" />;

  return (
    <div className="w-full overflow-auto">
      <table className="w-full border-collapse text-xs">
        <thead>
          <tr>
            <th className={headingClass}>FQDN</th>
            <th className={headingClass}>Protocol</th>
            <th className={headingClass}>Port</th>
            <th className={headingClass}>Status</th>
          </tr>
        </thead>
        <tbody>
          {resources.map((resource) => (
            <tr key={`${resource.resource_id || resource.fqdn}-${resource.port || 0}`}>
              <td className={`${cellClass} max-w-[260px] overflow-hidden truncate`}>{resource.fqdn}</td>
              <td className={cellClass}>{resource.protocol || 'tcp'}</td>
              <td className={cellClass}>{resource.port || '-'}</td>
              <td className={cellClass}><span className={pillClass}>{resource.status || 'available'}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default ResourceTable;
