import StatusText from '../ui/StatusText';

export default function StatusBadge({ enabled }) {
  return <StatusText variant={enabled ? 'success' : 'danger'}>{enabled ? 'Enabled' : 'Disabled'}</StatusText>;
}
