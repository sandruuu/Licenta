import { Activity } from 'lucide-react';

function HealthBadge({ status }) {
  const normalized = String(status || 'unknown').toLowerCase();
  const styles = {
    good: 'bg-success-muted text-success border-success/20',
    pass: 'bg-success-muted text-success border-success/20',
    ok: 'bg-success-muted text-success border-success/20',
    warning: 'bg-warning-muted text-warning border-warning/20',
    critical: 'bg-danger-muted text-danger border-danger/20',
    fail: 'bg-danger-muted text-danger border-danger/20',
  };

  return (
    <span className={`px-2 py-0.5 rounded-full border text-[10px] font-semibold uppercase ${styles[normalized] || 'bg-surface-secondary text-text-secondary border-border'}`}>
      {normalized}
    </span>
  );
}

function DeviceHealthSummary({ health }) {
  if (!health) return null;

  const score = Number(health.overall_score || 0);
  const scoreStyle = score >= 70 ? 'bg-success' : score >= 40 ? 'bg-warning' : 'bg-danger';

  return (
    <div className="mt-5 pt-4 border-t border-border">
      <div className="flex items-center gap-2 text-[11px] font-semibold uppercase text-text-muted mb-3">
        <Activity size={14} />
        Device health
      </div>
      <div className="space-y-2">
        {(health.checks || []).map((check, idx) => (
          <div key={`${check.name || 'check'}-${idx}`} className="flex items-center justify-between gap-3 text-[13px]">
            <span className="text-text-secondary truncate">{check.name || 'Device check'}</span>
            <HealthBadge status={check.status} />
          </div>
        ))}
      </div>
      <div className="h-1.5 bg-surface-secondary rounded-full overflow-hidden mt-3">
        <div className={`h-full rounded-full transition-all ${scoreStyle}`} style={{ width: `${Math.max(0, Math.min(score, 100))}%` }} />
      </div>
      <div className="text-right text-[11px] text-text-secondary mt-1">Device score: {score}/100</div>
    </div>
  );
}

export default DeviceHealthSummary;
