import { useState } from 'react';

const statusLabels = {
  good: 'OK',
  warning: 'Warn',
  critical: 'Fail',
  unavailable: 'N/A'
};

function HealthCard({ check }) {
  const [expanded, setExpanded] = useState(false);
  const details = Object.entries(check?.details || {}).filter(([, value]) => String(value || '').trim() !== '');
  const canExpand = details.length > 0;
  const status = check?.status || 'unavailable';

  return (
    <article className={`health-card ${status} ${expanded ? 'expanded' : ''}`} onClick={() => canExpand && setExpanded(!expanded)}>
      <div className="health-main">
        <span className="health-dot" />
        <div className="health-copy">
          <h3>{check?.name || 'Check'}</h3>
          <p>{check?.description || 'Unavailable'}</p>
        </div>
        <span className="health-badge">{statusLabels[status] || status}</span>
      </div>
      {expanded && canExpand && (
        <div className="health-details">
          {details.map(([key, value]) => (
            <div key={key}>
              <span>{key}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      )}
    </article>
  );
}

export default HealthCard;