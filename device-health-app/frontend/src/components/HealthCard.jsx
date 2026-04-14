import React, { useState } from 'react';

function HealthCard({ name, status, description, details, delay = 0 }) {
    const [expanded, setExpanded] = useState(false);

    const statusConfig = {
        good: { color: '#22c55e', bg: 'rgba(34, 197, 94, 0.08)', label: 'OK' },
        warning: { color: '#eab308', bg: 'rgba(234, 179, 8, 0.08)', label: 'WARN' },
        critical: { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.08)', label: 'FAIL' }
    };

    const config = statusConfig[status] || statusConfig.warning;

    const hasDetails = details && Object.keys(details).length > 0;
    const filteredDetails = details
        ? Object.entries(details).filter(([_, v]) => v && v.trim() !== '')
        : [];

    return (
        <div
            className={`health-card ${expanded ? 'expanded' : ''}`}
            style={{ animationDelay: `${delay}ms` }}
            onClick={() => hasDetails && setExpanded(!expanded)}
        >
            <div className="card-header">
                <div className="card-left">
                    <span className="status-indicator" style={{ backgroundColor: config.color }}></span>
                    <div className="card-title-group">
                        <h3 className="card-title">{name}</h3>
                        <p className="card-description">{description}</p>
                    </div>
                </div>
                <div className="card-right">
                    <span
                        className="status-label"
                        style={{ color: config.color }}
                    >
                        {config.label}
                    </span>
                    {hasDetails && (
                        <span className={`expand-arrow ${expanded ? 'rotated' : ''}`}>
                            <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                                <path d="M4 2L8 6L4 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                            </svg>
                        </span>
                    )}
                </div>
            </div>

            {expanded && filteredDetails.length > 0 && (
                <div className="card-details">
                    {filteredDetails.map(([key, value]) => (
                        <div className="detail-row" key={key}>
                            <span className="detail-key">{key}</span>
                            <span className="detail-value">{value}</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

export default HealthCard;
