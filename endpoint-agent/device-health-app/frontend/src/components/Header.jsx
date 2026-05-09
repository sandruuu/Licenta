import React from 'react';

function Header({ hostname, os, collectedAt, onRefresh, refreshing }) {
    return (
        <header className="app-header">
            <div className="header-left">
                <div className="header-icon">🩺</div>
                <div className="header-info">
                    <h1 className="header-title">Device Health Agent</h1>
                    <p className="header-subtitle">
                        <span className="hostname">{hostname}</span>
                        {os && <span className="os-badge">{os}</span>}
                    </p>
                </div>
            </div>
            <div className="header-right">
                <button
                    className={`refresh-btn ${refreshing ? 'spinning' : ''}`}
                    onClick={onRefresh}
                    disabled={refreshing}
                    title="Refresh scan"
                >
                    ⟳
                </button>
            </div>
        </header>
    );
}

export default Header;
