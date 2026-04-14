import { useState, useEffect } from 'react';
import './App.css';
import { GetDeviceHealth } from "../wailsjs/go/main/App";
import { EventsOn } from "../wailsjs/runtime/runtime";
import OverallScore from './components/OverallScore';
import HealthCard from './components/HealthCard';
import PushApproval from './components/PushApproval';

function App() {
    const [health, setHealth] = useState(null);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);

    const fetchHealth = async (isRefresh = false) => {
        if (isRefresh) setRefreshing(true);
        try {
            const result = await GetDeviceHealth();
            setHealth(result);
        } catch (err) {
            console.error("Failed to fetch device health:", err);
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    };

    useEffect(() => {
        fetchHealth();

        // Listen for real-time health change events from the Go backend
        const unsubscribe = EventsOn("health:updated", () => {
            fetchHealth();
        });

        // Fallback poll every 5 minutes in case an event is missed
        const interval = setInterval(() => fetchHealth(), 300000);

        return () => {
            unsubscribe();
            clearInterval(interval);
        };
    }, []);

    const handleRefresh = () => {
        fetchHealth(true);
    };

    if (loading) {
        return (
            <div className="app">
                <div className="loading-screen">
                    <div className="loading-spinner"></div>
                    <p className="loading-text">Scanning...</p>
                </div>
            </div>
        );
    }

    if (!health) {
        return (
            <div className="app">
                <div className="loading-screen">
                    <p className="loading-text error-text">Failed to collect data</p>
                </div>
            </div>
        );
    }

    return (
        <div className="app">
            <PushApproval />
            <header className="app-header">
                <div className="header-left">
                    <div className="header-info">
                        <h1 className="header-title">Device Health</h1>
                        <p className="header-subtitle">
                            {health.hostname}
                        </p>
                    </div>
                </div>
                <button
                    className={`refresh-btn ${refreshing ? 'spinning' : ''}`}
                    onClick={handleRefresh}
                    disabled={refreshing}
                    title="Refresh"
                >
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                        <path d="M13.65 2.35A7.96 7.96 0 0 0 8 0C3.58 0 0 3.58 0 8s3.58 8 8 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0 1 8 14 6 6 0 1 1 8 2c1.66 0 3.14.69 4.22 1.78L9 7h7V0l-2.35 2.35z" fill="currentColor" />
                    </svg>
                </button>
            </header>

            <main className="dashboard">
                <div className="score-section">
                    <OverallScore score={health.overallScore} />
                </div>

                <div className="checks-grid">
                    {health.checks && health.checks.map((check, index) => (
                        <HealthCard
                            key={index}
                            name={check.name}
                            status={check.status}
                            description={check.description}
                            details={check.details}
                            delay={index * 80}
                        />
                    ))}
                </div>
            </main>

            <footer className="app-footer">
                <span className="footer-text">{health.collectedAt}</span>
            </footer>
        </div>
    );
}

export default App;
