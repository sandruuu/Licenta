import { useCallback, useEffect, useState } from 'react';
import { GetDashboard, HideWindow } from '../wailsjs/go/tray/GUIApp';
import { EventsOn } from '../wailsjs/runtime/runtime';
import AppLayout from './components/AppLayout';
import {
  fallbackDashboard,
  isWailsRuntimeReady,
} from './lib/dashboard';

function App() {
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadDashboard = useCallback(async () => {
    if (!isWailsRuntimeReady()) {
      setDashboard(fallbackDashboard);
      setLoading(false);
      setError('');
      return;
    }

    try {
      const nextDashboard = await GetDashboard();
      setDashboard(nextDashboard);
      setError('');
    } catch (err) {
      setError(err?.message || 'Agent dashboard is unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();

    if (!window?.runtime?.EventsOn) {
      return undefined;
    }

    const unsubscribe = EventsOn('dashboard:updated', loadDashboard);
    return () => {
      if (typeof unsubscribe === 'function') {
        unsubscribe();
      }
    };
  }, [loadDashboard]);

  const handleHide = () => {
    if (window?.go?.tray?.GUIApp?.HideWindow) {
      HideWindow();
    }
  };

  return (
    <AppLayout
      dashboard={dashboard}
      dashboardError={error}
      dashboardLoading={loading}
      onHide={handleHide}
    />
  );
}

export default App;
