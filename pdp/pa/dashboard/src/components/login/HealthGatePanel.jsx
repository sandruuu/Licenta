import { AlertTriangle, LoaderCircle, RefreshCw } from 'lucide-react';
import Button from '../ui/Button';

function HealthGatePanel({ healthGate, onRetry }) {
  return (
    <div className="text-center">
      {healthGate === 'checking' ? (
        <>
          <div className="w-[72px] h-[72px] rounded-full bg-info-muted border-2 border-info/20 flex items-center justify-center mx-auto mb-5">
            <LoaderCircle size={34} className="text-info spinner-icon" />
          </div>
          <h2 className="text-lg font-bold text-text-primary mb-2">Device health check</h2>
          <p className="text-sm text-text-secondary">Checking if Device Health App is running on your device.</p>
        </>
      ) : (
        <>
          <div className="w-[72px] h-[72px] rounded-full bg-danger-muted border-2 border-danger/20 flex items-center justify-center mx-auto mb-5">
            <AlertTriangle size={34} className="text-danger" />
          </div>
          <h2 className="text-lg font-bold text-text-primary mb-2">Device Health App not running</h2>
          <p className="text-sm text-text-secondary leading-6">
            Device Health App must be running before access can continue.
          </p>
          <Button type="button" variant="secondary" className="w-full justify-center mt-5" onClick={onRetry}>
            <RefreshCw size={14} />
            Retry
          </Button>
          <p className="text-[11px] text-text-muted mt-3">Auto-retrying every 5 seconds.</p>
        </>
      )}
    </div>
  );
}

export default HealthGatePanel;
