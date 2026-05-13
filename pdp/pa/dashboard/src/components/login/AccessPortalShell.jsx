import { CheckCircle2, Shield } from 'lucide-react';

function AccessPortalShell({ flowError, sessionLabel, resultType, children }) {
  return (
    <div className="min-h-screen bg-surface flex items-center justify-center px-4 py-8">
      <div className="w-full max-w-[420px] bg-surface-card border border-border rounded-lg shadow-xl p-8 animate-[cardFadeIn_0.35s_ease-out_both]">
        <div className="text-center mb-6">
          <div className="w-12 h-12 rounded-xl bg-accent-muted flex items-center justify-center mx-auto mb-3">
            <Shield size={24} className="text-accent" />
          </div>
          <h1 className="text-xl font-bold text-text-primary">Secure Access Portal</h1>
          <p className="text-xs text-text-secondary mt-1">Zero Trust Network Access</p>
        </div>

        {flowError ? (
          <div className="bg-danger-muted border border-danger/25 rounded-md p-3 mb-4 text-sm text-danger">
            {flowError}
          </div>
        ) : null}

        {children}

        {sessionLabel ? (
          <div className="text-center text-[11px] text-text-muted mt-5">
            {resultType === 'success' ? <CheckCircle2 size={12} className="inline mr-1" /> : null}
            {sessionLabel}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default AccessPortalShell;
