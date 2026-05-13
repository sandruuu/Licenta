import { KeyRound, Smartphone } from 'lucide-react';

const methodMeta = {
  totp: {
    icon: Smartphone,
    name: 'Authenticator app',
    desc: 'Enter a 6-digit code from your authenticator app',
  },
  webauthn: {
    icon: KeyRound,
    name: 'Security key',
    desc: 'Use your passkey or hardware security key',
  },
};

function MFASelection({ mfaMessage, mfaMethods, onSelect }) {
  return (
    <div>
      <div className="bg-info-muted border border-info/20 rounded-md p-3 mb-4 text-sm text-info">
        {mfaMessage || 'Additional verification is required.'}
      </div>
      <div className="space-y-2">
        {mfaMethods.map((method) => {
          const meta = methodMeta[method] || { icon: KeyRound, name: method, desc: '' };
          const Icon = meta.icon;
          return (
            <button
              key={method}
              type="button"
              onClick={() => onSelect(method)}
              className="w-full p-3 bg-surface-card border border-border rounded-md hover:border-accent hover:ring-[3px] hover:ring-accent-muted transition flex items-center gap-3 text-left"
            >
              <span className="w-9 h-9 rounded-md bg-accent-muted flex items-center justify-center text-accent shrink-0">
                <Icon size={18} />
              </span>
              <span className="min-w-0">
                <span className="block text-sm font-semibold text-text-primary">{meta.name}</span>
                <span className="block text-xs text-text-secondary truncate">{meta.desc}</span>
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default MFASelection;
