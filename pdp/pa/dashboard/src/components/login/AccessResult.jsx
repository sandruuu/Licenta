import { Check, XCircle } from 'lucide-react';

function AccessResult({ kind, message }) {
  const granted = kind === 'success';
  const Icon = granted ? Check : XCircle;

  return (
    <div className="text-center">
      <div className={`w-[72px] h-[72px] rounded-full ${granted ? 'bg-success' : 'bg-danger'} flex items-center justify-center mx-auto mb-5 text-white-smoke`}>
        <Icon size={36} />
      </div>
      <h2 className="text-xl font-bold text-text-primary mb-2">
        {granted ? 'Access granted' : 'Access denied'}
      </h2>
      <p className="text-sm text-text-secondary leading-6">{message}</p>
    </div>
  );
}

export default AccessResult;
