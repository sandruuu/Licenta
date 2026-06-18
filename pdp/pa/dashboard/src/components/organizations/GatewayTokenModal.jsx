import { AlertCircle, Copy } from 'lucide-react';
import { useEffect, useState } from 'react';
import Button from '../ui/Button';
import FormField, { FormInput } from '../ui/FormField';
import Modal from '../ui/Modal';

function TokenSkeleton() {
  return (
    <div className="flex flex-col gap-2 sm:flex-row">
      <div className="h-10 flex-1 animate-pulse rounded-md border border-border bg-border-light" />
      <div className="h-10 w-10 animate-pulse rounded-md border border-border bg-border-light" />
    </div>
  );
}

export default function GatewayTokenModal({
  open,
  tokenInfo,
  title = 'Gateway enrollment token',
  tokenLabel = 'Enrollment token',
  warningText = 'Copy this token now. It will not be shown again.',
  copyTitle = 'Copy enrollment token',
  fields = [],
  onClose,
}) {
  const [copiedKey, setCopiedKey] = useState('');
  const token = tokenInfo?.enrollment_token || tokenInfo?.token || '';
  const loading = !!tokenInfo?.loading;
  const error = tokenInfo?.error || '';

  useEffect(() => {
    setCopiedKey('');
  }, [open, token]);

  const copyValue = async (value, key) => {
    if (!value) return;
    try {
      await navigator.clipboard?.writeText(value);
      setCopiedKey(key);
    } catch {
      setCopiedKey('');
    }
  };

  const close = () => {
    setCopiedKey('');
    onClose?.();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title={title}
      size="lg"
      footer={<Button onClick={close}>Done</Button>}
    >
      {error ? (
        <div className="flex items-start gap-2 rounded-md border border-danger bg-danger-muted p-3 text-sm font-semibold text-danger">
          <AlertCircle size={18} className="mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      ) : (
        <>
          <div className="flex items-center gap-2 text-sm font-semibold text-warning">
            <AlertCircle size={18} className="shrink-0" />
            <span>{warningText}</span>
          </div>
          {fields.map((field) => {
            const key = field.key || field.label;
            return (
              <FormField key={key} label={field.label} className="mb-0">
                {loading ? (
                  <TokenSkeleton />
                ) : (
                  <div className="flex flex-col gap-2 sm:flex-row">
                    <FormInput readOnly value={field.value || '-'} className="font-mono" onFocus={(event) => event.target.select()} />
                    <Button
                      type="button"
                      variant="secondary"
                      onClick={() => copyValue(field.value, key)}
                      disabled={!field.value}
                      title={copiedKey === key ? 'Copied' : field.copyTitle || `Copy ${field.label}`}
                      aria-label={copiedKey === key ? 'Copied' : field.copyTitle || `Copy ${field.label}`}
                      className="!h-10 !w-10 !justify-center !gap-0 !px-0"
                    >
                      <Copy size={14} />
                    </Button>
                  </div>
                )}
              </FormField>
            );
          })}
          <FormField label={tokenLabel} className="mb-0">
            {loading ? (
              <TokenSkeleton />
            ) : (
              <div className="flex flex-col gap-2 sm:flex-row">
                <FormInput readOnly value={token || '-'} className="font-mono" onFocus={(event) => event.target.select()} />
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => copyValue(token, 'token')}
                  disabled={!token}
                  title={copiedKey === 'token' ? 'Copied' : copyTitle}
                  aria-label={copiedKey === 'token' ? 'Copied' : copyTitle}
                  className="!h-10 !w-10 !justify-center !gap-0 !px-0"
                >
                  <Copy size={14} />
                </Button>
              </div>
            )}
          </FormField>
        </>
      )}
    </Modal>
  );
}
