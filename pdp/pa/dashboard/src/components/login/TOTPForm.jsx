import { LoaderCircle } from 'lucide-react';
import Button from '../ui/Button';
import FormField, { FormInput } from '../ui/FormField';

function TOTPForm({ mfaMessage, totpCode, setTotpCode, onSubmit, loading, totpRef }) {
  return (
    <form onSubmit={onSubmit}>
      <div className="bg-info-muted border border-info/20 rounded-md p-3 mb-4 text-sm text-info">
        {mfaMessage || 'Enter the 6-digit verification code from your authenticator app.'}
      </div>
      <FormField label="Verification code" htmlFor="access-totp">
        <FormInput
          ref={totpRef}
          id="access-totp"
          type="text"
          value={totpCode}
          onChange={(event) => setTotpCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
          placeholder="000000"
          maxLength={6}
          inputMode="numeric"
          autoComplete="one-time-code"
          className="text-center text-2xl font-bold tracking-[0.4em] font-mono"
          required
        />
      </FormField>
      <Button type="submit" variant="primary" disabled={loading} className="w-full justify-center mt-2">
        {loading ? (
          <>
            <LoaderCircle size={14} className="spinner-icon" />
            Verifying
          </>
        ) : 'Verify'}
      </Button>
    </form>
  );
}

export default TOTPForm;
