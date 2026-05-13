import { LoaderCircle } from 'lucide-react';
import Button from '../ui/Button';
import FormField, { FormInput } from '../ui/FormField';
import DeviceHealthSummary from './DeviceHealthSummary';

function CredentialsForm({
  username,
  password,
  onUsernameChange,
  onPasswordChange,
  onSubmit,
  loading,
  usernameRef,
  deviceHealth,
}) {
  return (
    <>
      <form onSubmit={onSubmit}>
        <FormField label="Username" htmlFor="access-username">
          <FormInput
            ref={usernameRef}
            id="access-username"
            type="text"
            value={username}
            onChange={(event) => onUsernameChange(event.target.value)}
            placeholder="Enter your username"
            autoComplete="username"
            required
          />
        </FormField>
        <FormField label="Password" htmlFor="access-password">
          <FormInput
            id="access-password"
            type="password"
            value={password}
            onChange={(event) => onPasswordChange(event.target.value)}
            placeholder="Enter your password"
            autoComplete="current-password"
            required
          />
        </FormField>
        <Button type="submit" variant="primary" disabled={loading} className="w-full justify-center mt-2">
          {loading ? (
            <>
              <LoaderCircle size={14} className="spinner-icon" />
              Please wait
            </>
          ) : 'Sign in'}
        </Button>
      </form>
      <DeviceHealthSummary health={deviceHealth} />
    </>
  );
}

export default CredentialsForm;
