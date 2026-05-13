import { useState } from 'react';
import { createGateway as createGatewayRequest } from '../../api';
import { gatewayFQDN, gatewayLabelFromName, tenantDomain } from './tenantUtils';

function useGatewayCreate(onChanged) {
  const [tenant, setTenant] = useState(null);
  const [form, setForm] = useState({ name: '' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [enrollment, setEnrollment] = useState(null);
  const [open, setOpen] = useState(false);

  const openGatewayCreate = (selectedTenant) => {
    setTenant(selectedTenant);
    setForm({ name: '' });
    setError('');
    setEnrollment(null);
    setOpen(true);
  };

  const closeGatewayCreate = () => {
    setOpen(false);
    setTenant(null);
    setForm({ name: '' });
    setError('');
    setEnrollment(null);
  };

  const handleGatewayCreate = async () => {
    setError('');
    setEnrollment(null);
    const fqdn = gatewayFQDN(form.name, tenant);
    if (!tenant?.id) {
      setError('Organization is required');
      return;
    }
    if (!tenantDomain(tenant)) {
      setError('Set a primary domain for this organization before creating a gateway');
      return;
    }
    if (!gatewayLabelFromName(form.name)) {
      setError('Gateway name is required');
      return;
    }

    setSaving(true);
    try {
      const result = await createGatewayRequest({
        tenant_id: tenant.id,
        name: form.name.trim(),
        fqdn,
        auth_mode: 'builtin',
      });
      if (result?.enrollment_token) {
        setEnrollment({
          token: result.enrollment_token,
          gateway_id: result.id,
          tenant_id: result.tenant_id,
          fqdn,
          expires_at: result.token_expires_at,
        });
      }
      setForm({ name: '' });
      onChanged();
    } catch (e) {
      setError(e.message || 'Failed to create gateway');
    } finally {
      setSaving(false);
    }
  };

  return {
    open,
    tenant,
    form,
    setForm,
    saving,
    error,
    enrollment,
    openGatewayCreate,
    closeGatewayCreate,
    handleGatewayCreate,
  };
}

export default useGatewayCreate;
