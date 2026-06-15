import { useState } from 'react';
import { createGateway as createGatewayRequest } from '../../api';
import { gatewayFQDNFromLabel, gatewayLabelFromName, organizationDomain } from './organizationUtils';

function useGatewayCreate(onChanged) {
  const [organization, setOrganization] = useState(null);
  const [form, setForm] = useState({ name: '' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [enrollment, setEnrollment] = useState(null);
  const [open, setOpen] = useState(false);

  const openGatewayCreate = (selectedOrganization) => {
    setOrganization(selectedOrganization);
    setForm({ name: '', fqdn_label: '' });
    setError('');
    setEnrollment(null);
    setOpen(true);
  };

  const setGatewayOrganization = (selectedOrganization) => {
    setOrganization(selectedOrganization);
    setError('');
    setEnrollment(null);
  };

  const closeGatewayCreate = () => {
    setOpen(false);
    setOrganization(null);
    setForm({ name: '', fqdn_label: '' });
    setError('');
    setEnrollment(null);
  };

  const handleGatewayCreate = async () => {
    setError('');
    setEnrollment(null);
    const fqdnLabel = gatewayLabelFromName(form.fqdn_label);
    const fqdn = gatewayFQDNFromLabel(fqdnLabel, organization);
    if (!organization?.id) {
      setError('Organization is required');
      return;
    }
    if (!organizationDomain(organization)) {
      setError('Set a primary domain for this organization before creating a gateway');
      return;
    }
    if (!form.name?.trim()) {
      setError('Gateway name is required');
      return;
    }
    if (!fqdnLabel) {
      setError('Gateway FQDN label is required');
      return;
    }

    setSaving(true);
    try {
      const result = await createGatewayRequest({
        organization_id: organization.id,
        name: form.name.trim(),
        fqdn,
      });
      if (result?.enrollment_token) {
        setEnrollment({
          token: result.enrollment_token,
          gateway_id: result.id,
          organization_id: result.organization_id,
          fqdn,
          expires_at: result.token_expires_at,
        });
      }
      setForm({ name: '', fqdn_label: '' });
      onChanged();
    } catch (e) {
      setError(e.message || 'Failed to create gateway');
    } finally {
      setSaving(false);
    }
  };

  return {
    open,
    organization,
    form,
    setForm,
    saving,
    error,
    enrollment,
    openGatewayCreate,
    setGatewayOrganization,
    closeGatewayCreate,
    handleGatewayCreate,
  };
}

export default useGatewayCreate;
