import { useCallback, useEffect, useState } from 'react';
import { createOrganization, getOrganizations, updateOrganization } from '../../api';

function useOrganizationDirectory() {
  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [reactivating, setReactivating] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    getOrganizations()
      .then((data) => setOrganizations(Array.isArray(data) ? data : []))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const openCreate = () => {
    setForm({ name: '', domain: '', domains: [], description: '', enabled: true });
    setModal('create');
  };

  const openEdit = (organization) => {
    setForm({
      ...organization,
      domains: Array.isArray(organization.domains) ? organization.domains : [],
    });
    setModal('edit');
  };

  const closeModal = () => {
    setModal(null);
  };

  const handleSave = async () => {
    setSaving(true);
    const payload = {
      ...form,
      domains: Array.isArray(form.domains) ? form.domains : [],
    };
    try {
      if (modal === 'create') {
        await createOrganization(payload);
      } else {
        await updateOrganization(form.id, payload);
      }
      setModal(null);
      load();
    } catch (e) {
      console.error(e);
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async (organization) => {
    if (!organization?.id) return;
    setRevoking(true);
    try {
      await updateOrganization(organization.id, {
        ...organization,
        enabled: false,
        domains: Array.isArray(organization.domains) ? organization.domains : [],
      });
      load();
    } catch (e) {
      console.error(e);
    } finally {
      setRevoking(false);
    }
  };

  const handleReactivate = async (organization) => {
    if (!organization?.id) return;
    setReactivating(true);
    try {
      await updateOrganization(organization.id, {
        ...organization,
        enabled: true,
        domains: Array.isArray(organization.domains) ? organization.domains : [],
      });
      load();
    } catch (e) {
      console.error(e);
    } finally {
      setReactivating(false);
    }
  };

  return {
    organizations,
    loading,
    modal,
    form,
    setForm,
    saving,
    revoking,
    reactivating,
    load,
    openCreate,
    openEdit,
    closeModal,
    handleSave,
    handleRevoke,
    handleReactivate,
  };
}

export default useOrganizationDirectory;
