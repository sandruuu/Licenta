import { useCallback, useEffect, useState } from 'react';
import { createOrganization, deleteOrganization, getOrganizations, updateOrganization } from '../../api';

function useOrganizationDirectory() {
  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);

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

  const handleDelete = async (id) => {
    if (!confirm('Delete this organization? All associated gateways and resources will be orphaned.')) return;
    await deleteOrganization(id);
    load();
  };

  return {
    organizations,
    loading,
    modal,
    form,
    setForm,
    saving,
    load,
    openCreate,
    openEdit,
    closeModal,
    handleSave,
    handleDelete,
  };
}

export default useOrganizationDirectory;
