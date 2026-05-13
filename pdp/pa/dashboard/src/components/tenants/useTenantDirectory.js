import { useCallback, useEffect, useState } from 'react';
import { createTenant, deleteTenant, getTenants, updateTenant } from '../../api';

function useTenantDirectory() {
  const [tenants, setTenants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    getTenants()
      .then((data) => setTenants(Array.isArray(data) ? data : []))
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

  const openEdit = (tenant) => {
    setForm({
      ...tenant,
      domains: Array.isArray(tenant.domains) ? tenant.domains : [],
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
        await createTenant(payload);
      } else {
        await updateTenant(form.id, payload);
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
    if (!confirm('Delete this tenant? All associated gateways, resources, and policies will be orphaned.')) return;
    await deleteTenant(id);
    load();
  };

  return {
    tenants,
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

export default useTenantDirectory;
