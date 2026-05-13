import { useState } from 'react';
import { createIdP, deleteIdP, discoverIdP, getIdPs, updateIdP } from '../../api';

function useIdentityProviderManager(onChanged, publicConfig = {}) {
  const [open, setOpen] = useState(false);
  const [tenantId, setTenantId] = useState('');
  const [idps, setIdps] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const loadIdPs = (tid) => {
    setLoading(true);
    setError('');
    getIdPs(tid)
      .then((data) => setIdps(Array.isArray(data) ? data : []))
      .catch((e) => setError(e.message || 'Failed to load IdPs'))
      .finally(() => setLoading(false));
  };

  const openManager = (tenant) => {
    setTenantId(tenant.id);
    setModal(null);
    setForm({});
    setTestResult(null);
    setAdvancedOpen(false);
    setOpen(true);
    loadIdPs(tenant.id);
  };

  const closeManager = () => {
    setOpen(false);
  };

  const openCreate = () => {
    const claimDefaults = publicConfig.oidc_default_claim_mapping || {};
    setForm({
      name: '',
      type: 'oidc',
      issuer: '',
      client_id: '',
      client_secret: '',
      scopes: publicConfig.oidc_default_scopes || '',
      enabled: true,
      auto_discovery: true,
      claim_username: claimDefaults.username || '',
      claim_email: claimDefaults.email || '',
      claim_groups: claimDefaults.groups || '',
      group_role_mapping: [],
      is_default: idps.length === 0,
      has_client_secret: false,
    });
    setError('');
    setTestResult(null);
    setAdvancedOpen(false);
    setModal('create');
  };

  const openEdit = (idp) => {
    const claimDefaults = publicConfig.oidc_default_claim_mapping || {};
    const cm = idp.claim_mapping || {};
    const grm = idp.group_role_mapping || [];
    setForm({
      id: idp.id,
      name: idp.name || '',
      type: idp.type || 'oidc',
      issuer: idp.issuer || '',
      client_id: idp.client_id || '',
      client_secret: '',
      scopes: idp.scopes || publicConfig.oidc_default_scopes || '',
      enabled: idp.enabled !== false,
      auto_discovery: idp.auto_discovery !== false,
      claim_username: cm.username || claimDefaults.username || '',
      claim_email: cm.email || claimDefaults.email || '',
      claim_groups: cm.groups || claimDefaults.groups || '',
      group_role_mapping: grm,
      is_default: idp.is_default === true,
      has_client_secret: idp.has_client_secret === true,
    });
    setAdvancedOpen(
      grm.length > 0
      || (cm.username && cm.username !== claimDefaults.username)
      || (cm.email && cm.email !== claimDefaults.email)
      || (cm.groups && cm.groups !== claimDefaults.groups)
    );
    setTestResult(null);
    setModal('edit');
  };

  const handleSave = async () => {
    const claimDefaults = publicConfig.oidc_default_claim_mapping || {};
    setError('');
    if (!form.name.trim() || !form.issuer.trim() || !form.client_id.trim()) {
      setError('Name, Issuer URL, and OIDC Client ID are required');
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        type: form.type,
        issuer: form.issuer.trim(),
        client_id: form.client_id.trim(),
        client_secret: form.client_secret || undefined,
        scopes: form.scopes.trim(),
        enabled: form.enabled,
        auto_discovery: form.auto_discovery,
        claim_mapping: {
          username: (form.claim_username || '').trim() || claimDefaults.username || '',
          email: (form.claim_email || '').trim() || claimDefaults.email || '',
          groups: (form.claim_groups || '').trim() || claimDefaults.groups || '',
        },
        group_role_mapping: form.group_role_mapping || [],
        is_default: form.enabled !== false && form.is_default === true,
      };

      if (modal === 'create') {
        await createIdP(tenantId, payload);
      } else {
        await updateIdP(form.id, payload);
      }

      loadIdPs(tenantId);
      onChanged();
      setModal(null);
    } catch (e) {
      setError(e.message || 'Failed to save IdP');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this Identity Provider?')) return;
    setError('');
    try {
      await deleteIdP(id);
      loadIdPs(tenantId);
      onChanged();
    } catch (e) {
      setError(e.message || 'Failed to delete IdP');
    }
  };

  const handleSetDefault = async (idp) => {
    if (!idp?.id || idp.is_default) return;
    setError('');
    try {
      await updateIdP(idp.id, { is_default: true });
      loadIdPs(tenantId);
      onChanged();
    } catch (e) {
      setError(e.message || 'Failed to update default IdP');
    }
  };

  const handleTestConnection = async () => {
    setError('');
    setTesting(true);
    setTestResult(null);
    try {
      const result = await discoverIdP(form.issuer.trim());
      setTestResult(result);
    } catch (e) {
      setTestResult({ ok: false, error: e.message || 'Discovery probe failed' });
    } finally {
      setTesting(false);
    }
  };

  const addGroupRule = () => {
    setForm((current) => ({
      ...current,
      group_role_mapping: [...(current.group_role_mapping || []), { group_name: '', role: 'user' }],
    }));
  };

  const updateGroupRule = (index, field, value) => {
    setForm((current) => {
      const rules = [...(current.group_role_mapping || [])];
      rules[index] = { ...rules[index], [field]: value };
      return { ...current, group_role_mapping: rules };
    });
  };

  const removeGroupRule = (index) => {
    setForm((current) => {
      const rules = (current.group_role_mapping || []).filter((_, i) => i !== index);
      return { ...current, group_role_mapping: rules };
    });
  };

  return {
    open,
    tenantId,
    idps,
    loading,
    modal,
    setModal,
    form,
    setForm,
    saving,
    error,
    testResult,
    testing,
    advancedOpen,
    setAdvancedOpen,
    openManager,
    closeManager,
    openCreate,
    openEdit,
    handleDelete,
    handleSetDefault,
    handleTestConnection,
    handleSave,
    addGroupRule,
    updateGroupRule,
    removeGroupRule,
  };
}

export default useIdentityProviderManager;
