import { useMemo, useState } from 'react';
import { Plus } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import GatewayCreateModal from '../components/tenants/GatewayCreateModal';
import TenantFormModal from '../components/tenants/TenantFormModal';
import TenantTable from '../components/tenants/TenantTable';
import useGatewayCreate from '../components/tenants/useGatewayCreate';
import useTenantDirectory from '../components/tenants/useTenantDirectory';
import ListToolbar from '../components/ui/ListToolbar';

export default function Organizations() {
  const navigate = useNavigate();
  const tenantDirectory = useTenantDirectory();
  const gatewayCreate = useGatewayCreate(tenantDirectory.load);
  const [query, setQuery] = useState('');

  const openOrganization = (tenant) => {
    if (tenant?.id) navigate(`/dashboard/organizations/${encodeURIComponent(tenant.id)}`);
  };
  const filteredTenants = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return tenantDirectory.tenants.filter((tenant) => {
      if (!needle) return true;
      return [
        tenant.name,
        tenant.domain,
        tenant.description,
        tenant.id,
      ].some((value) => String(value || '').toLowerCase().includes(needle));
    });
  }, [tenantDirectory.tenants, query]);
  const hasFilters = query.trim();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-bold tracking-[-0.3px] text-text-primary">Organizations</h1>
          <p className="text-xs text-text-secondary mt-0.5 font-medium">Manage organizations, identity providers, and gateways</p>
        </div>
        <button
          onClick={tenantDirectory.openCreate}
          className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-md hover:bg-accent-hover transition-colors font-semibold text-xs shadow-sm"
        >
          <Plus size={16} />
          Create Organization
        </button>
      </div>

      <ListToolbar
        query={query}
        onQueryChange={setQuery}
        placeholder="Search name or domain"
      />

      <TenantTable
        loading={tenantDirectory.loading}
        tenants={filteredTenants}
        onCreateGateway={gatewayCreate.openGatewayCreate}
        onOpen={openOrganization}
        onEdit={tenantDirectory.openEdit}
        onDelete={tenantDirectory.handleDelete}
        emptyTitle={hasFilters ? 'No organizations match filters' : 'No organizations yet'}
        emptyMessage={hasFilters ? 'Adjust search or filters to find organizations.' : 'Create the first organization to start managing gateways and resources.'}
      />

      <TenantFormModal
        mode={tenantDirectory.modal}
        form={tenantDirectory.form}
        setForm={tenantDirectory.setForm}
        saving={tenantDirectory.saving}
        onClose={tenantDirectory.closeModal}
        onSave={tenantDirectory.handleSave}
      />

      {gatewayCreate.open ? (
        <GatewayCreateModal
          tenant={gatewayCreate.tenant}
          form={gatewayCreate.form}
          setForm={gatewayCreate.setForm}
          error={gatewayCreate.error}
          enrollment={gatewayCreate.enrollment}
          saving={gatewayCreate.saving}
          onClose={gatewayCreate.closeGatewayCreate}
          onCreate={gatewayCreate.handleGatewayCreate}
        />
      ) : null}
    </div>
  );
}
