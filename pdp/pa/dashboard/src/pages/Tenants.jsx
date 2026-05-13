import { Plus } from 'lucide-react';
import GatewayCreateModal from '../components/tenants/GatewayCreateModal';
import IdentityProviderManagerModal from '../components/tenants/IdentityProviderManagerModal';
import TenantFormModal from '../components/tenants/TenantFormModal';
import TenantTable from '../components/tenants/TenantTable';
import useGatewayCreate from '../components/tenants/useGatewayCreate';
import useIdentityProviderManager from '../components/tenants/useIdentityProviderManager';
import useTenantDirectory from '../components/tenants/useTenantDirectory';
import { usePublicConfig } from '../config/publicConfig';

export default function Tenants() {
  const publicConfig = usePublicConfig();
  const tenantDirectory = useTenantDirectory();
  const gatewayCreate = useGatewayCreate(tenantDirectory.load);
  const identityProviders = useIdentityProviderManager(tenantDirectory.load, publicConfig);

  const idpTenantName = tenantDirectory.tenants.find((tenant) => tenant.id === identityProviders.tenantId)?.name || '';
  const federatedCallbackURL = publicConfig.federated_callback_url || '';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-bold tracking-[-0.3px] text-text-primary">Tenants</h1>
          <p className="text-xs text-text-secondary mt-0.5 font-medium">Manage organizations, identity providers, and gateways</p>
        </div>
        <button
          onClick={tenantDirectory.openCreate}
          className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-md hover:bg-accent-hover transition-colors font-semibold text-xs shadow-sm"
        >
          <Plus size={16} />
          Create Tenant
        </button>
      </div>

      <TenantTable
        loading={tenantDirectory.loading}
        tenants={tenantDirectory.tenants}
        onManageIdPs={identityProviders.openManager}
        onCreateGateway={gatewayCreate.openGatewayCreate}
        onEdit={tenantDirectory.openEdit}
        onDelete={tenantDirectory.handleDelete}
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

      {identityProviders.open ? (
        <IdentityProviderManagerModal
          tenantName={idpTenantName}
          idps={identityProviders.idps}
          idpLoading={identityProviders.loading}
          idpError={identityProviders.error}
          idpModal={identityProviders.modal}
          setIdpModal={identityProviders.setModal}
          idpForm={identityProviders.form}
          setIdpForm={identityProviders.setForm}
          idpSaving={identityProviders.saving}
          testResult={identityProviders.testResult}
          testing={identityProviders.testing}
          idpAdvancedOpen={identityProviders.advancedOpen}
          setIdpAdvancedOpen={identityProviders.setAdvancedOpen}
          onClose={identityProviders.closeManager}
          onCreate={identityProviders.openCreate}
          onEdit={identityProviders.openEdit}
          onDelete={identityProviders.handleDelete}
          onSetDefault={identityProviders.handleSetDefault}
          onTestConnection={identityProviders.handleTestConnection}
          onSave={identityProviders.handleSave}
          addGroupRule={identityProviders.addGroupRule}
          updateGroupRule={identityProviders.updateGroupRule}
          removeGroupRule={identityProviders.removeGroupRule}
          federatedCallbackURL={federatedCallbackURL}
        />
      ) : null}
    </div>
  );
}
