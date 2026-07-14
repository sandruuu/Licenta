import { useCallback, useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { getGateways, getResources } from '../api';
import GatewayCreateModal from '../components/organizations/GatewayCreateModal';
import OrganizationFormModal from '../components/organizations/OrganizationFormModal';
import OrganizationTable from '../components/organizations/OrganizationTable';
import useGatewayCreate from '../components/organizations/useGatewayCreate';
import useOrganizationDirectory from '../components/organizations/useOrganizationDirectory';
import ConfirmDialog from '../components/ui/ConfirmDialog';
import ListToolbar from '../components/ui/ListToolbar';
import PageHeader from '../components/ui/PageHeader';
import Pagination from '../components/ui/Pagination';
import { usePaginatedTable } from '../components/ui/usePaginatedTable';
import { navigateWithReturn } from '../utils/navigation';

export default function Organizations() {
  const navigate = useNavigate();
  const location = useLocation();
  const organizationDirectory = useOrganizationDirectory();
  const [gateways, setGateways] = useState([]);
  const [resources, setResources] = useState([]);
  const loadRelatedInfrastructure = useCallback(() => {
    Promise.all([
      getGateways().catch(() => []),
      getResources().catch(() => []),
    ]).then(([gatewayData, resourceData]) => {
      setGateways(Array.isArray(gatewayData) ? gatewayData : []);
      setResources(Array.isArray(resourceData) ? resourceData : []);
    });
  }, []);
  const refreshOrganizationData = useCallback(() => {
    organizationDirectory.load();
    loadRelatedInfrastructure();
  }, [loadRelatedInfrastructure, organizationDirectory.load]);
  const gatewayCreate = useGatewayCreate(refreshOrganizationData);
  const [query, setQuery] = useState('');
  const [revokeOrganizationTarget, setRevokeOrganizationTarget] = useState(null);
  const [reactivateOrganizationTarget, setReactivateOrganizationTarget] = useState(null);

  useEffect(() => {
    loadRelatedInfrastructure();
  }, [loadRelatedInfrastructure]);

  const openOrganization = (organization) => {
    if (organization?.id) navigateWithReturn(navigate, `/organizations/${encodeURIComponent(organization.id)}`, location);
  };

  const filteredOrganizations = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return organizationDirectory.organizations.filter((organization) => {
      if (!needle) return true;
      return [
        organization.name,
        organization.domain,
        organization.description,
        organization.id,
      ].some((value) => String(value || '').toLowerCase().includes(needle));
    });
  }, [organizationDirectory.organizations, query]);

  const organizationStats = useMemo(() => {
    const gatewayCounts = new Map();
    const resourceCounts = new Map();
    const gatewayOrganizationIDs = new Map();

    gateways.forEach((gateway) => {
      const organizationIDs = new Set([
        gateway.organization_id,
        ...(Array.isArray(gateway.organization_ids) ? gateway.organization_ids : []),
      ].filter(Boolean));

      gatewayOrganizationIDs.set(gateway.id, organizationIDs);
      organizationIDs.forEach((organizationID) => {
        gatewayCounts.set(organizationID, (gatewayCounts.get(organizationID) || 0) + 1);
      });
    });

    resources.forEach((resource) => {
      const organizationIDs = new Set();
      if (resource.organization_id) organizationIDs.add(resource.organization_id);

      const gatewayOrganizations = gatewayOrganizationIDs.get(resource.gateway_id);
      gatewayOrganizations?.forEach((organizationID) => organizationIDs.add(organizationID));

      organizationIDs.forEach((organizationID) => {
        resourceCounts.set(organizationID, (resourceCounts.get(organizationID) || 0) + 1);
      });
    });

    return { gatewayCounts, resourceCounts };
  }, [gateways, resources]);

  const hasFilters = query.trim();
  const organizationPagination = usePaginatedTable(filteredOrganizations);

  const handleQueryChange = (value) => {
    setQuery(value);
    organizationPagination.resetPage();
  };

  const confirmRevokeOrganization = async () => {
    await organizationDirectory.handleRevoke(revokeOrganizationTarget);
    setRevokeOrganizationTarget(null);
  };

  const confirmReactivateOrganization = async () => {
    await organizationDirectory.handleReactivate(reactivateOrganizationTarget);
    setReactivateOrganizationTarget(null);
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <PageHeader
        title="Organizations"
        subtitle="Manage organizations, identity providers, and gateways"
        createLabel="Add Organization"
        onCreate={organizationDirectory.openCreate}
      />

      <ListToolbar
        query={query}
        onQueryChange={handleQueryChange}
        placeholder="Search organization or domain"
      />

      <div className="min-h-0 flex-1">
        <OrganizationTable
          loading={organizationDirectory.loading}
          organizations={organizationPagination.pageItems}
          gatewayCounts={organizationStats.gatewayCounts}
          resourceCounts={organizationStats.resourceCounts}
          pageSize={organizationPagination.pageSize}
          onCreateGateway={gatewayCreate.openGatewayCreate}
          onOpen={openOrganization}
          onEdit={organizationDirectory.openEdit}
          onRevoke={setRevokeOrganizationTarget}
          onReactivate={setReactivateOrganizationTarget}
          emptyTitle={hasFilters ? 'No organizations match filters' : 'No organizations yet'}
          emptyMessage={hasFilters ? 'Adjust search or filters to find organizations.' : 'Create the first organization to start managing gateways and resources.'}
        />
      </div>

      {/* <div className="pt-6">
        <Pagination
          currentPage={organizationPagination.currentPage}
          totalPages={organizationPagination.totalPages}
          onPageChange={organizationPagination.setCurrentPage}
        />
      </div> */}

      <OrganizationFormModal
        mode={organizationDirectory.modal}
        form={organizationDirectory.form}
        setForm={organizationDirectory.setForm}
        saving={organizationDirectory.saving}
        onClose={organizationDirectory.closeModal}
        onSave={organizationDirectory.handleSave}
      />

      <ConfirmDialog
        open={!!revokeOrganizationTarget}
        onClose={() => setRevokeOrganizationTarget(null)}
        onConfirm={confirmRevokeOrganization}
        title="Revoke organization"
        message={
          revokeOrganizationTarget
            ? `Revoke "${revokeOrganizationTarget.name}"? New access through this organization will be disabled, while the organization record remains available for review.`
            : ''
        }
        confirmLabel="Revoke organization"
        loadingLabel="Revoking..."
        loading={organizationDirectory.revoking}
      />

      <ConfirmDialog
        open={!!reactivateOrganizationTarget}
        onClose={() => setReactivateOrganizationTarget(null)}
        onConfirm={confirmReactivateOrganization}
        title="Reactivate organization"
        message={
          reactivateOrganizationTarget
            ? `Reactivate "${reactivateOrganizationTarget.name}"? Access policies and resources under this organization can become available again.`
            : ''
        }
        confirmLabel="Reactivate organization"
        confirmVariant="primary"
        loadingLabel="Reactivating..."
        loading={organizationDirectory.reactivating}
      />

      {gatewayCreate.open ? (
        <GatewayCreateModal
          organization={gatewayCreate.organization}
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
