import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import GatewayCreateModal from '../components/organizations/GatewayCreateModal';
import OrganizationFormModal from '../components/organizations/OrganizationFormModal';
import OrganizationTable from '../components/organizations/OrganizationTable';
import useGatewayCreate from '../components/organizations/useGatewayCreate';
import useOrganizationDirectory from '../components/organizations/useOrganizationDirectory';
import ListToolbar from '../components/ui/ListToolbar';
import PageHeader from '../components/ui/PageHeader';
import Pagination from '../components/ui/Pagination';
import { usePaginatedTable } from '../components/ui/usePaginatedTable';

export default function Organizations() {
  const navigate = useNavigate();
  const organizationDirectory = useOrganizationDirectory();
  const gatewayCreate = useGatewayCreate(organizationDirectory.load);
  const [query, setQuery] = useState('');

  const openOrganization = (organization) => {
    if (organization?.id) navigate(`/dashboard/organizations/${encodeURIComponent(organization.id)}`);
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

  const hasFilters = query.trim();
  const organizationPagination = usePaginatedTable(filteredOrganizations);

  const handleQueryChange = (value) => {
    setQuery(value);
    organizationPagination.resetPage();
  };

  return (
    <div className="pb-8">
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

      <OrganizationTable
        loading={organizationDirectory.loading}
        organizations={organizationPagination.pageItems}
        pageSize={organizationPagination.pageSize}
        onCreateGateway={gatewayCreate.openGatewayCreate}
        onOpen={openOrganization}
        onEdit={organizationDirectory.openEdit}
        onDelete={organizationDirectory.handleDelete}
        emptyTitle={hasFilters ? 'No organizations match filters' : 'No organizations yet'}
        emptyMessage={hasFilters ? 'Adjust search or filters to find organizations.' : 'Create the first organization to start managing gateways and resources.'}
      />

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
