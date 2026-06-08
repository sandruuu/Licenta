import { useState } from 'react';
import { ChevronLeft } from 'lucide-react';
import Button from '../ui/Button';
import ConfirmDialog from '../ui/ConfirmDialog';
import StatusText from '../ui/StatusText';
import {
  AuthenticationPolicySection,
  AuthorizedNetworksSection,
  DetailsSection,
  DeviceSection,
  NewUserSection,
  PolicyConfigSection,
  PolicyNavItem,
  RiskBasedAuthenticationSection,
  UserLocationSection,
} from './PolicyEditorSections';
import {
  POLICY_GROUPS,
  POLICY_SECTIONS,
  isSectionConfigured,
} from './policyModel';

export default function PolicyEditor({
  editor,
  form,
  setForm,
  assignments,
  maps,
  deviceCheckOptions,
  saving,
  onBack,
  onSave,
  onUnassignAssignment,
  onToggleSection,
  onSelectSection,
}) {
  const [unassignTarget, setUnassignTarget] = useState(null);
  const sectionByID = new Map(POLICY_SECTIONS.map((section) => [section.id, section]));
  const selectedSection = sectionByID.get(editor.activeSection) || sectionByID.get('details');
  const navGroups = [
    { label: 'Policy', sections: ['details'] },
    ...POLICY_GROUPS,
  ];

  const sectionContent = {
    newuser: <NewUserSection form={form} setForm={setForm} />,
    stepup: <AuthenticationPolicySection form={form} setForm={setForm} />,
    riskbasedauth: <RiskBasedAuthenticationSection form={form} setForm={setForm} />,
    location: <UserLocationSection form={form} setForm={setForm} />,
    devicehealth: <DeviceSection form={form} setForm={setForm} deviceCheckOptions={deviceCheckOptions} />,
    authorizednetworks: <AuthorizedNetworksSection form={form} setForm={setForm} />,
  };

  const renderSelectedSection = () => {
    if (selectedSection.id === 'details') {
      return (
        <DetailsSection
          form={form}
          setForm={setForm}
          assignments={assignments}
          maps={maps}
          saving={saving}
          onUnassignRequest={setUnassignTarget}
        />
      );
    }

    return (
      <PolicyConfigSection
        section={selectedSection}
        added={selectedSection.required || !!editor.enabledSections[selectedSection.id]}
        onToggle={selectedSection.required ? null : (value) => onToggleSection(selectedSection.id, value)}
      >
        {sectionContent[selectedSection.id]}
      </PolicyConfigSection>
    );
  };

  const confirmUnassign = async () => {
    if (!unassignTarget) return;
    await onUnassignAssignment?.(unassignTarget);
    setUnassignTarget(null);
  };

  return (
    <div className="space-y-7">
      <section className="flex h-[calc(100vh-64px)] min-h-0 flex-col space-y-5 pb-5 pr-3 pt-1">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                aria-label="Back"
                onClick={onBack}
                className="-ml-2 inline-flex h-11 w-11 shrink-0 items-center justify-center text-text-primary transition-colors hover:text-accent focus-visible:text-accent active:text-accent-hover"
              >
                <ChevronLeft size={34} strokeWidth={3} />
              </button>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-3">
                  <h1 className="text-2xl font-bold leading-tight text-text-primary">
                    {editor.mode === 'edit' ? (form.name || 'Edit Policy') : 'Create Policy'}
                  </h1>
                  <StatusText variant={form.enabled === false ? 'danger' : 'success'}>
                    {form.enabled === false ? 'Disabled' : 'Enabled'}
                  </StatusText>
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
                  <span>{editor.mode === 'edit' ? 'Edit policy configuration' : 'Create a new access policy'}</span>
                </div>
              </div>
            </div>
            {form.description && <p className="mt-4 max-w-3xl text-sm text-text-secondary">{form.description}</p>}
          </div>
        </div>

        <div className="border-t border-border" />

        <div className="grid min-h-0 flex-1 grid-cols-1 gap-6 overflow-hidden xl:grid-cols-[270px_minmax(0,1fr)]">
          <aside className="flex min-h-0 flex-col rounded-md border border-border bg-transparent p-3">
            <div className="min-h-0 flex-1 overflow-y-auto pr-3">
              {navGroups.map((group) => (
                <div key={group.label} className="mb-4 last:mb-0">
                  <p className="mb-1 px-3 text-[11px] font-bold uppercase tracking-[0.12em] text-text-muted">{group.label}</p>
                  <div className="space-y-1">
                    {group.sections.map((sectionID) => {
                      const section = sectionByID.get(sectionID);
                      if (!section) return null;
                      return (
                        <PolicyNavItem
                          key={section.id}
                          section={section}
                          active={selectedSection.id === section.id}
                          configured={isSectionConfigured(section, form, editor.enabledSections)}
                          onClick={() => onSelectSection(section.id)}
                        />
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-4 border-t border-border pt-3">
              <div className="flex flex-col gap-2">
                <Button className="justify-center" onClick={onSave} disabled={saving || !form.name.trim()}>
                  {saving ? 'Saving...' : 'Save'}
                </Button>
                <Button variant="secondary" className="justify-center" onClick={onBack}>Cancel</Button>
              </div>
            </div>
          </aside>
          <main className="min-h-0 min-w-0 overflow-y-auto pr-4 [scrollbar-gutter:stable]">
            {renderSelectedSection()}
          </main>
        </div>
      </section>
      <ConfirmDialog
        open={!!unassignTarget}
        onClose={() => setUnassignTarget(null)}
        onConfirm={confirmUnassign}
        title="Unassign policy"
        message={unassignTarget ? `Are you sure you want to unassign this policy from "${unassignTarget.label}"?` : ''}
        confirmLabel="Unassign"
        loadingLabel="Unassigning..."
        loading={saving}
      />
    </div>
  );
}
