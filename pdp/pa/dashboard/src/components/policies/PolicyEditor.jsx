import { ArrowLeft } from 'lucide-react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import {
  BackIconButton,
  DetailDivider,
} from '../ui/Detail';
import {
  ActionSection,
  DetailsSection,
  DeviceSection,
  PolicyConfigSection,
  PolicyNavItem,
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
  onToggleSection,
  onSelectSection,
}) {
  const actionSection = POLICY_SECTIONS.find((section) => section.id === 'action');
  const deviceSection = POLICY_SECTIONS.find((section) => section.id === 'device');
  const sectionByID = new Map(POLICY_SECTIONS.map((section) => [section.id, section]));
  const selectedSection = sectionByID.get(editor.activeSection) || sectionByID.get('details');
  const deviceAdded = !!editor.enabledSections.device;
  const navGroups = [
    { label: 'Policy', sections: ['details'] },
    ...POLICY_GROUPS,
  ];

  const renderSelectedSection = () => {
    if (selectedSection.id === 'details') {
      return <DetailsSection form={form} setForm={setForm} assignments={assignments} maps={maps} />;
    }

    if (selectedSection.id === 'action') {
      return (
        <PolicyConfigSection section={actionSection} added>
          <ActionSection form={form} setForm={setForm} />
        </PolicyConfigSection>
      );
    }

    return (
      <PolicyConfigSection
        section={deviceSection}
        added={deviceAdded}
        onToggle={(value) => onToggleSection(deviceSection.id, value)}
      >
        <DeviceSection form={form} setForm={setForm} deviceCheckOptions={deviceCheckOptions} />
      </PolicyConfigSection>
    );
  };

  return (
    <div className="space-y-7">
      <section className="p-5">
        <div className="space-y-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-start gap-3">
                <BackIconButton compact title="Back" onClick={onBack}>
                  <ArrowLeft size={16} />
                </BackIconButton>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-3">
                    <h1 className="text-2xl font-bold leading-tight text-text-primary">
                      {editor.mode === 'edit' ? (form.name || 'Edit Policy') : 'Create Policy'}
                    </h1>
                    <Badge variant={form.enabled === false ? 'danger' : 'success'}>
                      {form.enabled === false ? 'Disabled' : 'Enabled'}
                    </Badge>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
                    <span>{editor.mode === 'edit' ? 'Edit policy configuration' : 'Create a new access policy'}</span>
                  </div>
                </div>
              </div>
              {form.description && <p className="mt-4 max-w-3xl text-sm text-text-secondary">{form.description}</p>}
            </div>
          </div>

          <DetailDivider />

          <div className="grid overflow-hidden rounded-md xl:grid-cols-[270px_minmax(0,1fr)]">
            <aside className="flex min-h-[520px] flex-col rounded-md border border-border p-3 xl:border-r">
              <div className="flex-1">
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
              <div className="border-t border-border pt-3">
                <div className="flex flex-col gap-2">
                  <Button variant="secondary" className="justify-center" onClick={onBack}>Cancel</Button>
                  <Button className="justify-center" onClick={onSave} disabled={saving || !form.name.trim()}>
                    {saving ? 'Saving...' : 'Save Policy'}
                  </Button>
                </div>
              </div>
            </aside>
            <main className="min-h-[520px] p-5">
              {renderSelectedSection()}
            </main>
          </div>
        </div>
      </section>
    </div>
  );
}
