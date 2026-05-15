import { ArrowLeft, CheckCircle2, FileText } from 'lucide-react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import {
  BackIconButton,
  DetailDivider,
  DetailSummaryItem,
  detailSectionTitleClass,
} from '../ui/Detail';
import FormField, { FormInput, FormSelect, FormTextarea } from '../ui/FormField';
import { ActionBadge, LayerBadge } from './PolicyBadges';
import { sectionIcons } from './policyIcons';
import {
  POLICY_GROUPS,
  POLICY_SECTIONS,
  isSectionConfigured,
  targetLabel,
} from './policyModel';

function SectionToggle({ checked, onChange }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={`relative h-6 w-11 shrink-0 rounded-full border transition-colors ${
        checked ? 'border-accent bg-accent' : 'border-border bg-surface-secondary'
      }`}
      aria-pressed={checked}
    >
      <span
        className={`absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white-smoke shadow-sm transition-transform ${
          checked ? 'translate-x-5' : 'translate-x-0'
        }`}
      />
    </button>
  );
}

function AssignmentList({ assignments, maps }) {
  if (!assignments.length) {
    return (
      <p className="mt-2 px-4 py-3 text-sm font-semibold text-text-secondary">
        This policy is not applied yet.
      </p>
    );
  }

  return (
    <div className="mt-2 space-y-2">
      {assignments.map((assignment) => (
        <DetailSummaryItem key={assignment.id} className="rounded-md border border-border-light bg-surface-card">
          <span className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="truncate text-base font-semibold text-text-primary">
              {targetLabel(assignment, maps)}
            </span>
            <LayerBadge level={assignment.level} />
          </span>
          <span className="mt-1 block truncate text-xs text-text-secondary">
            {maps.organizations.get(assignment.tenant_id)?.name || assignment.tenant_id}
          </span>
        </DetailSummaryItem>
      ))}
    </div>
  );
}

function PolicyNavItem({ section, active, configured, onClick }) {
  const Icon = sectionIcons[section.id] || FileText;

  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex w-full items-center gap-3 border-l-2 px-3 py-3 text-left transition-colors ${
        active
          ? 'border-accent text-accent'
          : 'border-transparent text-text-secondary hover:text-text-primary'
      }`}
    >
      <Icon size={16} className="shrink-0" />
      <span className="min-w-0 flex-1">
        <span className={`block truncate font-bold ${active ? 'text-sm' : 'text-[13px]'}`}>{section.label}</span>
        <span className="mt-0.5 block truncate text-[11px] font-medium text-text-muted">{section.category}</span>
      </span>
      <span className={`grid h-5 w-5 shrink-0 place-items-center rounded-full ${
        configured ? 'bg-success-muted text-success' : 'bg-surface-secondary text-text-muted'
      }`}>
        {configured ? <CheckCircle2 size={13} /> : <span className="h-1.5 w-1.5 rounded-full bg-current opacity-45" />}
      </span>
    </button>
  );
}

function DetailsSection({ form, setForm, assignments, maps }) {
  return (
    <div>
      <p className={detailSectionTitleClass}>Policy details</p>
      <div className="mt-3 grid max-w-4xl gap-x-4 gap-y-1 md:grid-cols-2">
        <FormField label="Policy name" className="mb-3 md:col-span-2">
          <FormInput
            value={form.name}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
            placeholder="Finance Payroll MFA"
          />
        </FormField>
        <FormField label="Description" className="mb-3 md:col-span-2">
          <FormTextarea
            value={form.description}
            onChange={(event) => setForm({ ...form, description: event.target.value })}
            placeholder="Short internal description"
          />
        </FormField>
        <FormField label="Policy priority" className="mb-3">
          <FormInput
            type="number"
            value={form.priority}
            onChange={(event) => setForm({ ...form, priority: event.target.value })}
          />
        </FormField>
        <FormField label="Status" className="mb-3">
          <FormSelect
            value={form.enabled === false ? 'disabled' : 'enabled'}
            onChange={(event) => setForm({ ...form, enabled: event.target.value === 'enabled' })}
          >
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </FormSelect>
        </FormField>
      </div>

      <div className="mt-5">
        <p className={detailSectionTitleClass}>Assignments ({assignments.length})</p>
        <AssignmentList assignments={assignments} maps={maps} />
      </div>
    </div>
  );
}

function RadioOption({ name, value, selected, title, description, onSelect }) {
  return (
    <label className={`block cursor-pointer rounded-md border px-4 py-3 transition-colors ${
      selected ? 'border-accent bg-accent-muted' : 'border-border-light bg-surface-card hover:border-accent hover:bg-accent-muted'
    }`}>
      <input
        type="radio"
        name={name}
        checked={selected}
        onChange={() => onSelect(value)}
        className="sr-only"
      />
      <span className="flex items-start gap-3">
        <span className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full border ${
          selected ? 'border-accent bg-accent' : 'border-border bg-surface'
        }`}>
          <span className={`h-2 w-2 rounded-full bg-white-smoke transition-opacity ${selected ? 'opacity-100' : 'opacity-0'}`} />
        </span>
        <span className="min-w-0">
          <span className="block text-sm font-bold text-text-primary">{title}</span>
          <span className="mt-1 block text-xs leading-5 text-text-secondary">{description}</span>
        </span>
      </span>
    </label>
  );
}

function ActionSection({ form, setForm }) {
  return (
    <div className="grid max-w-5xl gap-3 lg:grid-cols-3">
      {[
        { value: 'mfa_required', title: 'Require MFA', description: 'Require multi-factor authentication when this policy matches.' },
        { value: 'allow', title: 'Allow access', description: 'Allow users to access the resource when all added conditions match.' },
        { value: 'deny', title: 'Deny access', description: 'Block access when this policy matches. Put deny rules above allow rules for hard exclusions.' },
      ].map((option) => (
        <RadioOption
          key={option.value}
          name="policy-action"
          value={option.value}
          selected={form.action === option.value}
          title={option.title}
          description={option.description}
          onSelect={(value) => setForm({ ...form, action: value })}
        />
      ))}
    </div>
  );
}

function DeviceSection({ form, setForm }) {
  return (
    <div className="grid max-w-4xl gap-x-4 gap-y-1 md:grid-cols-2">
      <FormField label="Required device checks" className="mb-3">
        <FormInput
          value={form.required_checks}
          onChange={(event) => setForm({ ...form, required_checks: event.target.value })}
          placeholder="disk_encryption, firewall"
        />
      </FormField>
      <FormField label="Required check status" className="mb-3">
        <FormSelect
          value={form.required_check_status}
          onChange={(event) => setForm({ ...form, required_check_status: event.target.value })}
        >
          <option value="">Any status</option>
          <option value="pass">Pass</option>
          <option value="healthy">Healthy</option>
          <option value="ok">OK</option>
        </FormSelect>
      </FormField>
    </div>
  );
}

function PolicyConfigSection({ section, added, onToggle, children }) {
  return (
    <div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className={detailSectionTitleClass}>{section.label}</p>
          <p className="mt-1 max-w-3xl text-sm text-text-secondary">{section.description}</p>
        </div>
        {section.required ? (
          <Badge variant="accent">Required</Badge>
        ) : (
          <div className="flex shrink-0 items-center gap-2">
            <span className="text-xs font-bold text-text-secondary">Add</span>
            <SectionToggle checked={added} onChange={onToggle} />
          </div>
        )}
      </div>
      <div className="mt-4">
        {section.required || added ? (
          children
        ) : (
          <p className="rounded-md border border-border-light bg-surface-card px-4 py-3 text-sm font-semibold text-text-secondary">
            Turn on Add to include this condition in the saved policy.
          </p>
        )}
      </div>
    </div>
  );
}

export default function PolicyEditor({
  editor,
  form,
  setForm,
  assignments,
  maps,
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
        <DeviceSection form={form} setForm={setForm} />
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
                    <ActionBadge action={form.action} />
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
