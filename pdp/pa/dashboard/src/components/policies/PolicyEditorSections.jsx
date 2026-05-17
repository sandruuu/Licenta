import { Check, FileText } from 'lucide-react';
import Badge from '../ui/Badge';
import {
  DetailSummaryItem,
  detailSectionTitleClass,
} from '../ui/Detail';
import FormField, { FormCheckbox, FormInput, FormTextarea } from '../ui/FormField';
import { LayerBadge } from './PolicyBadges';
import { sectionIcons } from './policyIcons';
import {
  assignmentScopeLabel,
  listToText,
  requiredDeviceChecksFromValue,
  targetLabel,
  toggleListValue,
} from './policyModel';

function SectionToggle({ checked, onChange }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={`inline-flex h-6 w-11 shrink-0 items-center rounded-full border p-0.5 align-middle transition-colors ${
        checked ? 'border-accent bg-accent' : 'border-border bg-surface-secondary'
      }`}
      aria-pressed={checked}
    >
      <span
        className={`block h-4 w-4 rounded-full bg-white-smoke shadow-sm transition-transform ${
          checked ? 'translate-x-6' : 'translate-x-0'
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
            {assignmentScopeLabel(assignment, maps) || maps.organizations.get(assignment.tenant_id)?.name || assignment.tenant_id}
          </span>
        </DetailSummaryItem>
      ))}
    </div>
  );
}

export function PolicyNavItem({ section, active, configured, onClick }) {
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
      <span className="grid h-5 w-5 shrink-0 place-items-center text-success">
        {configured ? <Check size={15} strokeWidth={3} className="block" /> : null}
      </span>
    </button>
  );
}

export function DetailsSection({ form, setForm, assignments, maps }) {
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
        <FormCheckbox
          id="policy-enabled"
          checked={form.enabled !== false}
          onChange={(event) => setForm({ ...form, enabled: event.target.checked })}
          label="Enabled"
        />
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
      <span className="flex items-center gap-3">
        <span className={`grid h-2 w-2 shrink-0 place-items-center rounded-full border ${
          selected ? 'border-accent bg-accent' : 'border-border bg-surface'
        }`} />
        <span className="min-w-0">
          <span className="block text-sm font-bold text-text-primary">{title}</span>
          <span className="mt-1 block text-xs leading-5 text-text-secondary">{description}</span>
        </span>
      </span>
    </label>
  );
}

export function ActionSection({ form, setForm }) {
  return (
    <div className="grid max-w-3xl gap-3">
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

export function DeviceSection({ form, setForm, deviceCheckOptions }) {
  const selectedChecks = requiredDeviceChecksFromValue(form.required_checks);
  const toggleCheck = (checkName) => {
    const nextChecks = toggleListValue(selectedChecks, checkName);
    setForm({
      ...form,
      required_checks: listToText(nextChecks),
      required_check_status: nextChecks.length ? form.required_check_status : '',
    });
  };

  return (
    <div className="grid max-w-4xl gap-4">
      <FormField
        label="Required device health checks"
        className="mb-0"
      >
        <div className="grid max-w-3xl gap-3">
          {deviceCheckOptions.map((option) => {
            const checked = selectedChecks.includes(option.value);
            return (
              <button
                type="button"
                key={option.value}
                onClick={() => toggleCheck(option.value)}
                className={`block rounded-md border px-4 py-3 text-left transition-colors ${
                  checked ? 'border-accent bg-accent-muted' : 'border-border-light bg-surface-card hover:border-accent hover:bg-accent-muted'
                }`}
                aria-pressed={checked}
              >
                <span className="flex items-center gap-3">
                  <span
                    className={`grid h-2 w-2 shrink-0 place-items-center rounded-md border transition-colors ${
                      checked ? 'border-accent bg-accent text-white-smoke' : 'border-border bg-surface text-transparent'
                    }`}
                    aria-hidden="true"
                  />
                  <span className="min-w-0">
                    <span className="block text-sm font-bold text-text-primary">{option.label}</span>
                  </span>
                </span>
              </button>
            );
          })}
          {selectedChecks.length > 0 && (
            <button
              type="button"
              onClick={() => setForm({ ...form, required_checks: '', required_check_status: '' })}
              className="w-fit text-xs font-bold text-accent hover:text-accent-hover"
            >
              Clear selected checks
            </button>
          )}
        </div>
      </FormField>
    </div>
  );
}

export function PolicyConfigSection({ section, added, onToggle, children }) {
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
          <div className="flex h-8 shrink-0 items-center gap-2">
            <span className="text-xs font-bold leading-none text-text-secondary">Add</span>
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
