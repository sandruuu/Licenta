import { useState } from 'react';
import { Check, FileText, Plus, Unlink, X } from 'lucide-react';
import FormField, { FormCheckbox, FormInput, FormSelect, FormTextarea } from '../ui/FormField';
import StatusText from '../ui/StatusText';
import { layerIcons, sectionIcons } from './policyIcons';
import {
  ACCESS_CONDITION_GROUPS,
  AUTHENTICATION_POLICIES,
  COUNTRY_OPTIONS,
  NEW_USER_POLICIES,
  STEP_UP_METHOD_OPTIONS,
  USER_LOCATION_ACTIONS,
  actionFromAuthenticationPolicy,
  assignmentTargetLabel,
  countryLabel,
  createUserLocationRule,
  isDefaultGlobalAssignment,
  layerMeta,
  listToText,
  normalizeStepUpMethods,
  normalizeUserLocationRules,
  requiredDeviceChecksFromValue,
  splitList,
  toggleListValue,
} from './policyModel';
import { displayGatewayName, displayOrganizationName } from '../../utils/displayNames';

const assignmentCardClass = 'block w-full rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-3 py-3 text-left shadow-[0_6px_14px_rgba(42,42,42,0.10)] transition-[border-color,background-color,box-shadow] duration-150 hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_8px_16px_rgba(42,42,42,0.12)]';
const sectionTitleClass = 'text-[20px] font-bold leading-tight text-text-primary';
const sectionCountClass = 'text-sm font-bold text-text-muted';
const shadowSafeContentClass = 'px-2 pb-5 pt-1';
const optionClass = 'block rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-4 py-3 text-left shadow-[0_8px_16px_rgba(42,42,42,0.10)] transition-[border-color,background-color,box-shadow] duration-150 hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.12)]';
const optionSelectedClass = 'border-accent bg-[rgba(44,97,100,0.12)] shadow-[0_10px_18px_rgba(42,42,42,0.14)]';

function DetailsHeading({ children }) {
  return <p className={sectionTitleClass}>{children}</p>;
}

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

function assignmentLocationLabel(assignment, maps) {
  const resource = maps.resources?.get(assignment.resource_id);
  const gateway = maps.gateways?.get(resource?.gateway_id || assignment.gateway_id);
  const organization = maps.organizations?.get(assignment.organization_id);
  return [
    gateway ? displayGatewayName(gateway) : '',
    organization ? displayOrganizationName(organization) : '',
  ].filter(Boolean).join(' / ');
}

function AssignmentList({ assignments, maps, saving, onUnassignRequest }) {
  if (!assignments.length) {
    return (
      <p className="mt-2 px-4 py-3 text-sm font-semibold text-text-secondary">
        This policy is not applied yet.
      </p>
    );
  }

  return (
    <div className="mt-1 grid gap-2 px-2 pb-4 pt-1 lg:grid-cols-2">
      {assignments.map((assignment) => {
        const meta = layerMeta(assignment.level);
        const Icon = layerIcons[assignment.level] || FileText;
        const target = assignmentTargetLabel(assignment, maps);
        const defaultAssignment = isDefaultGlobalAssignment(assignment);
        return (
          <div key={assignment.id} className={assignmentCardClass}>
            <div className="min-w-0">
              <div className="flex min-w-0 items-center justify-between gap-2">
                <p className="inline-flex min-w-0 items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.1em] text-accent">
                  <Icon size={12} className="shrink-0" />
                  <span className="truncate">{meta.shortLabel}</span>
                </p>
                <button
                  type="button"
                  disabled={saving || defaultAssignment}
                  onClick={(event) => {
                    event.stopPropagation();
                    onUnassignRequest?.({ ...assignment, label: target });
                  }}
                  className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-danger transition-colors hover:bg-danger-muted disabled:cursor-not-allowed disabled:text-text-muted disabled:opacity-60 disabled:hover:bg-transparent"
                  title="Unassign"
                  aria-label={`Unassign ${target}`}
                >
                  <Unlink size={14} />
                </button>
              </div>
              <div className="min-w-0">
                <p className="mt-2 truncate text-sm font-semibold text-text-primary">{target}</p>
                <p className="mt-1 truncate text-xs font-semibold text-text-secondary">
                  {assignmentLocationLabel(assignment, maps) || '-'}
                </p>
              </div>
            </div>
          </div>
        );
      })}
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

export function DetailsSection({ form, setForm, assignments, maps, saving, onUnassignRequest }) {
  return (
    <div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <DetailsHeading>Policy details</DetailsHeading>
        <StatusText variant="success">Required</StatusText>
      </div>
      <div className={`mt-3 grid max-w-4xl gap-x-4 gap-y-1 md:grid-cols-2 ${shadowSafeContentClass}`}>
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
        <DetailsHeading>
          Assignments <span className={sectionCountClass}>({assignments.length})</span>
        </DetailsHeading>
        <AssignmentList assignments={assignments} maps={maps} saving={saving} onUnassignRequest={onUnassignRequest} />
      </div>
    </div>
  );
}

function RadioOption({ name, value, selected, title, description, onSelect }) {
  return (
    <div className={`${optionClass} ${selected ? optionSelectedClass : ''}`}>
      <label className="flex cursor-pointer items-center gap-3">
        <input
          type="radio"
          name={name}
          checked={selected}
          onChange={() => onSelect(value)}
          className="sr-only"
        />
        <span className={`grid h-2 w-2 shrink-0 place-items-center rounded-full border ${
          selected ? 'border-accent bg-accent' : 'border-border bg-surface'
        }`} />
        <span className="min-w-0">
          <span className="block text-sm font-bold text-text-primary">{title}</span>
          <span className="mt-1 block text-xs leading-5 text-text-secondary">{description}</span>
        </span>
      </label>
    </div>
  );
}

export function NewUserSection({ form, setForm }) {
  return (
    <div className="grid max-w-3xl gap-3">
      {NEW_USER_POLICIES.map((option) => (
        <RadioOption
          key={option.value}
          name="new-user-policy"
          value={option.value}
          selected={(form.new_user_policy || 'require_enrollment') === option.value}
          title={option.title}
          description={option.description}
          onSelect={(value) => setForm({ ...form, new_user_policy: value })}
        />
      ))}
    </div>
  );
}

function StepUpMethodsCheckboxes({ form, setForm }) {
  const selectedStepUpMethods = normalizeStepUpMethods(form.step_up_methods);
  const requiredMethod = STEP_UP_METHOD_OPTIONS[0]?.value;
  const toggleStepUpMethod = (method) => {
    if (method === requiredMethod) return;
    const nextMethods = toggleListValue(selectedStepUpMethods, method);
    setForm({ ...form, step_up_methods: listToText(normalizeStepUpMethods(nextMethods)) });
  };

  return (
    <div className="grid gap-2">
      {STEP_UP_METHOD_OPTIONS.map((method) => {
        const checked = selectedStepUpMethods.includes(method.value);
        const required = method.value === requiredMethod;
        return (
          <label
            key={method.value}
            className={`inline-flex select-none items-center gap-2 text-sm font-semibold text-text-secondary ${
              required ? 'cursor-default' : 'cursor-pointer hover:text-text-primary'
            }`}
          >
            <input
              type="checkbox"
              checked={checked}
              disabled={required}
              onChange={() => toggleStepUpMethod(method.value)}
              className="peer sr-only"
              aria-label={required ? `${method.label} required` : method.label}
            />
            <span
              aria-hidden="true"
              className={`grid h-5 w-5 shrink-0 place-items-center rounded-md border transition-colors peer-focus-visible:ring-[3px] peer-focus-visible:ring-accent-muted ${
                checked
                  ? 'border-accent bg-accent text-white-smoke'
                  : 'border-border bg-surface text-transparent'
              }`}
            >
              <Check size={14} strokeWidth={3} />
            </span>
            <span>{method.label}</span>
          </label>
        );
      })}
    </div>
  );
}

export function AuthenticationPolicySection({ form, setForm }) {
  return (
    <div className="grid max-w-4xl gap-5">
      <div className="grid max-w-3xl gap-3">
      {AUTHENTICATION_POLICIES.map((option) => {
        const selected = (form.authentication_policy || 'enforce_mfa') === option.value;
        return (
          <div key={option.value} className={`grid gap-2 ${option.value === 'enforce_mfa' && selected ? 'mb-2' : ''}`}>
            <RadioOption
              name="authentication-policy"
              value={option.value}
              selected={selected}
              title={option.title}
              description={option.description}
              onSelect={(value) => setForm({
                ...form,
                authentication_policy: value,
                action: actionFromAuthenticationPolicy(value),
              })}
            />
            {option.value === 'enforce_mfa' && selected ? (
              <div className="ml-7 mt-2">
                <StepUpMethodsCheckboxes form={form} setForm={setForm} />
              </div>
            ) : null}
          </div>
        );
      })}
      </div>
    </div>
  );
}

export function RiskBasedAuthenticationSection() {
  return (
    <div className="grid max-w-4xl gap-4">
      <div className="rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] p-4 shadow-[0_8px_16px_rgba(42,42,42,0.10)]">
        <p className="text-sm font-bold text-text-primary">Require MFA when risk is detected</p>
        <p className="mt-2 max-w-3xl text-xs leading-5 text-text-secondary">
          Uses the internal detectors for new location, unrealistic travel, and user baseline anomaly.
        </p>
      </div>
      <p className="max-w-3xl text-xs font-semibold leading-5 text-text-secondary">
        User baseline requires at least 5 successful geolocated accesses across 3 distinct days in the last 30 days.
      </p>
    </div>
  );
}

function LocationActionOptions({ name, value, onChange }) {
  return (
    <div className="grid gap-3">
      {USER_LOCATION_ACTIONS.map((option) => {
        const selected = value === option.value;
        return (
          <label key={option.value} className="flex cursor-pointer items-start gap-3">
            <input
              type="radio"
              name={name}
              value={option.value}
              checked={selected}
              onChange={() => onChange(option.value)}
              className="peer sr-only"
            />
            <span
              aria-hidden="true"
              className={`mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full border transition-colors ${
                selected ? 'border-accent' : 'border-border'
              }`}
            >
              <span className={`h-2 w-2 rounded-full ${selected ? 'bg-accent' : 'bg-transparent'}`} />
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-bold leading-5 text-text-primary">{option.title}</span>
              {option.description && (
                <span className="mt-0.5 block max-w-3xl text-xs leading-5 text-text-secondary">{option.description}</span>
              )}
            </span>
          </label>
        );
      })}
    </div>
  );
}

function splitNetworkInput(value) {
  return String(value || '')
    .replace(/\s*-\s*/g, '-')
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function isIPv4(value) {
  const parts = String(value || '').split('.');
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const number = Number(part);
    return number >= 0 && number <= 255 && part === String(number);
  });
}

function isIPv6Like(value) {
  return /^[0-9a-fA-F:]+$/.test(value) && value.includes(':');
}

function isValidNetworkValue(value) {
  if (String(value || '').includes('-') && !String(value || '').includes('/')) {
    const parts = String(value || '').split('-').map((part) => part.trim());
    return parts.length === 2 &&
      parts.every((part) => isIPv4(part) || isIPv6Like(part)) &&
      parts.some(Boolean);
  }
  const [address, prefix, extra] = String(value || '').split('/');
  if (!address || extra !== undefined) return false;
  if (prefix === undefined) return isIPv4(address) || isIPv6Like(address);
  if (!/^\d+$/.test(prefix)) return false;
  const prefixLength = Number(prefix);
  if (isIPv4(address)) return prefixLength >= 0 && prefixLength <= 32;
  if (isIPv6Like(address)) return prefixLength >= 0 && prefixLength <= 128;
  return false;
}

function NetworkListEditor({ value, onChange, placeholder, disabled }) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');
  const values = splitList(value);

  const addValues = (rawValue) => {
    const tokens = splitNetworkInput(rawValue);
    if (!tokens.length) return;
    const invalid = tokens.filter((token) => !isValidNetworkValue(token));
    if (invalid.length) {
      setError(`Invalid IP or CIDR: ${invalid.join(', ')}`);
      return;
    }
    const seen = new Set(values.map((item) => item.toLowerCase()));
    const nextValues = [...values];
    tokens.forEach((token) => {
      const key = token.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        nextValues.push(token);
      }
    });
    onChange(nextValues);
    setDraft('');
    setError('');
  };

  const removeValue = (item) => {
    onChange(values.filter((valueItem) => valueItem !== item));
    setError('');
  };

  return (
    <div className="grid gap-2">
      <div className="flex gap-2">
        <FormInput
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              addValues(draft);
            }
          }}
          onPaste={(event) => {
            const text = event.clipboardData.getData('text');
            if (splitNetworkInput(text).length > 1) {
              event.preventDefault();
              addValues(text);
            }
          }}
          placeholder={placeholder}
          disabled={disabled}
        />
        <button
          type="button"
          onClick={() => addValues(draft)}
          disabled={disabled || !draft.trim()}
          className="grid h-[38px] w-[42px] shrink-0 place-items-center rounded-md border border-accent text-accent hover:bg-accent-muted disabled:cursor-not-allowed disabled:border-border disabled:text-text-muted disabled:hover:bg-transparent"
          aria-label="Add network"
        >
          <Plus size={16} />
        </button>
      </div>
      {error && <p className="text-xs font-semibold text-danger">{error}</p>}
      {values.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {values.map((item) => (
            <span
              key={item}
              className="inline-flex min-h-7 items-center gap-1 rounded-md border border-border-light bg-surface-card px-2 text-xs font-bold text-text-primary"
            >
              {item}
              <button
                type="button"
                onClick={() => removeValue(item)}
                disabled={disabled}
                className="grid h-5 w-5 place-items-center rounded-md text-text-muted hover:bg-surface-hover hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-50"
                aria-label={`Remove ${item}`}
              >
                <X size={13} />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function CountrySelector({ value, onChange }) {
  const selectedCountries = splitList(value).map((country) => country.toUpperCase());
  const addCountry = (country) => {
    if (!country || selectedCountries.includes(country)) return;
    onChange([...selectedCountries, country]);
  };
  const removeCountry = (country) => {
    onChange(selectedCountries.filter((item) => item !== country));
  };

  return (
    <div className="grid gap-2">
      <FormSelect
        value=""
        onChange={(event) => addCountry(event.target.value)}
        placeholder="Select..."
      >
        <option value="">Select...</option>
        {COUNTRY_OPTIONS.map((country) => (
          <option key={country.value} value={country.value} disabled={selectedCountries.includes(country.value)}>
            {country.label}
          </option>
        ))}
      </FormSelect>
      {selectedCountries.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {selectedCountries.map((country) => (
            <span
              key={country}
              className="inline-flex min-h-7 items-center gap-1 rounded-md border border-border-light bg-surface-card px-2 text-xs font-bold text-text-primary"
            >
              {countryLabel(country)}
              <button
                type="button"
                onClick={() => removeCountry(country)}
                className="grid h-5 w-5 place-items-center rounded-md text-text-muted hover:bg-surface-hover hover:text-text-primary"
                aria-label={`Remove ${countryLabel(country)}`}
              >
                <X size={13} />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function UserLocationSection({ form, setForm }) {
  const rules = normalizeUserLocationRules(form.user_location_rules?.length ? form.user_location_rules : [createUserLocationRule()]);
  const updateRule = (index, patch) => {
    setForm((current) => {
      const currentRules = normalizeUserLocationRules(current.user_location_rules?.length ? current.user_location_rules : [createUserLocationRule()]);
      return {
        ...current,
        user_location_rules: currentRules.map((rule, ruleIndex) => (ruleIndex === index ? { ...rule, ...patch } : rule)),
      };
    });
  };
  const removeRule = (index) => {
    setForm((current) => {
      const currentRules = normalizeUserLocationRules(current.user_location_rules?.length ? current.user_location_rules : [createUserLocationRule()]);
      const nextRules = currentRules.filter((_, ruleIndex) => ruleIndex !== index);
      return { ...current, user_location_rules: nextRules.length ? nextRules : [createUserLocationRule()] };
    });
  };
  const addRule = () => {
    setForm((current) => {
      const currentRules = normalizeUserLocationRules(current.user_location_rules?.length ? current.user_location_rules : [createUserLocationRule()]);
      return { ...current, user_location_rules: [...currentRules, createUserLocationRule()] };
    });
  };

  return (
    <div className="grid max-w-4xl gap-5">
      <div className="grid gap-4">
        {rules.map((rule, index) => (
          <div
            key={`location-rule-${index}`}
            className="rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] p-4 shadow-[0_8px_16px_rgba(42,42,42,0.10)]"
          >
            <div className="mb-3 flex items-start justify-between gap-3">
              <p className="text-sm font-bold text-text-primary">Rule {index + 1}</p>
              {rules.length > 1 && (
                <button
                  type="button"
                  onClick={() => removeRule(index)}
                  className="grid h-8 w-8 place-items-center rounded-md text-text-muted transition-colors hover:bg-danger-muted hover:text-danger"
                  aria-label={`Remove rule ${index + 1}`}
                >
                  <X size={15} />
                </button>
              )}
            </div>
            <FormField label="Select country or countries" className="mb-4">
              <CountrySelector
                value={rule.countries}
                onChange={(countries) => updateRule(index, { countries })}
              />
            </FormField>
            <LocationActionOptions
              name={`user-location-rule-${index}`}
              value={rule.action || 'allow'}
              onChange={(action) => updateRule(index, { action })}
            />
          </div>
        ))}
        <button
          type="button"
          onClick={addRule}
          className="inline-flex w-fit items-center gap-2 rounded-md border border-accent px-3 py-2 text-sm font-bold text-accent hover:bg-accent-muted"
        >
          <Plus size={15} />
          Add another rule
        </button>
      </div>

      <div className="border-t border-border-light pt-5">
        <p className="mb-4 text-base font-bold text-text-primary">All other countries</p>
        <LocationActionOptions
          name="user-location-default-action"
          value={form.user_location_default_action || 'allow'}
          onChange={(action) => setForm((current) => ({ ...current, user_location_default_action: action }))}
        />
      </div>

      <div className="border-t border-border-light pt-5">
        <p className="mb-4 text-base font-bold text-text-primary">Unknown locations</p>
        <LocationActionOptions
          name="user-location-unknown-action"
          value={form.user_location_unknown_action || 'allow'}
          onChange={(action) => setForm((current) => ({ ...current, user_location_unknown_action: action }))}
        />
        <p className="mt-4 max-w-3xl text-xs font-semibold leading-5 text-text-secondary">
          Access attempts from internal IPs and unknown countries use the unknown locations setting.
        </p>
      </div>
    </div>
  );
}

export function AuthorizedNetworksSection({ form, setForm }) {
  return (
    <div className="grid max-w-4xl gap-4">
      <FormField
        label="Allow access from these networks"
        hint="Users from these IPs, CIDRs, or IP ranges can access normally. Use this with Block access from any other network to create an allowlist."
        className="mb-0"
      >
        <NetworkListEditor
          value={form.network_allowed_cidrs || ''}
          onChange={(values) => setForm({ ...form, network_allowed_cidrs: values })}
          placeholder="192.0.2.10, 192.0.2.0/24, 198.51.100.10-198.51.100.20"
        />
      </FormField>
      <FormField
        label="Skip MFA from these networks"
        hint="Users from these IPs, CIDRs, or IP ranges can access with primary authentication only."
        className="mb-0"
      >
        <NetworkListEditor
          value={form.network_skip_mfa_cidrs || ''}
          onChange={(values) => setForm({ ...form, network_skip_mfa_cidrs: values })}
          placeholder="192.0.2.0/24"
        />
      </FormField>

      <FormField
        label="Require MFA from these networks every time"
        hint="Users from these IPs, CIDRs, or IP ranges must complete MFA even if another policy would normally skip it."
        className="mb-0"
      >
        <NetworkListEditor
          value={form.network_require_mfa_cidrs || ''}
          onChange={(values) => setForm({ ...form, network_require_mfa_cidrs: values })}
          placeholder="203.0.113.0/24"
        />
      </FormField>
      <FormField
        label="Block access from these networks"
        hint="Blocked networks are most restrictive when IPs, CIDRs, or IP ranges overlap with allow, skip, or require MFA networks."
        className="mb-0"
      >
        <NetworkListEditor
          value={form.network_blocked_cidrs || ''}
          onChange={(values) => setForm({ ...form, network_blocked_cidrs: values })}
          placeholder="198.51.100.0/24"
        />
      </FormField>
      <FormCheckbox
        id="network-deny-other"
        checked={!!form.network_deny_other}
        onChange={(event) => setForm({ ...form, network_deny_other: event.target.checked })}
        label="Block access from any other network not specified above"
      />
    </div>
  );
}

export function ActionSection({ form, setForm }) {
  return (
    <div className="grid max-w-3xl gap-3">
      {[
        { value: 'allow', title: 'Allow access', description: 'Allow users to access the resource when all added conditions match.' },
        { value: 'step_up_required', title: 'Require step-up', description: 'Require additional verification when this policy matches.' },
        { value: 'deny', title: 'Deny access', description: 'Block access when this policy matches. Deny has priority over MFA and allow decisions.' },
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

export function StepUpSection({ form, setForm }) {
  if (form.action !== 'step_up_required') {
    return (
      <p className="rounded-md border border-border-light bg-surface-card px-4 py-3 text-sm font-semibold text-text-secondary">
        Select Require step-up in Decision to configure authentication requirements.
      </p>
    );
  }

  return (
    <div className="grid max-w-4xl gap-4">
      <FormField label="Step-up methods" className="mb-0">
        <StepUpMethodsCheckboxes form={form} setForm={setForm} />
      </FormField>
    </div>
  );
}

export function AccessConditionsSection({ form, setForm }) {
  const toggleCondition = (field) => {
    setForm({ ...form, [field]: !form[field] });
  };

  return (
    <div className="grid max-w-4xl gap-5">
      <FormField label="Condition match" className="mb-0 max-w-xs">
        <FormSelect
          value={form.access_match_mode || 'all'}
          onChange={(event) => setForm({ ...form, access_match_mode: event.target.value })}
        >
          <option value="all">All selected</option>
          <option value="any">Any selected</option>
        </FormSelect>
      </FormField>
      {ACCESS_CONDITION_GROUPS.map((group) => (
        <div key={group.id} className="grid gap-2">
          <p className="text-xs font-bold uppercase tracking-[0.12em] text-text-muted">{group.label}</p>
          <div className="grid gap-2 sm:grid-cols-2">
            {group.options.map((option) => {
              const checked = !!form[option.field];
              return (
                <button
                  type="button"
                  key={option.field}
                  onClick={() => toggleCondition(option.field)}
                  className={`block min-h-12 rounded-md border px-4 py-3 text-left transition-colors ${
                    checked ? 'border-accent bg-accent-muted text-accent' : 'border-border-light bg-surface-card hover:border-accent hover:bg-accent-muted'
                  }`}
                  aria-pressed={checked}
                >
                  <span className="flex items-center gap-3">
                    <span
                      className={`grid h-2 w-2 shrink-0 place-items-center rounded-md border transition-colors ${
                        checked ? 'border-accent bg-accent' : 'border-border bg-surface'
                      }`}
                      aria-hidden="true"
                    />
                    <span className="min-w-0 text-sm font-bold text-text-primary">{option.label}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

export function DeviceSection({ form, setForm, deviceCheckOptions }) {
  const selectedChecks = requiredDeviceChecksFromValue(form.required_checks);
  const allCheckValues = deviceCheckOptions.map((option) => option.value);
  const allChecksSelected = allCheckValues.length > 0 && allCheckValues.every((value) => selectedChecks.includes(value));
  const toggleCheck = (checkName) => {
    const nextChecks = toggleListValue(selectedChecks, checkName);
    setForm({
      ...form,
      required_checks: listToText(nextChecks),
      required_check_status: nextChecks.length ? form.required_check_status : '',
    });
  };
  const selectAllChecks = () => {
    setForm({
      ...form,
      required_checks: listToText(allCheckValues),
      required_check_status: form.required_check_status || 'good',
    });
  };

  return (
    <div className="grid max-w-4xl gap-4">
      <div className="max-w-3xl rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-4 py-3 shadow-[0_8px_16px_rgba(42,42,42,0.10)]">
        <p className="text-xs font-semibold leading-5 text-text-primary">
          If required device data checks fail: Block access.
        </p>
      </div>
      <FormField
        label="Required device data checks"
        className="mb-0"
      >
        <div className="grid max-w-3xl gap-3">
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={selectAllChecks}
              disabled={allCheckValues.length === 0 || allChecksSelected}
              className="w-fit rounded-md border border-accent px-3 py-2 text-xs font-bold text-accent transition hover:bg-accent-muted disabled:cursor-not-allowed disabled:border-border-light disabled:text-text-muted disabled:hover:bg-transparent"
            >
              Select all
            </button>
            {selectedChecks.length > 0 && (
              <button
                type="button"
                onClick={() => setForm({ ...form, required_checks: '', required_check_status: '' })}
                className="w-fit rounded-md border border-border-light px-3 py-2 text-xs font-bold text-text-secondary transition hover:border-accent hover:text-accent"
              >
                Clear selected checks
              </button>
            )}
          </div>
          {deviceCheckOptions.map((option) => {
            const checked = selectedChecks.includes(option.value);
            return (
              <button
                type="button"
                key={option.value}
                onClick={() => toggleCheck(option.value)}
                className={`block rounded-md border px-4 py-3 text-left transition-[border-color,background-color,box-shadow] duration-150 ${
                  checked
                    ? 'border-accent bg-[rgba(44,97,100,0.12)] shadow-[0_8px_16px_rgba(42,42,42,0.12)]'
                    : 'border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] shadow-[0_8px_16px_rgba(42,42,42,0.10)] hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.12)]'
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
          <p className={sectionTitleClass}>{section.label}</p>
          <p className="mt-1 max-w-3xl text-sm text-text-secondary">{section.description}</p>
        </div>
        {section.required ? (
          <StatusText variant="success">Required</StatusText>
        ) : onToggle ? (
          <div className="flex h-8 shrink-0 items-center gap-2">
            <span className="text-xs font-bold leading-none text-text-secondary">Add</span>
            <SectionToggle checked={added} onChange={onToggle} />
          </div>
        ) : (
          <StatusText variant={added ? 'success' : 'neutral'}>{added ? 'Active' : 'Inactive'}</StatusText>
        )}
      </div>
      <div className={`mt-3 ${shadowSafeContentClass}`}>
        {section.required || added ? (
          children
        ) : null}
      </div>
    </div>
  );
}
