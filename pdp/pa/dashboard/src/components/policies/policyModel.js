export const ACTION_META = {
  allow: { label: 'Allow access', short: 'Allow', variant: 'success' },
  mfa_required: { label: 'Require MFA', short: 'MFA', variant: 'warning' },
  deny: { label: 'Deny access', short: 'Deny', variant: 'danger' },
};

export const LAYERS = [
  {
    value: 'resource_group',
    label: 'Application-Group policy',
    shortLabel: 'Resource + Group',
    order: 1,
    description: 'Apply policy to specific user groups accessing specific applications.',
  },
  {
    value: 'resource',
    label: 'Application policy',
    shortLabel: 'Resource',
    order: 2,
    description: 'Apply policy to all users accessing selected applications.',
  },
  {
    value: 'group',
    label: 'User-Group policy',
    shortLabel: 'Group',
    order: 3,
    description: 'Apply policy to specific user groups regardless of application access.',
  },
  {
    value: 'organization',
    label: 'Global policy',
    shortLabel: 'Organization',
    order: 4,
    description: 'Apply policy globally to the entire organization.',
  },
];

export const POLICY_SECTIONS = [
  {
    id: 'details',
    label: 'Details',
    required: true,
    description: 'Name the policy and review where it is currently applied.',
    protects: 'Clear ownership and descriptions make policy changes auditable.',
    recommendation: 'Use a name that includes the target audience and intent, for example Finance Payroll MFA.',
  },
  {
    id: 'action',
    label: 'Authentication policy',
    required: true,
    description: 'Choose what happens when all added policy settings match.',
    protects: 'Makes the final access decision explicit and easy to review.',
    recommendation: 'Put deny rules above allow rules when you need hard exclusions.',
  },
  {
    id: 'device',
    label: 'Device compliance',
    fields: ['required_checks'],
    description: 'Require agent-reported device checks to match.',
    protects: 'Keeps unmanaged or unhealthy devices from reaching protected resources.',
    recommendation: 'Start with one or two high-signal checks, then expand after devices report consistently.',
  },
];

export const DEFAULT_DEVICE_CHECK_OPTIONS = [
  {
    value: 'Operating System',
    label: 'Operating System',
    description: 'OS name, version, build, architecture, and uptime.',
  },
  {
    value: 'Firewall',
    label: 'Firewall',
    description: 'Windows firewall profile state.',
  },
  {
    value: 'Antivirus',
    label: 'Antivirus',
    description: 'Detected antivirus, real-time protection, and definitions.',
  },
  {
    value: 'Disk Encryption',
    label: 'Disk Encryption',
    description: 'System drive encryption and protection state.',
  },
  {
    value: 'Windows Updates',
    label: 'Windows Updates',
    description: 'Pending updates and last installed hotfix.',
  },
  {
    value: 'Password & Lock',
    label: 'Password & Lock',
    description: 'Password and screen lock posture.',
  },
];

const EXCLUDED_DEVICE_CHECK_NAMES = new Set(['connectivity']);

export function isSupportedDeviceCheck(checkName) {
  const normalizedName = String(checkName || '').trim().toLowerCase();
  return normalizedName !== '' && !EXCLUDED_DEVICE_CHECK_NAMES.has(normalizedName);
}

export function requiredDeviceChecksFromValue(value) {
  return splitList(value).filter(isSupportedDeviceCheck);
}

export const POLICY_GROUPS = [
  { label: 'Access', sections: ['action'] },
  { label: 'Devices', sections: ['device'] },
];

export const EMPTY_POLICY_FORM = {
  name: '',
  description: '',
  enabled: true,
  action: 'allow',
  required_checks: '',
  required_check_status: '',
};

export const EMPTY_ASSIGNMENT_FORM = {
  policy_id: '',
  tenant_id: '',
  level: 'organization',
  resource_id: '',
  resource_ids: [],
  group_id: '',
  group_ids: [],
  group_name: '',
  priority: 100,
  enabled: true,
};

export function splitList(value) {
  if (Array.isArray(value)) return value.map((item) => String(item || '').trim()).filter(Boolean);
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

export function listToText(value) {
  return Array.isArray(value) ? value.join(', ') : '';
}

export function deviceCheckOptionsFromReports(reports = []) {
  const optionsByName = new Map(DEFAULT_DEVICE_CHECK_OPTIONS.map((option) => [option.value, option]));
  reports.forEach((report) => {
    (report?.checks || []).forEach((check) => {
      const name = String(check?.name || '').trim();
      if (!isSupportedDeviceCheck(name) || optionsByName.has(name)) return;
      optionsByName.set(name, {
        value: name,
        label: name,
        description: check.description || 'Reported by device posture telemetry.',
      });
    });
  });
  return [...optionsByName.values()]
    .filter((option) => isSupportedDeviceCheck(option.value))
    .sort((left, right) => left.label.localeCompare(right.label));
}

export function compactObject(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => {
      if (Array.isArray(entry)) return entry.length > 0;
      if (typeof entry === 'boolean') return entry;
      if (typeof entry === 'number') return entry > 0;
      return String(entry || '').trim() !== '';
    }),
  );
}

export function isFilled(value) {
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value > 0;
  return String(value || '').trim() !== '';
}

export function policyFormFromRule(rule) {
  const conditions = rule?.conditions || {};
  return {
    ...EMPTY_POLICY_FORM,
    id: rule?.id,
    name: rule?.name || '',
    description: rule?.description || '',
    enabled: rule?.enabled !== false,
    action: rule?.action || 'allow',
    required_checks: listToText(requiredDeviceChecksFromValue(conditions.required_checks)),
    required_check_status: conditions.required_check_status || '',
  };
}

export function inferEnabledSections(form) {
  return Object.fromEntries(
    POLICY_SECTIONS.filter((section) => section.fields).map((section) => [
      section.id,
      section.fields.some((field) => isFilled(form[field])),
    ]),
  );
}

export function conditionsFromForm(form, enabledSections = inferEnabledSections(form)) {
  const requiredChecks = requiredDeviceChecksFromValue(form.required_checks);
  return compactObject({
    required_checks: enabledSections.device ? requiredChecks : [],
    required_check_status: enabledSections.device && requiredChecks.length ? form.required_check_status : '',
  });
}

export function conditionSummary(policy) {
  const conditions = policy?.conditions || {};
  const parts = [];
  if (conditions.required_checks?.length) parts.push(`device check ${conditions.required_checks.join(', ')}`);
  return parts.length ? parts : ['assignment matches'];
}

export function actionMeta(action) {
  return ACTION_META[action] || ACTION_META.allow;
}

export function layerMeta(level) {
  return LAYERS.find((item) => item.value === level) || LAYERS[3];
}

export function layerWeight(level) {
  return layerMeta(level).order;
}

export function assignmentScopeLabel(assignment, maps) {
  const organization = maps.organizations?.get(assignment.tenant_id)?.name || assignment.tenant_id || '';
  const group = maps.groups?.get(assignment.group_id);
  const idp = group?.idp_id ? maps.idps?.get(group.idp_id) : null;
  return [organization, idp?.name || group?.idp_id].filter(Boolean).join(' / ');
}

export function targetLabel(assignment, maps) {
  const organization = maps.organizations.get(assignment.tenant_id)?.name || assignment.tenant_id || 'Organization';
  const resource = maps.resources.get(assignment.resource_id)?.name || assignment.resource_id || 'Resource';
  const group = maps.groups.get(assignment.group_id)?.display_name || assignment.group_name || assignment.group_id || 'Group';
  if (assignment.level === 'resource_group') return `${resource} + ${group}`;
  if (assignment.level === 'resource') return resource;
  if (assignment.level === 'group') return group;
  return organization;
}

export function isSectionConfigured(section, form, enabledSections) {
  if (section.id === 'details') return form.name.trim() !== '';
  if (section.required) return true;
  return !!enabledSections[section.id];
}

export function selectedCountForLayer(form) {
  if (form.level === 'resource') return form.resource_ids?.length || 0;
  if (form.level === 'group') return form.group_ids?.length || (form.group_name?.trim() ? 1 : 0);
  if (form.level === 'resource_group') {
    const resourceCount = form.resource_ids?.length || 0;
    const groupCount = form.group_ids?.length || (form.group_name?.trim() ? 1 : 0);
    return resourceCount * groupCount;
  }
  return form.tenant_id ? 1 : 0;
}

export function toggleListValue(list = [], value) {
  if (!value) return list;
  return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
}
