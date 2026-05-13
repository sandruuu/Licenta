export const scopeOptions = [
  { value: 'tenant', label: 'Organization' },
  { value: 'gateway', label: 'Gateway' },
  { value: 'resource', label: 'Resource' },
];

export const assignmentFilterOptions = [
  { value: 'all', label: 'All assignments' },
  { value: 'unassigned', label: 'Unassigned' },
  ...scopeOptions,
];

export const basePolicyConditions = {
  min_health_score: 0,
  required_checks: '',
  allowed_roles: '',
  allowed_users: '',
  allowed_groups: '',
  allowed_ips: '',
  allowed_time_start: '',
  allowed_time_end: '',
  allowed_days: '',
  target_resources: '',
  target_ports: '',
  max_risk_score: 100,
};

export function createBlankConditions(overrides = {}) {
  return { ...basePolicyConditions, ...overrides };
}

export function conditionsToForm(conditions = {}) {
  return {
    min_health_score: conditions.min_health_score ?? 0,
    required_checks: (conditions.required_checks || []).join(', '),
    allowed_roles: (conditions.allowed_roles || []).join(', '),
    allowed_users: (conditions.allowed_users || []).join(', '),
    allowed_groups: (conditions.allowed_groups || []).join(', '),
    allowed_ips: (conditions.allowed_ips || []).join(', '),
    allowed_time_start: conditions.allowed_time_start || '',
    allowed_time_end: conditions.allowed_time_end || '',
    allowed_days: (conditions.allowed_days || []).join(', '),
    target_resources: (conditions.target_resources || []).join(', '),
    target_ports: (conditions.target_ports || []).join(', '),
    max_risk_score: conditions.max_risk_score ?? 100,
  };
}

export function splitList(value) {
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

export function splitIntList(value) {
  return value ? value.split(',').map((item) => parseInt(item.trim(), 10)).filter((item) => !Number.isNaN(item)) : [];
}

export function actionVariant(action) {
  if (action === 'allow') return 'success';
  if (action === 'deny') return 'danger';
  return 'warning';
}

export function ruleScopeMode(rule) {
  if (!rule) return 'global';
  if (rule.scope === 'resource') return 'resource';
  if (rule.scope === 'gateway') return 'gateway';
  return rule.tenant_id ? 'tenant' : 'global';
}

export function assignmentScopeMode(assignment) {
  if (!assignment) return 'unassigned';
  if (assignment.resource_id) return 'resource';
  if (assignment.gateway_id) return 'gateway';
  return assignment.tenant_id ? 'tenant' : 'unassigned';
}

export function assignmentScopeLabel(assignment) {
  const mode = assignmentScopeMode(assignment);
  if (mode === 'tenant') return 'Organization';
  if (mode === 'gateway') return 'Gateway';
  if (mode === 'resource') return 'Resource';
  return 'Unassigned';
}

export function assignmentScopeVariant(assignment) {
  const mode = assignmentScopeMode(assignment);
  if (mode === 'resource') return 'info';
  if (mode === 'gateway') return 'accent';
  if (mode === 'tenant') return 'success';
  return 'neutral';
}

export function scopeLabel(rule) {
  const mode = ruleScopeMode(rule);
  return scopeOptions.find((option) => option.value === mode)?.label || 'Global';
}

export function scopeVariant(rule) {
  const mode = ruleScopeMode(rule);
  if (mode === 'resource') return 'info';
  if (mode === 'gateway') return 'accent';
  if (mode === 'tenant') return 'success';
  return 'neutral';
}

export function includesText(value, needle) {
  return String(value || '').toLowerCase().includes(needle);
}
