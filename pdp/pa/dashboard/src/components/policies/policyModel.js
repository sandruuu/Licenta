export const ACTION_META = {
  allow: { label: 'Allow access', short: 'Allow', variant: 'success' },
  step_up_required: { label: 'Enforce MFA', short: 'MFA', variant: 'warning' },
  deny: { label: 'Deny access', short: 'Deny', variant: 'danger' },
};

export const AUTHENTICATION_POLICIES = [
  {
    value: 'enforce_mfa',
    action: 'step_up_required',
    title: 'Enforce MFA',
    description: 'Require multi-factor authentication or enrollment when applicable.',
  },
  {
    value: 'bypass_mfa',
    action: 'allow',
    title: 'Bypass MFA',
    description: 'Allow access without multi-factor authentication or enrollment unless a stricter policy applies.',
  },
  {
    value: 'deny',
    action: 'deny',
    title: 'Deny access',
    description: 'Block authentication for all users in this policy scope.',
  },
];

export const STEP_UP_METHOD_OPTIONS = [
  { value: 'totp', label: 'Authenticator app' },
  { value: 'webauthn', label: 'Passkey or security key' },
];

const REQUIRED_STEP_UP_METHOD = STEP_UP_METHOD_OPTIONS[0].value;

export const NEW_USER_POLICIES = [
  {
    value: 'require_enrollment',
    title: 'Require enrollment',
    description: 'Prompt unenrolled users to enroll whenever possible after primary authentication.',
  },
  {
    value: 'allow_without_mfa',
    title: 'Allow access without MFA',
    description: 'Let users unknown to MFA pass through without enrollment or multi-factor authentication.',
  },
  {
    value: 'deny',
    title: 'Deny access',
    description: 'Block unenrolled users until an administrator or enrollment flow prepares their MFA account.',
  },
];

export const USER_LOCATION_ACTIONS = [
  {
    value: 'require_mfa',
    title: 'Require MFA or passwordless authentication, even if it would normally be skipped',
    description: 'This overrides policies that allow MFA or passwordless authentication to be skipped, like remembered devices and authorized networks policies.',
  },
  {
    value: 'skip_mfa',
    title: 'Skip MFA and allow access with only a password',
    description: 'This allows users to skip MFA and log in with only a password. Passwordless authentication is not skipped.',
  },
  {
    value: 'allow',
    title: 'Allow access from selected countries and unknown locations',
    description: 'This setting will allow access whenever this policy has precedence. It will override and remove similar location restrictions from lower policies.',
  },
  {
    value: 'block',
    title: 'Block access',
    description: '',
  },
];

export const COUNTRY_OPTIONS = [
  { value: 'AR', label: 'Argentina' },
  { value: 'AU', label: 'Australia' },
  { value: 'AT', label: 'Austria' },
  { value: 'BE', label: 'Belgium' },
  { value: 'BR', label: 'Brazil' },
  { value: 'BG', label: 'Bulgaria' },
  { value: 'CA', label: 'Canada' },
  { value: 'CL', label: 'Chile' },
  { value: 'CN', label: 'China' },
  { value: 'CO', label: 'Colombia' },
  { value: 'HR', label: 'Croatia' },
  { value: 'CZ', label: 'Czechia' },
  { value: 'DK', label: 'Denmark' },
  { value: 'EE', label: 'Estonia' },
  { value: 'FI', label: 'Finland' },
  { value: 'FR', label: 'France' },
  { value: 'DE', label: 'Germany' },
  { value: 'GR', label: 'Greece' },
  { value: 'HU', label: 'Hungary' },
  { value: 'IN', label: 'India' },
  { value: 'IE', label: 'Ireland' },
  { value: 'IL', label: 'Israel' },
  { value: 'IT', label: 'Italy' },
  { value: 'JP', label: 'Japan' },
  { value: 'LV', label: 'Latvia' },
  { value: 'LT', label: 'Lithuania' },
  { value: 'LU', label: 'Luxembourg' },
  { value: 'MX', label: 'Mexico' },
  { value: 'NL', label: 'Netherlands' },
  { value: 'NO', label: 'Norway' },
  { value: 'PL', label: 'Poland' },
  { value: 'PT', label: 'Portugal' },
  { value: 'RO', label: 'Romania' },
  { value: 'RU', label: 'Russia' },
  { value: 'RS', label: 'Serbia' },
  { value: 'SK', label: 'Slovakia' },
  { value: 'SI', label: 'Slovenia' },
  { value: 'ES', label: 'Spain' },
  { value: 'SE', label: 'Sweden' },
  { value: 'CH', label: 'Switzerland' },
  { value: 'TR', label: 'Turkey' },
  { value: 'UA', label: 'Ukraine' },
  { value: 'GB', label: 'United Kingdom' },
  { value: 'US', label: 'United States' },
].sort((left, right) => left.label.localeCompare(right.label));

export function actionFromAuthenticationPolicy(policy) {
  return AUTHENTICATION_POLICIES.find((item) => item.value === policy)?.action || 'step_up_required';
}

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
    category: 'Policy',
    required: true,
    description: 'Name the policy and review where it is currently applied.',
    protects: 'Clear ownership and descriptions make policy changes auditable.',
    recommendation: 'Use a name that includes the target audience and intent, for example Finance Payroll MFA.',
  },
  {
    id: 'newuser',
    label: 'New User policy',
    category: 'Users',
    fields: ['new_user_policy'],
    description: 'Define what happens when a user is not enrolled for MFA yet.',
    protects: 'Controls inline enrollment, temporary pass-through, or blocking for unknown and unenrolled users.',
    recommendation: 'Use Require enrollment for normal rollout and Deny access for sensitive resources.',
  },
  {
    id: 'stepup',
    label: 'Authentication policy',
    category: 'Users',
    required: true,
    fields: [
      'action',
      'authentication_policy',
      'step_up_methods',
    ],
    description: 'Define whether access requires MFA, bypasses MFA, or is blocked.',
    protects: 'Separates the access decision from contextual signals and controls which MFA methods users can complete.',
    recommendation: 'Use Enforce MFA by default, Bypass MFA only for explicit exceptions, and Deny for hard blocks.',
  },
  {
    id: 'riskbasedauth',
    label: 'Risk-Based Authentication',
    category: 'Users',
    fields: ['risk_auth_enabled'],
    description: 'Require MFA when internal risk signals indicate the access attempt is unusual.',
    protects: 'Uses learned access history and geovelocity checks to step up suspicious authentications.',
    recommendation: 'Enable all signals for sensitive resources; baseline signals activate only after enough successful history exists.',
  },
  {
    id: 'location',
    label: 'User location',
    category: 'Users',
    fields: ['user_location_rules', 'user_location_default_action', 'user_location_unknown_action'],
    description: 'Define country-based access rules for the source IP location.',
    protects: 'Lets admins allow, require MFA, skip MFA, or block access for selected countries and all other countries.',
    recommendation: 'Use explicit allow countries with Block access for all other countries when resources are geographically restricted.',
  },
  {
    id: 'devicehealth',
    label: 'Device data',
    category: 'Devices',
    fields: ['required_checks', 'required_check_status'],
    description: 'Require selected device data checks to report the expected status.',
    protects: 'Keeps endpoints that fail required health checks from reaching protected resources.',
    recommendation: 'Start with high-signal checks such as firewall, disk encryption, and updates.',
  },
  {
    id: 'authorizednetworks',
    label: 'Authorized networks',
    category: 'Networks',
    fields: [
      'network_allowed_cidrs',
      'network_skip_mfa_cidrs',
      'network_require_mfa_cidrs',
      'network_blocked_cidrs',
      'network_deny_other',
    ],
    description: 'By default, access is allowed from all networks. Add entries here only for networks that should be allowed in an allowlist, skip MFA, require MFA, or be blocked.',
    protects: 'Lets admins allow, skip MFA, force MFA, or block access based on IP address, CIDR, or IP range.',
    recommendation: 'Use Allow networks with Block any other network for allowlists, Skip MFA only for tightly controlled networks, and Block for explicit exclusions.',
  },
];

export const ACCESS_CONDITION_GROUPS = [
  {
    id: 'location',
    label: 'Location',
    options: [
      { field: 'access_new_location', label: 'New location' },
      { field: 'access_impossible_travel', label: 'Unrealistic travel' },
    ],
  },
];

export const LOCATION_CONDITION_OPTIONS = [
  { field: 'access_new_location', label: 'New location' },
  { field: 'access_impossible_travel', label: 'Unrealistic travel' },
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
    description: 'Password and screen lock device state.',
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
  { label: 'Users', sections: ['newuser', 'stepup', 'riskbasedauth', 'location'] },
  { label: 'Devices', sections: ['devicehealth'] },
  { label: 'Networks', sections: ['authorizednetworks'] },
];

export const EMPTY_POLICY_FORM = {
  name: '',
  description: '',
  enabled: true,
  action: 'step_up_required',
  authentication_policy: 'enforce_mfa',
  new_user_policy: 'require_enrollment',
  required_checks: '',
  required_check_status: 'good',
  user_location_rules: [{ countries: [], action: 'allow' }],
  user_location_default_action: 'allow',
  user_location_unknown_action: 'allow',
  user_location_check_mode: 'access_device_only',
  access_match_mode: 'all',
  access_new_location: false,
  access_impossible_travel: false,
  risk_auth_enabled: false,
  network_allowed_cidrs: [],
  network_skip_mfa_cidrs: [],
  network_require_mfa_cidrs: [],
  network_blocked_cidrs: [],
  network_deny_other: false,
  step_up_methods: REQUIRED_STEP_UP_METHOD,
};

export const EMPTY_ASSIGNMENT_FORM = {
  policy_id: '',
  organization_id: '',
  level: 'organization',
  resource_id: '',
  resource_ids: [],
  group_id: '',
  group_ids: [],
  group_name: '',
  order_placement: '',
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

export function normalizeStepUpMethods(value) {
  const validMethods = new Set(STEP_UP_METHOD_OPTIONS.map((method) => method.value));
  const selectedMethods = new Set([REQUIRED_STEP_UP_METHOD]);
  splitList(value).forEach((method) => {
    if (validMethods.has(method)) {
      selectedMethods.add(method);
    }
  });
  return STEP_UP_METHOD_OPTIONS
    .map((method) => method.value)
    .filter((method) => selectedMethods.has(method));
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
        description: check.description || 'Reported by TrustAgent device data.',
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
      if (entry && typeof entry === 'object') return Object.keys(entry).length > 0;
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

export function createUserLocationRule() {
  return { countries: [], action: 'allow' };
}

export function normalizeUserLocationRules(rules = []) {
  const normalized = Array.isArray(rules) ? rules : [];
  const validActions = new Set(USER_LOCATION_ACTIONS.map((action) => action.value));
  return normalized.map((rule) => ({
    countries: splitList(rule?.countries).map((country) => country.toUpperCase()),
    action: validActions.has(rule?.action) ? rule.action : 'allow',
  }));
}

export function isUserLocationConfigured(form) {
  const rules = normalizeUserLocationRules(form.user_location_rules);
  return rules.some((rule) => rule.countries.length > 0) ||
    (form.user_location_default_action && form.user_location_default_action !== 'allow') ||
    (form.user_location_unknown_action && form.user_location_unknown_action !== 'allow');
}

export function isAuthorizedNetworksConfigured(form) {
  return isFilled(form.network_allowed_cidrs) ||
    isFilled(form.network_skip_mfa_cidrs) ||
    isFilled(form.network_require_mfa_cidrs) ||
    isFilled(form.network_blocked_cidrs) ||
    !!form.network_deny_other;
}

export function isRiskBasedAuthenticationConfigured(form) {
  return !!form.risk_auth_enabled;
}

export function countryLabel(value) {
  const country = COUNTRY_OPTIONS.find((option) => option.value === String(value || '').toUpperCase());
  return country ? country.label : value;
}

export function policyFormFromRule(rule) {
  const conditions = rule?.conditions || {};
  const access = conditions.access_conditions || {};
  const authentication = conditions.authentication || {};
  const devicePosture = conditions.device_posture || {};
  const user = conditions.user || {};
  const userLocation = conditions.user_location || {};
  const network = conditions.network || {};
  const riskBasedAuth = conditions.risk_based_authentication || {};
  const stepUpMethods = normalizeStepUpMethods(authentication.step_up_methods);
  return {
    ...EMPTY_POLICY_FORM,
    id: rule?.id,
    name: rule?.name || '',
    description: rule?.description || '',
    enabled: rule?.enabled !== false,
    action: rule?.action || 'step_up_required',
    authentication_policy: authentication.policy || 'enforce_mfa',
    new_user_policy: user.new_user_policy || '',
    required_checks: listToText(requiredDeviceChecksFromValue(devicePosture.required_checks)),
    required_check_status: devicePosture.required_status || 'good',
    user_location_rules: normalizeUserLocationRules(userLocation.rules?.length ? userLocation.rules : [{ countries: [], action: 'allow' }]),
    user_location_default_action: userLocation.default_action || 'allow',
    user_location_unknown_action: userLocation.unknown_location_action || 'allow',
    user_location_check_mode: userLocation.check_mode || 'access_device_only',
    access_match_mode: conditions.access_match_mode || 'all',
    access_new_location: !!access.location?.new_location,
    access_impossible_travel: !!access.location?.impossible_travel,
    risk_auth_enabled: !!riskBasedAuth.require_mfa_on_risk,
    network_allowed_cidrs: splitList(network.allowed_cidrs),
    network_skip_mfa_cidrs: splitList(network.skip_mfa_cidrs),
    network_require_mfa_cidrs: splitList(network.require_mfa_cidrs),
    network_blocked_cidrs: splitList(network.blocked_cidrs),
    network_deny_other: !!network.deny_other_networks,
    step_up_methods: listToText(stepUpMethods),
  };
}

export function inferEnabledSections(form) {
  return Object.fromEntries(
    POLICY_SECTIONS.filter((section) => section.fields).map((section) => {
      if (section.required) return [section.id, true];
      if (section.id === 'newuser') return [section.id, !!form.new_user_policy];
      if (section.id === 'riskbasedauth') return [section.id, isRiskBasedAuthenticationConfigured(form)];
      if (section.id === 'location') return [section.id, isUserLocationConfigured(form)];
      if (section.id === 'devicehealth') return [section.id, isFilled(form.required_checks)];
      if (section.id === 'authorizednetworks') return [section.id, isAuthorizedNetworksConfigured(form)];
      return [
        section.id,
        section.fields.some((field) => isFilled(form[field])),
      ];
    }),
  );
}

export function conditionsFromForm(form, enabledSections = inferEnabledSections(form)) {
  const requiredChecks = requiredDeviceChecksFromValue(form.required_checks);
  const stepUpMethods = normalizeStepUpMethods(form.step_up_methods);
  const allowedCIDRs = splitList(form.network_allowed_cidrs);
  const skipMFACIDRs = splitList(form.network_skip_mfa_cidrs);
  const requireMFACIDRs = splitList(form.network_require_mfa_cidrs);
  const blockedCIDRs = splitList(form.network_blocked_cidrs);
  const userLocationRules = normalizeUserLocationRules(form.user_location_rules)
    .filter((rule) => rule.countries.length > 0);
  const authenticationPolicy = form.authentication_policy || 'enforce_mfa';
  const authentication = compactObject({
    policy: authenticationPolicy,
    ...(authenticationPolicy === 'enforce_mfa' ? {
      step_up_methods: stepUpMethods,
    } : {}),
  });
  const devicePosture = compactObject({
    required_checks: enabledSections.devicehealth ? requiredChecks : [],
    required_status: enabledSections.devicehealth && requiredChecks.length ? (form.required_check_status || 'good') : '',
  });
  return compactObject({
    user: enabledSections.newuser ? compactObject({
      new_user_policy: form.new_user_policy || 'require_enrollment',
    }) : null,
    access_conditions: compactAccessConditions(form, enabledSections),
    access_match_mode: form.access_match_mode === 'any' ? 'any' : '',
    user_location: enabledSections.location ? compactObject({
      rules: userLocationRules,
      default_action: form.user_location_default_action || 'allow',
      unknown_location_action: form.user_location_unknown_action || 'allow',
      check_mode: form.user_location_check_mode || 'access_device_only',
    }) : null,
    risk_based_authentication: enabledSections.riskbasedauth ? compactObject({
      require_mfa_on_risk: true,
    }) : null,
    network: enabledSections.authorizednetworks ? compactObject({
      allowed_cidrs: allowedCIDRs,
      skip_mfa_cidrs: skipMFACIDRs,
      require_mfa_cidrs: requireMFACIDRs,
      blocked_cidrs: blockedCIDRs,
      deny_other_networks: !!form.network_deny_other,
    }) : null,
    authentication,
    device_posture: Object.keys(devicePosture).length ? devicePosture : null,
  });
}

export function compactAccessConditions(form, enabledSections = inferEnabledSections(form)) {
  const conditions = {
    location: enabledSections.location ? compactObject({
      new_location: !!form.access_new_location,
      impossible_travel: !!form.access_impossible_travel,
    }) : null,
  };
  return compactObject(conditions);
}

export function accessConditionLabels(conditions = {}) {
  const selected = [];
  ACCESS_CONDITION_GROUPS.forEach((group) => {
    group.options.forEach((option) => {
      const path = option.field.replace(/^access_/, '');
      if (
        group.id === 'location' && conditions.location?.[path]
      ) {
        selected.push(option.label);
      }
    });
  });
  return selected;
}

export function conditionSummary(policy) {
  const conditions = policy?.conditions || {};
  const parts = [];
  const accessLabels = accessConditionLabels(conditions.access_conditions);
  const authentication = conditions.authentication || {};
  const devicePosture = conditions.device_posture || {};
  const user = conditions.user || {};
  const userLocation = conditions.user_location || {};
  const network = conditions.network || {};
  const riskBasedAuth = conditions.risk_based_authentication || {};
  if (user.new_user_policy === 'require_enrollment') parts.push('new users require enrollment');
  if (user.new_user_policy === 'allow_without_mfa') parts.push('new users bypass MFA');
  if (user.new_user_policy === 'deny') parts.push('new users denied');
  if (accessLabels.length) {
    const joiner = conditions.access_match_mode === 'any' ? 'any of' : 'all of';
    parts.push(`signal ${joiner} ${accessLabels.join(', ')}`);
  }
  if (userLocation.rules?.length) {
    const countryCount = userLocation.rules.reduce((count, rule) => count + (rule.countries?.length || 0), 0);
    parts.push(`location rules for ${countryCount} countries`);
  }
  if (userLocation.default_action && userLocation.default_action !== 'allow') {
    parts.push(`all other countries ${userLocation.default_action.replace('_', ' ')}`);
  }
  if (riskBasedAuth.require_mfa_on_risk) {
    parts.push('risk-based MFA enabled');
  }
  if (network.allowed_cidrs?.length) {
    parts.push(`allowed network ${network.allowed_cidrs.join(', ')}`);
  }
  if (network.skip_mfa_cidrs?.length) {
    parts.push(`skip MFA network ${network.skip_mfa_cidrs.join(', ')}`);
  }
  if (network.require_mfa_cidrs?.length) {
    parts.push(`require MFA network ${network.require_mfa_cidrs.join(', ')}`);
  }
  if (network.blocked_cidrs?.length) {
    parts.push(`blocked network ${network.blocked_cidrs.join(', ')}`);
  }
  if (network.deny_other_networks) {
    parts.push('all other networks blocked');
  }
  if (devicePosture.required_checks?.length) {
    parts.push(`device check ${devicePosture.required_checks.join(', ')}`);
  }
  if (authentication.step_up_methods?.length) {
    const methods = authentication.step_up_methods;
    parts.push(`step-up via ${methods.join(', ')}`);
  }
  if (authentication.policy === 'bypass_mfa') parts.push('authentication bypasses MFA');
  if (authentication.policy === 'deny') parts.push('authentication denied');
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
  const organization = maps.organizations?.get(assignment.organization_id)?.name || assignment.organization_id || '';
  const group = maps.groups?.get(assignment.group_id);
  const idp = group?.idp_id ? maps.idps?.get(group.idp_id) : null;
  return [organization, idp?.name || group?.idp_id].filter(Boolean).join(' / ');
}

export function targetLabel(assignment, maps) {
  const organization = maps.organizations.get(assignment.organization_id)?.name || assignment.organization_id || 'Organization';
  const resource = maps.resources.get(assignment.resource_id)?.name || assignment.resource_id || 'Resource';
  const group = maps.groups.get(assignment.group_id)?.display_name || assignment.group_name || assignment.group_id || 'Group';
  if (assignment.level === 'resource_group') return `${resource} + ${group}`;
  if (assignment.level === 'resource') return resource;
  if (assignment.level === 'group') return group;
  return organization;
}

export function assignmentTargetLabel(assignment, maps) {
  const organization = maps.organizations.get(assignment.organization_id)?.name || assignment.organization_id || 'Organization';
  const resource = maps.resources.get(assignment.resource_id)?.name || assignment.resource_id || 'Application';
  const group = maps.groups.get(assignment.group_id)?.display_name || assignment.group_name || assignment.group_id || 'Group';
  if (assignment.level === 'organization') return `All applications in ${organization}`;
  if (assignment.level === 'resource_group') return `${resource} + ${group}`;
  if (assignment.level === 'resource') return resource;
  if (assignment.level === 'group') return group;
  return targetLabel(assignment, maps);
}

export function assignmentContextLabel(assignment, maps) {
  const organization = maps.organizations.get(assignment.organization_id)?.name || assignment.organization_id || 'Organization';
  const group = maps.groups?.get(assignment.group_id);
  const idp = group?.idp_id ? maps.idps?.get(group.idp_id) : null;
  const context = [organization, idp?.name || group?.idp_id].filter(Boolean).join(' / ');
  if (assignment.level === 'organization') return organization;
  return context || organization;
}

export function isDefaultGlobalPolicy(policyOrID) {
  const policyID = typeof policyOrID === 'string' ? policyOrID : policyOrID?.id;
  return String(policyID || '').startsWith('policy-global-default-');
}

export function isDefaultGlobalAssignment(assignmentOrID) {
  const assignmentID = typeof assignmentOrID === 'string' ? assignmentOrID : assignmentOrID?.id;
  return String(assignmentID || '').startsWith('assignment-global-default-');
}

export function isSectionConfigured(section, form, enabledSections) {
  if (section.id === 'details') return form.name.trim() !== '';
  if (section.required) return true;
  if (section.fields && !enabledSections[section.id]) return false;
  if (section.id === 'newuser') return !!form.new_user_policy;
  if (section.id === 'riskbasedauth') return isRiskBasedAuthenticationConfigured(form);
  if (section.id === 'location') return isUserLocationConfigured(form);
  if (section.id === 'devicehealth') return isFilled(form.required_checks);
  if (section.id === 'authorizednetworks') return isAuthorizedNetworksConfigured(form);
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
  return form.organization_id ? 1 : 0;
}

export function toggleListValue(list = [], value) {
  if (!value) return list;
  return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
}
