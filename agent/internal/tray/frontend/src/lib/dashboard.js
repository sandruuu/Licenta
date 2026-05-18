export const navigationItems = [
  { id: 'overview', label: 'Overview' },
  { id: 'enrollment', label: 'Enrollment' },
  { id: 'security', label: 'Security' },
];

export const fallbackDashboard = {
  connection: {
    state: 'unenrolled',
    message: 'Device is not enrolled',
  },
  status: {
    enrollment_state: 'UNENROLLED',
  },
  enrollment: {
    state: 'UNENROLLED',
  },
  certificate: {
    valid: false,
  },
  user: {
    session_state: 'signed_out',
  },
  posture: {
    checks: [],
  },
  resources: [],
  active_sessions: [],
  access_events: [],
  reported_at: new Date().toISOString(),
};

export function isWailsRuntimeReady() {
  return Boolean(window?.go?.tray?.GUIApp?.GetDashboard);
}

export function normalizeStatus(value) {
  return String(value || 'unknown').trim().toLowerCase();
}

export function formatDateTime(value) {
  if (!value) return 'Not reported';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.getFullYear() <= 1) {
    return 'Not reported';
  }
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(parsed);
}

export function formatStatusLabel(value) {
  return normalizeStatus(value)
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}
