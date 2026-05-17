export const emptyDashboard = {
  connection: { state: 'disconnected', message: 'Loading Agent status' },
  status: {},
  enrollment: {},
  certificate: {},
  user: {},
  posture: { checks: [] },
  resources: [],
  active_sessions: [],
  access_events: []
};

export const navigationItems = [
  { id: 'overview', label: 'Overview' },
  { id: 'enrollment', label: 'Enrollment' },
  { id: 'security', label: 'Device Security' },
  { id: 'resources', label: 'Resources' },
  { id: 'sessions', label: 'Sessions' },
  { id: 'access', label: 'Access Log' },
];

export const viewCopy = {
  overview: {
    title: 'Agent Overview',
    subtitle: 'Local service, enrollment, posture, and access status',
  },
  enrollment: {
    title: 'Enrollment',
    subtitle: 'Device identity, certificate, and local user binding',
  },
  security: {
    title: 'Device Security',
    subtitle: 'Posture checks collected by the LocalSystem service',
  },
  resources: {
    title: 'Resources',
    subtitle: 'Catalog resources synced from the control plane',
  },
  sessions: {
    title: 'Sessions',
    subtitle: 'Active local resource sessions',
  },
  access: {
    title: 'Access Log',
    subtitle: 'Recent local decisions and access messages',
  },
};

export function normalizeDashboard(value) {
  return {
    ...emptyDashboard,
    ...value,
    connection: { ...emptyDashboard.connection, ...(value?.connection || {}) },
    status: value?.status || {},
    enrollment: value?.enrollment || {},
    certificate: value?.certificate || {},
    user: value?.user || {},
    posture: value?.posture || { checks: [] },
    resources: value?.resources || [],
    active_sessions: value?.active_sessions || [],
    access_events: value?.access_events || []
  };
}

export function toneForConnection(state) {
  if (state === 'connected') return 'success';
  if (state === 'unenrolled') return 'warning';
  return 'danger';
}

export function toneForEnrollment(state) {
  if (state === 'ENROLLED') return 'success';
  if (state === 'PENDING') return 'warning';
  if (state === 'UNENROLLED') return 'warning';
  return 'danger';
}

export function toneForSession(state) {
  if (state === 'ready') return 'success';
  if (state === 'missing' || state === 'expired') return 'warning';
  return 'danger';
}

export function formatTime(value) {
  if (!value) return 'Unavailable';
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.getFullYear() <= 1) return 'Unavailable';
  return date.toLocaleString();
}
