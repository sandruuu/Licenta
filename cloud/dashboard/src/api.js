// API client for the ZTNA Cloud PDP/IdP backend
const API_BASE = '/api';

// Get the auth token from localStorage
function getToken() {
  return localStorage.getItem('admin_token');
}

// Set the auth token
export function setToken(token) {
  localStorage.setItem('admin_token', token);
}

// Clear auth
export function clearToken() {
  localStorage.removeItem('admin_token');
}

// Generic fetch wrapper with auth headers, error handling, and response unwrapping
async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    clearToken();
    window.location.href = '/dashboard/login';
    throw new Error('Unauthorized');
  }

  const json = await res.json();

  if (!res.ok) {
    throw new Error(json.error || res.statusText);
  }

  // Unwrap APIResponse envelope: { success, data, message } -> data
  if (json !== null && typeof json === 'object' && 'data' in json) {
    return json.data;
  }
  return json;
}

// ─── Auth ───────────────────────────────────

export async function login(username, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  return res.json();
}

export async function verifyMFA(token, code) {
  const res = await fetch(`${API_BASE}/auth/verify-mfa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, code }),
  });
  return res.json();
}

// ─── Dashboard ──────────────────────────────

export async function getDashboardStats() {
  return apiFetch('/admin/dashboard');
}

export async function getDeviceHealthReports() {
  return apiFetch('/admin/device-health');
}

export async function getDeviceHealthReport(deviceId) {
  return apiFetch(`/admin/device-health/${encodeURIComponent(deviceId)}`);
}

// ─── Resources ──────────────────────────────

export async function getResources() {
  return apiFetch('/admin/resources');
}

export async function getResource(id) {
  return apiFetch(`/admin/resources/${id}`);
}

export async function createResource(data) {
  return apiFetch('/admin/resources', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateResource(id, data) {
  return apiFetch(`/admin/resources/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteResource(id) {
  return apiFetch(`/admin/resources/${id}`, {
    method: 'DELETE',
  });
}

export async function generateCert(resourceId, domain, validDays) {
  return apiFetch('/admin/resources-generate-cert', {
    method: 'POST',
    body: JSON.stringify({ resource_id: resourceId, domain, valid_days: validDays }),
  });
}

export async function regenerateSecret(resourceId) {
  return apiFetch(`/admin/resources-regenerate-secret/${resourceId}`, {
    method: 'POST',
  });
}

// ─── Gateways ───────────────────────────────

export async function getGateways() {
  return apiFetch('/admin/gateways');
}

export async function createGateway(data) {
  return apiFetch('/admin/gateways', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function getGateway(id) {
  return apiFetch(`/admin/gateways/${id}`);
}

export async function updateGateway(id, data) {
  return apiFetch(`/admin/gateways/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteGateway(id) {
  return apiFetch(`/admin/gateways/${id}`, {
    method: 'DELETE',
  });
}

export async function regenerateGatewayToken(id) {
  return apiFetch(`/admin/gateways/${id}/regenerate-token`, {
    method: 'POST',
  });
}

export async function revokeGateway(id) {
  return apiFetch(`/admin/gateways/${id}/revoke`, {
    method: 'POST',
  });
}

// ─── Policy Rules ───────────────────────────

export async function getRules() {
  return apiFetch('/admin/rules');
}

export async function createRule(data) {
  return apiFetch('/admin/rules', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateRule(id, data) {
  return apiFetch(`/admin/rules/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteRule(id) {
  return apiFetch(`/admin/rules/${id}`, {
    method: 'DELETE',
  });
}

// ─── Users ──────────────────────────────────

export async function getUsers() {
  return apiFetch('/admin/users');
}

// ─── Sessions ───────────────────────────────

export async function getSessions() {
  return apiFetch('/admin/sessions');
}

export async function revokeSession(id) {
  return apiFetch(`/admin/sessions/${id}`, {
    method: 'DELETE',
  });
}

// ─── Audit ──────────────────────────────────

export async function getAuditLog(limit = 100) {
  return apiFetch(`/admin/audit?limit=${limit}`);
}
