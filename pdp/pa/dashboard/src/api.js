// API client for the ZTNA PDP/PA backend
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

  const text = await res.text();
  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      if (!res.ok) {
        throw new Error(text || res.statusText);
      }
      throw new Error(`Invalid JSON response from ${path}`);
    }
  }

  if (!res.ok) {
    throw new Error(json?.error || res.statusText);
  }

  // Unwrap APIResponse envelope: { success, data, message } -> data
  if (json !== null && typeof json === 'object' && 'data' in json) {
    return json.data;
  }
  return json;
}

// Organizations. The backend contract still uses /admin/tenants.

export async function getTenants() {
  return apiFetch('/admin/tenants');
}

export async function createTenant(data) {
  return apiFetch('/admin/tenants', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function getTenant(id) {
  return apiFetch(`/admin/tenants/${id}`);
}

export async function updateTenant(id, data) {
  return apiFetch(`/admin/tenants/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteTenant(id) {
  return apiFetch(`/admin/tenants/${id}`, {
    method: 'DELETE',
  });
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

export async function verifyMFA(token, code, method = 'totp') {
  const res = await fetch(`${API_BASE}/auth/verify-mfa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfa_token: token, method, totp_code: code }),
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

export async function getDevicePostureReports() {
  return apiFetch('/admin/device-posture');
}

export async function getDevicePostureReport(deviceId) {
  return apiFetch(`/admin/device-posture/${encodeURIComponent(deviceId)}`);
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

export async function testGatewayFederation(id, issuer) {
  return apiFetch(`/admin/gateways/${id}/test-federation`, {
    method: 'POST',
    body: JSON.stringify({ issuer: issuer || '' }),
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

export async function getPolicyAssignments() {
  return apiFetch('/admin/policy-assignments');
}

export async function createPolicyAssignment(data) {
  return apiFetch('/admin/policy-assignments', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updatePolicyAssignment(id, data) {
  return apiFetch(`/admin/policy-assignments/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deletePolicyAssignment(id) {
  return apiFetch(`/admin/policy-assignments/${id}`, {
    method: 'DELETE',
  });
}

// Directory principals provisioned by organization IdPs through SCIM.

export async function getDirectoryUsers(tenantId = '', idpId = '') {
  const params = new URLSearchParams();
  if (tenantId) params.set('tenant_id', tenantId);
  if (idpId) params.set('idp_id', idpId);
  const query = params.toString();
  return apiFetch(`/admin/directory/users${query ? `?${query}` : ''}`);
}

export async function getDirectoryGroups(tenantId = '', idpId = '') {
  const params = new URLSearchParams();
  if (tenantId) params.set('tenant_id', tenantId);
  if (idpId) params.set('idp_id', idpId);
  const query = params.toString();
  return apiFetch(`/admin/directory/groups${query ? `?${query}` : ''}`);
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

// Identity Providers (per Organization)

export async function getIdPs(tenantId) {
  return apiFetch(`/admin/tenants/idps?tenant_id=${encodeURIComponent(tenantId)}`);
}

export async function createIdP(tenantId, data) {
  return apiFetch(`/admin/tenants/idps?tenant_id=${encodeURIComponent(tenantId)}`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function getIdP(id) {
  return apiFetch(`/admin/tenants/idps/${id}`);
}

export async function updateIdP(id, data) {
  return apiFetch(`/admin/tenants/idps/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteIdP(id) {
  return apiFetch(`/admin/tenants/idps/${id}`, {
    method: 'DELETE',
  });
}

export async function discoverIdP(issuer) {
  return apiFetch(`/admin/tenants/idps/discover`, {
    method: 'POST',
    body: JSON.stringify({ issuer }),
  });
}
