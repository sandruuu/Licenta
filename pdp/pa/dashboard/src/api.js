// API client for the TrustCloud/PA backend
const API_BASE = '/api';

// Get the auth token from localStorage
export function getToken() {
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
  const { redirectOnUnauthorized = true, ...fetchOptions } = options;
  const token = getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...fetchOptions.headers,
  };

  const res = await fetch(`${API_BASE}${path}`, {
    ...fetchOptions,
    headers,
  });

  if (res.status === 401) {
    clearToken();
    if (redirectOnUnauthorized) {
      window.location.href = '/login';
    }
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

export async function getOrganizations() {
  return apiFetch('/admin/organizations');
}

export async function createOrganization(data) {
  return apiFetch('/admin/organizations', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function getOrganization(id) {
  return apiFetch(`/admin/organizations/${id}`);
}

export async function updateOrganization(id, data) {
  return apiFetch(`/admin/organizations/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteOrganization(id) {
  return apiFetch(`/admin/organizations/${id}`, {
    method: 'DELETE',
  });
}

// ─── Auth ───────────────────────────────────

export async function login(email, password, purpose = '') {
  const body = { email, password };
  if (purpose) {
    body.purpose = purpose;
  }
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

export async function verifyMFA(challengeId, code) {
  const res = await fetch(`${API_BASE}/auth/mfa/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_id: challengeId, code }),
  });
  return res.json();
}

export async function beginPasskeyAuthentication(email) {
  const res = await fetch(`${API_BASE}/auth/passkey/login/begin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || data.message || 'Could not start passkey sign-in');
  }
  return data;
}

export async function finishPasskeyAuthentication(email, challengeId, credential) {
  const params = new URLSearchParams({ email, challenge_id: challengeId });
  const res = await fetch(`${API_BASE}/auth/passkey/login/finish?${params.toString()}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credential),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || data.message || 'Passkey sign-in failed');
  }
  return data;
}

export async function beginPasskeyRegistration(token) {
  const res = await fetch(`${API_BASE}/auth/passkey/register/begin`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({}),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || data.message || 'Could not start passkey registration');
  }
  return data;
}

export async function finishPasskeyRegistration(token, credential) {
  const res = await fetch(`${API_BASE}/auth/passkey/register/finish`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(credential),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || data.message || 'Passkey registration failed');
  }
  return data;
}

export async function validateAdminSession() {
  return apiFetch('/admin/session', {
    redirectOnUnauthorized: false,
  });
}

// ─── Dashboard ──────────────────────────────

export async function getDashboardStats() {
  return apiFetch('/admin/dashboard');
}

export async function getDeviceDataReports() {
  return apiFetch('/admin/device-data');
}

export async function getDeviceDataReport(deviceId) {
  return apiFetch(`/admin/device-data/${encodeURIComponent(deviceId)}`);
}

export async function getEnrollments() {
  return apiFetch('/admin/enrollments');
}

export async function revokeEnrollment(id) {
  return apiFetch(`/admin/enrollments/${encodeURIComponent(id)}/revoke`, {
    method: 'POST',
  });
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

// Access policies use Duo-style assignment layers: organization, group, resource, and resource_group.

export async function getPolicies() {
  return apiFetch('/admin/policies');
}

export async function createPolicy(data) {
  return apiFetch('/admin/policies', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function getPolicy(id) {
  return apiFetch(`/admin/policies/${id}`);
}

export async function updatePolicy(id, data) {
  return apiFetch(`/admin/policies/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deletePolicy(id) {
  return apiFetch(`/admin/policies/${id}`, {
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

// Directory principals provisioned by organization IdPs through SCIM.

export async function getDirectoryUsers(organizationId = '', idpId = '') {
  const params = new URLSearchParams();
  if (organizationId) params.set('organization_id', organizationId);
  if (idpId) params.set('idp_id', idpId);
  const query = params.toString();
  return apiFetch(`/admin/directory/users${query ? `?${query}` : ''}`);
}

export async function getDirectoryGroups(organizationId = '', idpId = '') {
  const params = new URLSearchParams();
  if (organizationId) params.set('organization_id', organizationId);
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

export async function getIdPs(organizationId) {
  return apiFetch(`/admin/organizations/idps?organization_id=${encodeURIComponent(organizationId)}`);
}

export async function createIdP(organizationId, data) {
  return apiFetch(`/admin/organizations/idps?organization_id=${encodeURIComponent(organizationId)}`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function getIdP(id) {
  return apiFetch(`/admin/organizations/idps/${id}`);
}

export async function updateIdP(id, data) {
  return apiFetch(`/admin/organizations/idps/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteIdP(id) {
  return apiFetch(`/admin/organizations/idps/${id}`, {
    method: 'DELETE',
  });
}

export async function discoverIdP(issuer) {
  return apiFetch(`/admin/organizations/idps/discover`, {
    method: 'POST',
    body: JSON.stringify({ issuer }),
  });
}
