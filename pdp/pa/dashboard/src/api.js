// API client for the TrustCloud/PA backend
const API_BASE = '/api';
const ACCESS_TOKEN_KEY = 'admin_token';
const REFRESH_TOKEN_KEY = 'admin_refresh_token';
const SESSION_ID_KEY = 'admin_session_id';

// Get the auth token from localStorage
export function getToken() {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken() {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function getSessionID() {
  return localStorage.getItem(SESSION_ID_KEY);
}

// Set the auth token
export function setToken(token) {
  if (token) {
    localStorage.setItem(ACCESS_TOKEN_KEY, token);
  }
}

export function setAuthSession(session) {
  if (!session) return;
  setToken(session.auth_token || session.token);
  if (session.refresh_token) {
    localStorage.setItem(REFRESH_TOKEN_KEY, session.refresh_token);
  }
  if (session.session_id) {
    localStorage.setItem(SESSION_ID_KEY, session.session_id);
  }
}

// Clear auth
export function clearAuthSession() {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(SESSION_ID_KEY);
}

export function clearToken() {
  clearAuthSession();
}

function decodeTokenPayload(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const padded = parts[1] + '='.repeat((4 - (parts[1].length % 4)) % 4);
    const json = window.atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export function getTokenExpiresAt() {
  const payload = decodeTokenPayload(getToken());
  if (!payload?.exp) return null;
  return Number(payload.exp) * 1000;
}

export function getSessionRefreshDelay() {
  const expiresAt = getTokenExpiresAt();
  if (!expiresAt) return 5 * 60 * 1000;
  const remaining = expiresAt - Date.now();
  if (remaining <= 0) return 0;
  const refreshBeforeExpiry = 2 * 60 * 1000;
  if (remaining <= refreshBeforeExpiry) return 0;
  const maxRefreshInterval = 5 * 60 * 1000;
  const minRefreshInterval = 30 * 1000;
  return Math.max(minRefreshInterval, Math.min(maxRefreshInterval, remaining - refreshBeforeExpiry));
}

function authHeaders(extraHeaders = {}) {
  const token = getToken();
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...extraHeaders,
  };
}

async function readJSONResponse(res, path) {
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

  if (json !== null && typeof json === 'object' && 'data' in json) {
    return json.data;
  }
  return json;
}

// Generic fetch wrapper with auth headers, error handling, token refresh, and response unwrapping
async function apiFetch(path, options = {}) {
  const {
    redirectOnUnauthorized = true,
    retryOnUnauthorized = true,
    clearOnUnauthorized = true,
    ...fetchOptions
  } = options;

  const run = () => fetch(`${API_BASE}${path}`, {
    ...fetchOptions,
    headers: authHeaders(fetchOptions.headers),
  });

  let res = await run();

  if (res.status === 401 && retryOnUnauthorized && getRefreshToken() && getSessionID()) {
    try {
      await refreshAdminSession();
      res = await run();
    } catch {
      // Fall through to the normal unauthorized handling below.
    }
  }

  if (res.status === 401) {
    if (clearOnUnauthorized) clearAuthSession();
    if (redirectOnUnauthorized) {
      window.location.href = '/login';
    }
    throw new Error('Unauthorized');
  }

  return readJSONResponse(res, path);
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

export async function refreshAdminSession() {
  const sessionID = getSessionID();
  const refreshToken = getRefreshToken();
  if (!sessionID || !refreshToken) {
    throw new Error('Missing session refresh credentials');
  }
  const res = await fetch(`${API_BASE}/auth/session/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionID, refresh_token: refreshToken }),
  });
  const session = await readJSONResponse(res, '/auth/session/refresh');
  setAuthSession(session);
  return session;
}

export async function logoutAdminSession() {
  const token = getToken();
  const sessionID = getSessionID();
  const refreshToken = getRefreshToken();
  try {
    await fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ session_id: sessionID, refresh_token: refreshToken }),
    });
  } finally {
    clearAuthSession();
  }
}

export async function validateAdminSession() {
  if (!getToken()) {
    return refreshAdminSession();
  }
  try {
    return await apiFetch('/admin/session', {
      redirectOnUnauthorized: false,
      retryOnUnauthorized: false,
      clearOnUnauthorized: false,
    });
  } catch (err) {
    if (getRefreshToken() && getSessionID()) {
      return refreshAdminSession();
    }
    throw err;
  }
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
