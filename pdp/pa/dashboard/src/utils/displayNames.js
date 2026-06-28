export function displayGatewayName(gateway, fallback = 'Gateway') {
  const name = String(gateway?.name || '').trim();
  if (name) return name;
  const fqdn = String(gateway?.fqdn || '').trim();
  if (fqdn) return fqdn;
  return fallback;
}

export function displayResourceName(resource, fallback = 'Resource') {
  const name = String(resource?.name || '').trim();
  if (name) return name;
  return fallback;
}

export function displayOrganizationName(organization, fallback = 'Organization') {
  const name = String(organization?.name || '').trim();
  if (name) return name;
  const domain = String(organization?.domain || '').trim();
  if (domain) return domain;
  return fallback;
}

export function isInternalID(value) {
  return /^[a-z][a-z0-9_]*_[a-f0-9]{16,}$/i.test(String(value || '').trim());
}

export function displayResourceReference(value, resourcesByID, gatewaysByID, fallback = '-') {
  const key = String(value || '').trim();
  if (!key) return fallback;

  const resource = resourcesByID?.get(key);
  if (resource) return displayResourceName(resource, fallback);

  const gateway = gatewaysByID?.get(key);
  if (gateway) return displayGatewayName(gateway, fallback);

  return isInternalID(key) ? fallback : key;
}
