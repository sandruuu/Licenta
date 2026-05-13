export function formatDate(d) {
  if (!d) return '-';
  return new Date(d).toLocaleDateString('ro-RO');
}

export function copyText(text) {
  if (!text) return;
  navigator.clipboard.writeText(text).catch(() => {});
}

export function gatewayLabelFromName(name) {
  return (name || '')
    .trim()
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63);
}

export function tenantDomain(tenant) {
  return (tenant?.domain || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
}

export function gatewayFQDN(name, tenant) {
  const label = gatewayLabelFromName(name);
  const domain = tenantDomain(tenant);
  return label && domain ? `${label}.${domain}` : '';
}
