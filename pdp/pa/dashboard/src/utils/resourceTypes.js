export function resourceTypeBadgeVariant(type) {
  const normalized = String(type || '').trim().toLowerCase();
  if (normalized === 'web') return 'resourceWeb';
  if (normalized === 'ssh') return 'resourceSsh';
  if (normalized === 'rdp') return 'resourceRdp';
  return 'neutral';
}
