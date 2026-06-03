export function currentLocationPath(location) {
  if (!location) return '/';
  return `${location.pathname || '/'}${location.search || ''}${location.hash || ''}`;
}

export function navigateWithReturn(navigate, to, location) {
  navigate(to, { state: { returnTo: currentLocationPath(location) } });
}

export function navigateBack(navigate, fallback, location) {
  const returnTo = safeInternalPath(location?.state?.returnTo);
  const currentPath = currentLocationPath(location);

  if (returnTo && returnTo !== currentPath) {
    navigate(returnTo, { replace: true });
    return;
  }

  if (canUseBrowserBack()) {
    navigate(-1);
    return;
  }

  navigate(fallback || '/', { replace: true });
}

function safeInternalPath(value) {
  if (typeof value !== 'string') return '';
  if (!value.startsWith('/') || value.startsWith('//')) return '';
  return value;
}

function canUseBrowserBack() {
  if (typeof window === 'undefined') return false;
  const index = window.history?.state?.idx;
  if (typeof index !== 'number' || index <= 0) return false;

  if (typeof document !== 'undefined' && document.referrer) {
    try {
      return new URL(document.referrer).origin === window.location.origin;
    } catch {
      return false;
    }
  }

  return true;
}
