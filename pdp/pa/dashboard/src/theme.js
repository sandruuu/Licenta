const THEME_KEY = 'pdp_theme';
const THEMES = new Set(['light', 'dark']);

function systemTheme() {
  if (typeof window === 'undefined' || !window.matchMedia) return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function getCurrentTheme() {
  if (typeof document === 'undefined') return 'light';
  const theme = document.documentElement.dataset.theme;
  if (THEMES.has(theme)) return theme;
  return systemTheme();
}

export function applyTheme(theme) {
  const nextTheme = THEMES.has(theme) ? theme : systemTheme();
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.theme = nextTheme;
    document.documentElement.style.colorScheme = nextTheme;
  }
  return nextTheme;
}

export function initTheme() {
  let stored = '';
  try {
    stored = localStorage.getItem(THEME_KEY) || '';
  } catch {
    stored = '';
  }
  return applyTheme(THEMES.has(stored) ? stored : systemTheme());
}

export function saveTheme(theme) {
  const nextTheme = applyTheme(theme);
  try {
    localStorage.setItem(THEME_KEY, nextTheme);
  } catch {
    // Session-level theme still works if storage is unavailable.
  }
  return nextTheme;
}
