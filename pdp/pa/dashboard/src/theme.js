const THEME_KEY = 'pdp_theme';
const LIGHT_THEME = 'light';

export function getCurrentTheme() {
  if (typeof document === 'undefined') return LIGHT_THEME;
  const theme = document.documentElement.dataset.theme;
  return theme === LIGHT_THEME ? theme : LIGHT_THEME;
}

export function applyTheme() {
  const nextTheme = LIGHT_THEME;
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.theme = nextTheme;
    document.documentElement.style.colorScheme = nextTheme;
  }
  return nextTheme;
}

export function initTheme() {
  try {
    localStorage.setItem(THEME_KEY, LIGHT_THEME);
  } catch {
    // The dashboard still renders light if storage is unavailable.
  }
  return applyTheme();
}

export function saveTheme() {
  const nextTheme = applyTheme();
  try {
    localStorage.setItem(THEME_KEY, nextTheme);
  } catch {
    // Session-level theme still works if storage is unavailable.
  }
  return nextTheme;
}
