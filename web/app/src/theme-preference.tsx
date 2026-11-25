import { useLayoutEffect, useState } from 'react';

const THEMES = { system: 'System', dark: 'Dark', light: 'Light', hc: 'High contrast' } as const;
type Theme = keyof typeof THEMES;

const STORAGE_KEY = 'xtrace.viewer.theme';

function isTheme(value: string | null): value is Theme {
  return value !== null && Object.hasOwn(THEMES, value);
}

function initialTheme(): Theme {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY);
    if (isTheme(value)) return value;
  } catch {
    // The preference still works in memory when the browser blocks storage.
  }
  return 'system';
}

export function ThemePreference() {
  const [theme, setTheme] = useState(initialTheme);

  useLayoutEffect(() => {
    const root = document.documentElement;
    if (theme !== 'system') {
      root.dataset.theme = theme;
      return;
    }
    const light = window.matchMedia?.('(prefers-color-scheme: light)');
    const applySystem = () => { root.dataset.theme = light?.matches ? 'light' : 'dark'; };
    applySystem();
    light?.addEventListener('change', applySystem);
    return () => light?.removeEventListener('change', applySystem);
  }, [theme]);

  return <div className="theme-preference">
    <label id="viewer-theme-label" htmlFor="viewer-theme">Theme</label>
    <select className="theme-select" id="viewer-theme" aria-labelledby="viewer-theme-label" value={theme} onChange={(event) => {
      const value = event.currentTarget.value;
      if (!isTheme(value)) return;
      setTheme(value);
      try {
        window.localStorage.setItem(STORAGE_KEY, value);
      } catch {
        // Keep the current selection without a persistent copy.
      }
    }}>
      {Object.entries(THEMES).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
    </select>
  </div>;
}
