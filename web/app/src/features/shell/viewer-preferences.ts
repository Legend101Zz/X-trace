import { createContext, useContext, useState } from 'react';

export const CODE_SIZES = ['12', '13', '14', '16'] as const;

const defaults = {
  codeSize: '12' as typeof CODE_SIZES[number],
  density: 'comfortable' as 'comfortable' | 'compact',
  time: 'local' as 'local' | 'utc',
  inline: 'on' as 'on' | 'off',
  timing: 'off' as 'on' | 'off',
  motion: 'system' as 'system' | 'reduce',
};

type ViewerPreferences = typeof defaults;
const choices = {
  codeSize: CODE_SIZES,
  density: ['comfortable', 'compact'],
  time: ['local', 'utc'],
  inline: ['on', 'off'],
  timing: ['on', 'off'],
  motion: ['system', 'reduce'],
} as const;

const KEY = 'xtrace.viewer.appearance';
export const ViewerPreferencesContext = createContext<ViewerPreferences>(defaults);
export const useViewerPreferences = () => useContext(ViewerPreferencesContext);
export const ViewerPreferencesUpdateContext = createContext<ReturnType<typeof useAppearancePreferences>['update'] | null>(null);

function read(): ViewerPreferences {
  try {
    const stored: unknown = JSON.parse(localStorage.getItem(KEY) ?? 'null');
    if (!stored || typeof stored !== 'object') return defaults;
    return Object.fromEntries(Object.entries(choices).map(([key, options]) => {
      const value: unknown = Reflect.get(stored, key);
      return [key, options.some((item) => item === value) ? value : defaults[key as keyof ViewerPreferences]];
    })) as ViewerPreferences;
  } catch {
    return defaults;
  }
}

export function useAppearancePreferences() {
  const [preferences, setPreferences] = useState(read);
  function update<Key extends keyof ViewerPreferences>(key: Key, value: ViewerPreferences[Key]) {
    const next = { ...preferences, [key]: value };
    setPreferences(next);
    try { localStorage.setItem(KEY, JSON.stringify(next)); } catch {
      // Keep the working preference in memory when storage is unavailable.
    }
  }
  return { preferences, update };
}
