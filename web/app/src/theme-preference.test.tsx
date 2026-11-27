import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ThemePreference } from './theme-preference';

const storageKey = 'xtrace.viewer.theme';
const root = document.documentElement;

function stubSystemColorScheme() {
  const media = Object.assign(new EventTarget(), { matches: false });
  vi.stubGlobal('matchMedia', () => media);
  return (light: boolean) => {
    media.matches = light;
    media.dispatchEvent(new Event('change'));
  };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.localStorage.removeItem(storageKey);
  delete root.dataset.theme;
});

it('falls back to live System mode for an invalid stored choice', () => {
  window.localStorage.setItem(storageKey, 'constructor');
  const setSystemLight = stubSystemColorScheme();
  render(<ThemePreference />);

  expect(screen.getByRole('combobox', { name: 'Theme' })).toHaveValue('system');
  expect(root).toHaveAttribute('data-theme', 'dark');
  setSystemLight(true);
  expect(root).toHaveAttribute('data-theme', 'light');
});

it('uses System mode when access to localStorage is blocked', () => {
  vi.spyOn(window, 'localStorage', 'get').mockImplementation(() => {
    throw new DOMException('Storage access blocked', 'SecurityError');
  });
  const setSystemLight = stubSystemColorScheme();
  setSystemLight(true);
  render(<ThemePreference />);

  expect(screen.getByRole('combobox', { name: 'Theme' })).toHaveValue('system');
  expect(root).toHaveAttribute('data-theme', 'light');
});

it('keeps an explicit theme active in memory when saving fails', () => {
  const save = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new DOMException('Storage quota exceeded', 'QuotaExceededError');
  });
  const setSystemLight = stubSystemColorScheme();
  render(<ThemePreference />);

  const theme = screen.getByRole('combobox', { name: 'Theme' });
  fireEvent.change(theme, { target: { value: 'hc' } });
  expect(save).toHaveBeenCalledWith(storageKey, 'hc');
  expect(theme).toHaveValue('hc');
  expect(root).toHaveAttribute('data-theme', 'hc');
  expect(window.localStorage.getItem(storageKey)).toBeNull();

  setSystemLight(true);
  expect(root).toHaveAttribute('data-theme', 'hc');
  fireEvent.change(theme, { target: { value: 'system' } });
  expect(root).toHaveAttribute('data-theme', 'light');
});
