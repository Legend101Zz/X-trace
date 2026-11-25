import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { useThemePreference } from '../../theme-preference';
import { ViewerSettings } from './ViewerSettings';
import { useAppearancePreferences } from './viewer-preferences';

const key = 'xtrace.viewer.appearance';

function SettingsHarness() {
  const appearance = useAppearancePreferences();
  const theme = useThemePreference();
  return <ViewerSettings appearance={appearance} theme={theme} dock="bottom" onDock={() => undefined} />;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.removeItem(key);
  delete document.documentElement.dataset.theme;
});

it('validates stored choices independently and restores valid updates after remount', () => {
  localStorage.setItem(key, JSON.stringify({ codeSize: '99', density: 'compact', time: 'utc', inline: 'off', motion: 'force' }));
  const mounted = render(<SettingsHarness />);
  expect(screen.getByLabelText('Code font size')).toHaveValue('12');
  expect(screen.getByLabelText('Density')).toHaveValue('compact');
  expect(screen.getByLabelText('Recording times')).toHaveValue('utc');
  expect(screen.getByLabelText('Inline values in code')).toHaveValue('off');
  expect(screen.getByLabelText('Animations')).toHaveValue('system');
  fireEvent.change(screen.getByLabelText('Code font size'), { target: { value: '16' } });
  mounted.unmount();
  render(<SettingsHarness />);
  expect(screen.getByLabelText('Code font size')).toHaveValue('16');
  expect(screen.getByLabelText('Recording times')).toHaveValue('utc');
});

it('keeps appearance usable for the session when storage reads and writes are blocked', () => {
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('storage blocked'); });
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('storage blocked'); });
  const mounted = render(<SettingsHarness />);
  const inline = screen.getByLabelText('Inline values in code');
  expect(inline).toHaveValue('on');
  fireEvent.change(inline, { target: { value: 'off' } });
  expect(inline).toHaveValue('off');
  fireEvent.change(screen.getByLabelText('Animations'), { target: { value: 'reduce' } });
  expect(screen.getByLabelText('Animations')).toHaveValue('reduce');
  mounted.unmount();
  render(<SettingsHarness />);
  expect(screen.getByLabelText('Inline values in code')).toHaveValue('on');
  expect(screen.getByLabelText('Animations')).toHaveValue('system');
});
