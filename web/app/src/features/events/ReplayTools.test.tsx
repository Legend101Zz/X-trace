import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { useRef, useState } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import type { ReplayEvent } from '../../types';
import { ReplayTools } from './ReplayTools';
import { useAppearancePreferences, ViewerPreferencesContext, ViewerPreferencesUpdateContext } from '../shell/viewer-preferences';
import { ViewerSettings } from '../shell/ViewerSettings';
import { useThemePreference } from '../../theme-preference';

const steps = [
  { sequence: '2', kind: 'recording_event_kind:frame_enter', frameId: 'same' },
  { sequence: '4', kind: 'recording_event_kind:gap', frameId: null },
  { sequence: '6', kind: 'recording_event_kind:frame_throw', frameId: 'same' },
] as ReplayEvent[];

function Harness({ onGo = vi.fn(), onAnnounce = vi.fn() }: { onGo?: (sequence: string) => void; onAnnounce?: (message: string) => void }) {
  const appearance = useAppearancePreferences();
  const theme = useThemePreference();
  const [kinds, setKinds] = useState<readonly string[]>([]);
  const controlRef = useRef<HTMLButtonElement>(null);
  return <ViewerPreferencesContext.Provider value={appearance.preferences}>
    <ViewerPreferencesUpdateContext.Provider value={appearance.update}>
      <input aria-label="Normal typing" />
      <ReplayTools events={steps} selected={steps[0]} filter={{ kinds }} busy={false} onFilter={setKinds}
        onGo={onGo} onActivate={() => undefined} onAnnounce={onAnnounce} controlRef={controlRef} />
      <ViewerSettings appearance={appearance} theme={theme} dock="bottom" onDock={() => undefined} />
    </ViewerPreferencesUpdateContext.Provider>
  </ViewerPreferencesContext.Provider>;
}

afterEach(() => { cleanup(); vi.unstubAllGlobals(); localStorage.clear(); });

it('groups the tools below 1280 and restores the keyboard opener on Escape', () => {
  render(<Harness />);
  const tools = screen.getByRole('button', { name: 'Tools' });
  tools.focus();
  fireEvent.click(tools);
  const menu = screen.getByRole('dialog', { name: 'Tools' });
  expect(within(menu).getByRole('button', { name: 'Filter steps' })).toHaveFocus();
  fireEvent.click(within(menu).getByRole('button', { name: 'Filter steps' }));
  const filter = screen.getByRole('dialog', { name: 'Filter steps' });
  expect(within(filter).getByRole('button', { name: 'All steps' })).toHaveFocus();
  fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(tools).toHaveFocus();
});

it('exposes individual wide actions and shares the timing setting in both directions', () => {
  vi.stubGlobal('matchMedia', () => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  render(<Harness />);
  expect(screen.queryByRole('button', { name: 'Tools' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Filter' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Go to step' })).toBeInTheDocument();
  const timing = screen.getByRole('button', { name: 'Show timing' });
  expect(timing).toHaveAttribute('aria-pressed', 'false');
  fireEvent.click(timing);
  expect(screen.getByLabelText('Show timing')).toHaveValue('on');
  fireEvent.change(screen.getByLabelText('Show timing'), { target: { value: 'off' } });
  expect(timing).toHaveAttribute('aria-pressed', 'false');
  expect(JSON.parse(localStorage.getItem('xtrace.viewer.appearance')!).timing).toBe('off');
});

it('leaves text editing shortcuts alone and validates exact loaded Go targets without numeric coercion', () => {
  const go = vi.fn();
  render(<Harness onGo={go} />);
  const input = screen.getByRole('textbox', { name: 'Normal typing' });
  input.focus();
  fireEvent.keyDown(input, { altKey: true, code: 'KeyJ' });
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  screen.getByRole('button', { name: 'Tools' }).focus();
  fireEvent.keyDown(document.activeElement!, { altKey: true, code: 'KeyJ' });
  const dialog = screen.getByRole('dialog', { name: 'Go to step' });
  const sequence = within(dialog).getByRole('textbox', { name: 'Go to step number' });
  expect(sequence).toHaveFocus();
  for (const value of ['2tail', '2.5', '99']) {
    fireEvent.change(sequence, { target: { value } });
    fireEvent.submit(sequence.closest('form')!);
    expect(go).not.toHaveBeenCalled();
  }
  expect(dialog).toHaveTextContent('Event sequence is not in the loaded window.');
  expect(dialog).toHaveTextContent('No match here does not mean no match in the recording.');
  fireEvent.change(sequence, { target: { value: '0004' } });
  fireEvent.submit(sequence.closest('form')!);
  expect(go).toHaveBeenCalledExactlyOnceWith('4');
});

it('gives the reason for an unavailable loaded Jump and selects an observed frameless gap', () => {
  const go = vi.fn();
  const announce = vi.fn();
  render(<Harness onGo={go} onAnnounce={announce} />);
  screen.getByRole('button', { name: 'Tools' }).focus();
  fireEvent.keyDown(document.activeElement!, { altKey: true, code: 'KeyG' });
  const dialog = screen.getByRole('dialog', { name: 'Jump to' });
  const absent = within(dialog).getByRole('button', { name: 'Next database call' });
  expect(absent).toHaveAttribute('aria-disabled', 'true');
  fireEvent.click(absent);
  expect(announce).toHaveBeenCalledWith('No later database call in the loaded steps.');
  expect(dialog).toHaveTextContent('No later database call in the loaded steps.');
  expect(go).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Next not-recorded stretch' }));
  expect(go).toHaveBeenCalledExactlyOnceWith('4');
});

it('keeps each unavailable Jump reason attached when pointer feedback changes', () => {
  const go = vi.fn();
  render(<Harness onGo={go} />);
  screen.getByRole('button', { name: 'Tools' }).focus();
  fireEvent.keyDown(document.activeElement!, { altKey: true, code: 'KeyG' });
  const dialog = screen.getByRole('dialog', { name: 'Jump to' });
  const absent = within(dialog).getByRole('button', { name: 'Next database call' });
  absent.focus();
  expect(absent).toHaveAccessibleDescription('No later database call in the loaded steps.');
  fireEvent.mouseEnter(within(dialog).getByRole('button', { name: 'Next not-recorded stretch' }));
  expect(absent).toHaveAccessibleDescription('No later database call in the loaded steps.');
  expect(within(dialog).getByRole('button', { name: 'Previous http call' }))
    .toHaveAccessibleDescription('No earlier http call in the loaded steps.');
  expect(go).not.toHaveBeenCalled();
});
