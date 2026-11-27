import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { AppShell } from '../../app-shell';
import { useAppearancePreferences } from '../shell/viewer-preferences';
import { StartTourButton } from '../shell/ViewerTour';
import { ExportAction } from './ExportAction';

it('gives Export the active tour and replay handoff and returns focus to the export opener', () => {
  const pause = vi.fn();
  function Shell() {
    const appearance = useAppearancePreferences();
    return <AppShell activePane="recordings" onPane={() => undefined} announcement="" auth="ready" authError=""
      openRecordings={[]} selectedRecording="" onSelectRecording={() => undefined} onCloseRecording={() => undefined}
      sourceEvent={undefined} detail={null} endpoint={null} appearance={appearance} playbackControls={null} onPausePlayback={pause} onTourSteps={() => undefined}>
      <><StartTourButton /><ExportAction endpoint={null} label="Export endpoints…" /></>
      {null}
      {null}
    </AppShell>;
  }

  // jsdom lacks native modality. The installed journey also checks modality and the real replay timer.
  const prototype = HTMLDialogElement.prototype;
  const installModal = typeof prototype.showModal !== 'function';
  const installClose = typeof prototype.close !== 'function';
  if (installModal) Object.defineProperty(prototype, 'showModal', { configurable: true, value(this: HTMLDialogElement) { this.open = true; } });
  if (installClose) Object.defineProperty(prototype, 'close', { configurable: true, value(this: HTMLDialogElement) { this.open = false; } });
  try {
    render(<Shell />);
    fireEvent.click(screen.getByRole('button', { name: 'Take the 3-step tour' }));
    expect(screen.getByRole('dialog', { name: 'Find a recording' })).toBeInTheDocument();
    pause.mockClear();
    const opener = screen.getByRole('button', { name: 'Export endpoints…' });
    fireEvent.click(opener);
    const sheet = screen.getByRole('dialog', { name: 'Export' });
    expect(pause).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog', { name: 'Find a recording' })).toBeNull();
    expect(within(sheet).getByRole('button', { name: 'Close' })).toHaveFocus();
    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    expect(opener).toHaveFocus();
    expect(screen.queryByRole('dialog')).toBeNull();
  } finally {
    cleanup();
    if (installModal) Reflect.deleteProperty(prototype, 'showModal');
    if (installClose) Reflect.deleteProperty(prototype, 'close');
  }
});
