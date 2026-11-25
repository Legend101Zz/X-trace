import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ReplayControls } from './ReplayControls';

afterEach(cleanup);
const playback = { status: 'paused' as const, speed: 1 as const, stopReason: null, epoch: 0 };
const actions = () => ({ onToggle: vi.fn(), onPause: vi.fn(), onSpeed: vi.fn() });

it('opens the current speed, picks explicitly, and returns keyboard focus', () => {
  const callbacks = actions();
  render(<ReplayControls playback={playback} reason={null} pacing="Display delay 12 ms." {...callbacks} />);
  const opener = screen.getByRole('button', { name: 'Replay speed, 1×' });
  fireEvent.click(opener);
  expect(screen.getByRole('button', { name: '1×' })).toHaveFocus();
  fireEvent.click(screen.getByRole('button', { name: '2×' }));
  expect(callbacks.onSpeed).toHaveBeenCalledWith(2);
  expect(screen.queryByRole('dialog', { name: 'Replay speed' })).not.toBeInTheDocument();
  expect(opener).toHaveFocus();
});

it('Escape closes speed and pauses an active replay without moving focus elsewhere', () => {
  const callbacks = actions();
  render(<ReplayControls playback={{ ...playback, status: 'playing' }} reason={null} pacing="Display delay 12 ms." {...callbacks} />);
  const opener = screen.getByRole('button', { name: 'Replay speed, 1×' });
  fireEvent.click(opener);
  fireEvent.keyDown(screen.getByRole('dialog', { name: 'Replay speed' }), { key: 'Escape' });
  expect(callbacks.onPause).toHaveBeenCalledOnce();
  expect(opener).toHaveFocus();
  expect(screen.getByText('Display delay 12 ms.')).toBeInTheDocument();
});

it('keeps unavailable replay focusable with its visible accessible reason', () => {
  const callbacks = actions();
  render(<ReplayControls playback={playback} reason="Load later steps to continue." pacing="" {...callbacks} />);
  const button = screen.getByRole('button', { name: 'Replay' });
  expect(button).toHaveAttribute('aria-disabled', 'true');
  expect(button).toHaveAccessibleDescription('Load later steps to continue.');
  button.focus();
  expect(button).toHaveFocus();
  fireEvent.click(button);
  expect(callbacks.onToggle).toHaveBeenCalledOnce();
});
