import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NavigationControls } from '../features/evidence/NavigationControls';
import { navigationControls } from './navigation';

afterEach(cleanup);

const loaded = new Set(['f2', 'f3']);

describe('linear navigation controls', () => {
  it('navigation_buttons_disabled_on_boundary_with_text', () => {
    const controls = navigationControls({
      previous: { state: 'boundary' }, next: { state: 'target', frameId: 'f2' },
      into: { state: 'target', frameId: 'f3' }, over: { state: 'unavailable', reason: 'partial_frontier' }, out: { state: 'boundary' },
    }, loaded);
    const byAction = Object.fromEntries(controls.map((control) => [control.action, control]));
    expect(byAction.previous).toMatchObject({ enabled: false, reason: 'Boundary: this is the first frame.' });
    expect(byAction.next).toMatchObject({ enabled: true, reason: null, targetFrameId: 'f2' });
    expect(byAction.over.reason).toBe('Unavailable: the recording is partial and evidence ends here.');
    expect(byAction.out.reason).toBe('Boundary: this frame is at the top level.');
  });

  it('disables a target that is not in the loaded window and says so', () => {
    const [previous] = navigationControls({ previous: { state: 'target', frameId: 'far' } }, loaded);
    expect(previous).toMatchObject({ enabled: false, needsWindow: true, targetFrameId: 'far' });
    expect(previous.reason).toContain('outside the loaded window');
  });

  it('treats a missing server result as unavailable, never as a target', () => {
    const controls = navigationControls(undefined, loaded);
    expect(controls.every((control) => !control.enabled && control.reason)).toBe(true);
  });

  it('renders the reason as visible text and wires an enabled button', () => {
    const onNavigate = vi.fn();
    render(<NavigationControls navigation={{ previous: { state: 'boundary' }, next: { state: 'target', frameId: 'f2' }, into: { state: 'unavailable', reason: 'legacy_unindexed' }, over: { state: 'boundary' }, out: { state: 'boundary' } }} loadedFrameIds={loaded} onNavigate={onNavigate} />);
    expect(screen.getByRole('button', { name: 'Previous frame' })).toBeDisabled();
    expect(screen.getByText('Previous frame: Boundary: this is the first frame.')).toBeInTheDocument();
    expect(screen.getByText(/Step into: Unavailable: this recording was stored before frame indexing\./)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next frame' }));
    expect(onNavigate).toHaveBeenCalledWith('next', 'f2');
    expect(screen.getByRole('button', { name: 'Previous frame' })).toHaveAccessibleDescription(/first frame/);
  });
});
