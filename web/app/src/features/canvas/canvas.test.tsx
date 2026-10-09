import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReplayEvent } from '../../types';
import { CanvasView } from './CanvasView';

afterEach(cleanup);

const nav = { previous: { state: 'unavailable' }, next: { state: 'unavailable' }, into: { state: 'unavailable' }, over: { state: 'unavailable' }, out: { state: 'unavailable' } };
const ev = (n: number, parent: string | null, symbol: string) => ({ sequence: String(n), frameId: `f${n}`, navigation: nav, monotonicNs: String(n), kind: 'method', symbol, parentFrameId: parent, sourceBinding: 'unspecified', fieldTruncations: [] }) as unknown as ReplayEvent;
const events = [ev(1, null, 'Controller.create'), ev(2, 'f1', 'Repo.save'), ev(3, 'f1', 'Repo.save'), ev(4, 'f1', 'Audit.log')];

describe('canvas view', () => {
  it('canvas_selection_matches_linear_frame_id: the tree selects the node that holds the shared frame id', () => {
    render(<CanvasView events={events} selectedFrameId="f3" onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const selected = screen.getAllByRole('treeitem').filter((item) => item.getAttribute('aria-selected') === 'true');
    expect(selected).toHaveLength(1);
    // f2 and f3 collapse into one counted node whose id is the first member.
    expect(selected[0]).toHaveTextContent('Repo.save (2 repeated calls)');
  });

  it('uses a roving tabindex: exactly one tab stop', () => {
    render(<CanvasView events={events} selectedFrameId="f1" onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const stops = screen.getAllByRole('treeitem').filter((item) => item.tabIndex === 0);
    expect(stops).toHaveLength(1);
    expect(stops[0]).toHaveTextContent('Controller.create');
  });

  it('arrow keys move through nodes and map right/left to into/out', () => {
    const select = vi.fn();
    const navigate = vi.fn();
    render(<CanvasView events={events} selectedFrameId="f1" onSelectFrame={select} onNavigate={navigate} />);
    const tree = screen.getByRole('tree');
    fireEvent.keyDown(tree, { key: 'ArrowDown' });
    expect(select).toHaveBeenCalledWith('f2');
    fireEvent.keyDown(tree, { key: 'End' });
    expect(select).toHaveBeenLastCalledWith('f4');
    fireEvent.keyDown(tree, { key: 'ArrowRight' });
    fireEvent.keyDown(tree, { key: 'ArrowLeft' });
    expect(navigate.mock.calls).toEqual([['into'], ['out']]);
  });

  it('says when parent links were not observed instead of drawing a tree', () => {
    const flat = events.map((item) => ({ ...item, parentFrameId: null }) as unknown as ReplayEvent);
    render(<CanvasView events={flat} selectedFrameId={null} onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    expect(screen.getByText(/Parent links were not observed/)).toBeInTheDocument();
  });

  it('hides the decorative SVG from assistive technology', () => {
    const { container } = render(<CanvasView events={events} selectedFrameId={null} onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    expect(container.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
  });
});
