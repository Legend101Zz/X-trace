import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReplayEvent } from '../../types';
import { CanvasView } from './CanvasView';
import { MAP_TREE_ROW_LIMIT } from './useMapTreeWindow';
import { StepsList } from '../events/StepsList';

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

const nav = { previous: { state: 'unavailable' }, next: { state: 'unavailable' }, into: { state: 'unavailable' }, over: { state: 'unavailable' }, out: { state: 'unavailable' } };
const ev = (n: number, parent: string | null, symbol: string) => ({ sequence: String(n), frameId: `f${n}`, navigation: nav, monotonicNs: String(n), kind: 'method', symbol, parentFrameId: parent, sourceBinding: 'unspecified', fieldTruncations: [] }) as unknown as ReplayEvent;
const events = [ev(1, null, 'Controller.create'), ev(2, 'f1', 'Repo.save'), ev(3, 'f1', 'Repo.save'), ev(4, 'f1', 'Audit.log')];

// jsdom has no layout. These distinct, offset scrollports exercise scroll ownership only;
// the actual 10,000-frame embedded-browser journey must establish real viewport visibility.
function mockScrollGeometry() {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (this: Element) {
    if (this.matches('.canvas-tree, .event-rail')) return new DOMRect(100, 300, 240, 120);
    if (this.matches('.canvas-scroll')) return new DOMRect(100, 100, 240, 100);
    if (this.matches('[role="treeitem"][aria-selected="true"], .event[aria-current="true"]')) return new DOMRect(100, 1100, 240, 26);
    if (this.matches('.canvas-node[data-selected="true"]')) return new DOMRect(900, 600, 168, 28);
    return new DOMRect();
  });
  vi.spyOn(Element.prototype, 'clientWidth', 'get').mockImplementation(function (this: Element) {
    return this.matches('.canvas-tree, .canvas-scroll, .event-rail') ? 240 : 0;
  });
  vi.spyOn(Element.prototype, 'clientHeight', 'get').mockImplementation(function (this: Element) {
    if (this.matches('.canvas-tree, .event-rail')) return 120;
    return this.matches('.canvas-scroll') ? 100 : 0;
  });
}

// JSDOM does not lay out rows. This model gives spacers and wrapped cards
// independent heights and moves every rectangle with its own scrollport.
function mockWrappedMapLayout() {
  let width = 280;
  const callbacks = new Set<ResizeObserverCallback>();
  vi.stubGlobal('ResizeObserver', class {
    constructor(private callback: ResizeObserverCallback) { callbacks.add(callback); }
    observe() {}
    disconnect() { callbacks.delete(this.callback); }
  });
  const height = (item: Element) => item.classList.contains('canvas-tree-spacer')
    ? Number.parseFloat((item as HTMLElement).style.height)
    : (item.textContent?.includes('Wrap') ? (width < 200 ? 86 : 60) : 28) + 2;
  vi.spyOn(Element.prototype, 'clientWidth', 'get').mockImplementation(function (this: Element) {
    return this.matches('.canvas-tree') ? width : 0;
  });
  vi.spyOn(Element.prototype, 'clientHeight', 'get').mockImplementation(function (this: Element) {
    return this.matches('.canvas-tree') ? 124 : 0;
  });
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (this: Element) {
    if (this.matches('.canvas-tree')) return new DOMRect(100, 300, width, 124);
    const tree = this.parentElement;
    if (!tree?.matches('.canvas-tree')) return new DOMRect();
    let top = 300 - tree.scrollTop;
    for (const item of tree.children) {
      if (item === this) break;
      top += height(item);
    }
    return new DOMRect(100, top, width, height(this) - 2);
  });
  return (nextWidth: number) => {
    width = nextWidth;
    act(() => {
      for (const callback of [...callbacks]) callback([], {} as ResizeObserver);
    });
  };
}

function firstVisibleMapRow(tree: HTMLElement) {
  const viewport = tree.getBoundingClientRect();
  const row = [...tree.querySelectorAll<HTMLElement>('[role="treeitem"]')].find((item) => {
    const box = item.getBoundingClientRect();
    return box.bottom > viewport.top && box.top < viewport.bottom;
  });
  if (!row) throw new Error('no mounted tree row intersects the viewport');
  return { key: row.dataset.key, offset: row.getBoundingClientRect().top - viewport.top };
}

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

  it('emits the ARIA tree depth-first: parents precede children and levels never jump', () => {
    const deep = [ev(1, null, 'A'), ev(2, 'f1', 'B'), ev(3, 'f1', 'C'), ev(4, 'f2', 'D'), ev(5, 'f3', 'E')];
    render(<CanvasView events={deep} selectedFrameId={null} onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const items = screen.getAllByRole('treeitem');
    expect(items.map((item) => item.textContent?.[0])).toEqual(['A', 'B', 'D', 'C', 'E']);
    const levels = items.map((item) => Number(item.getAttribute('aria-level')));
    expect(levels).toEqual([1, 2, 3, 2, 3]);
    levels.forEach((level, index) => { if (index > 0) expect(level - levels[index - 1]).toBeLessThanOrEqual(1); });
    expect(items[3]).toHaveAttribute('aria-posinset', '2');
    expect(items[3]).toHaveAttribute('aria-setsize', '2');
  });

  it('lets collapsed repeated calls be expanded and each member selected', () => {
    const select = vi.fn();
    render(<CanvasView events={events} selectedFrameId="f3" onSelectFrame={select} onNavigate={() => undefined} />);
    fireEvent.click(screen.getByRole('button', { name: /Expand 2 repeated calls of Repo\.save/ }));
    const members = screen.getAllByRole('treeitem').filter((item) => /call \d of 2/.test(item.textContent ?? ''));
    expect(members).toHaveLength(2);
    fireEvent.click(members[1]);
    expect(select).toHaveBeenLastCalledWith('f3');
    expect(members[1]).toHaveAttribute('aria-selected', 'true');
  });

  it('keeps focus on the Expand button after toggling and keeps it out of the tab order', () => {
    render(<CanvasView events={events} selectedFrameId="f1" onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const button = screen.getByRole('button', { name: /Expand 2 repeated calls of Repo\.save/ });
    expect(button.tabIndex).toBe(-1);
    button.focus();
    fireEvent.click(button);
    expect(document.activeElement).toBe(button);
  });

  it('keeps Expand button focus when expanding the selected repeated-call group changes its row key', () => {
    render(<CanvasView events={events} selectedFrameId="f3" onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const button = screen.getByRole('button', { name: /Expand 2 repeated calls of Repo\.save/ });
    button.focus();
    fireEvent.click(button);
    expect(button).toHaveFocus();
    const selected = screen.getAllByRole('treeitem').filter((item) => item.getAttribute('aria-selected') === 'true');
    expect(selected).toHaveLength(1);
    expect(selected[0]).toHaveAttribute('data-key', 'f2/f3');
  });

  it.each(['mount', 'selection change'])('reveals the tree and drawing independently on %s without moving toolbar focus or the page', (phase) => {
    mockScrollGeometry();
    render(<button>Map</button>);
    const modeButton = screen.getByRole('button', { name: 'Map' });
    modeButton.focus();
    const props = { events, onSelectFrame: () => undefined, onNavigate: () => undefined };
    const view = render(<CanvasView {...props} selectedFrameId={phase === 'mount' ? 'f4' : null} />);
    if (phase === 'selection change') view.rerender(<CanvasView {...props} selectedFrameId="f4" />);
    const tree = screen.getByRole('tree');
    const drawing = screen.getByRole('region', { name: 'Frame graph drawing' });
    expect(tree.scrollTop).toBe(706);
    expect(drawing.scrollTop).toBe(428);
    expect(drawing.scrollLeft).toBe(728);
    expect(document.documentElement.scrollTop).toBe(0);
    expect(document.body.scrollTop).toBe(0);
    expect(modeButton).toHaveFocus();

    // Unrelated rerenders must preserve a user's independent pointer browsing position.
    tree.scrollTop = 120;
    drawing.scrollLeft = 30;
    view.rerender(<CanvasView {...props} selectedFrameId="f4" />);
    expect(tree.scrollTop).toBe(120);
    expect(drawing.scrollLeft).toBe(30);
  });

  it('moves roving tree-row focus with selection without asking focus to scroll ancestors', () => {
    const props = { events, onSelectFrame: () => undefined, onNavigate: () => undefined };
    const view = render(<CanvasView {...props} selectedFrameId="f1" />);
    const items = screen.getAllByRole('treeitem');
    items[0].focus();
    const focus = vi.spyOn(items[2], 'focus');
    view.rerender(<CanvasView {...props} selectedFrameId="f4" />);
    expect(items[2]).toHaveFocus();
    expect(focus).toHaveBeenCalledWith({ preventScroll: true });
  });

  it('bounds mounted rows while retaining selection beyond the unchanged drawing cap', () => {
    const large = Array.from({ length: 2_000 }, (_, index) => ev(index + 1, null, `Call${index + 1}`));
    const { container } = render(<CanvasView events={large} selectedFrameId="f2000" onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const items = screen.getAllByRole('treeitem');
    expect(items.length).toBeLessThanOrEqual(MAP_TREE_ROW_LIMIT);
    const selected = screen.getByRole('treeitem', { selected: true });
    expect(selected).toHaveAttribute('data-key', 'f2000');
    expect(selected).toHaveAttribute('aria-level', '1');
    expect(selected).toHaveAttribute('aria-posinset', '2000');
    expect(selected).toHaveAttribute('aria-setsize', '2000');
    expect(items.filter((item) => item.tabIndex === 0)).toEqual([selected]);
    expect(container.querySelectorAll('.canvas-node')).toHaveLength(400);
    expect(container.querySelector('.canvas-node[data-selected="true"]')).toBeNull();
  });

  it('keeps a focused row mounted during manual scroll and transfers focus to an offscreen keyboard target', () => {
    const large = Array.from({ length: 2_000 }, (_, index) => ev(index + 1, null, `Call${index + 1}`));
    function Controlled() {
      const [frame, setFrame] = useState('f1');
      return <CanvasView events={large} selectedFrameId={frame} onSelectFrame={setFrame} onNavigate={() => undefined} />;
    }
    mockScrollGeometry();
    render(<Controlled />);
    const tree = screen.getByRole('tree');
    const first = screen.getByRole('treeitem', { selected: true });
    fireEvent.click(first);
    first.focus();
    tree.scrollTop = 44 * 1_000;
    fireEvent.scroll(tree);
    expect(first).toHaveFocus();
    expect(screen.getByRole('treeitem', { name: 'Call1001' })).toBeInTheDocument();
    expect(screen.getAllByRole('treeitem').length).toBeLessThanOrEqual(MAP_TREE_ROW_LIMIT);
    expect(screen.queryByRole('treeitem', { name: 'Call2000' })).not.toBeInTheDocument();

    fireEvent.keyDown(first, { key: 'End' });
    const last = screen.getByRole('treeitem', { selected: true });
    expect(last).toHaveAttribute('data-key', 'f2000');
    expect(last).toHaveFocus();
    fireEvent.keyDown(last, { key: 'ArrowUp' });
    expect(screen.getByRole('treeitem', { selected: true })).toHaveAttribute('data-key', 'f1999');
    expect(screen.getByRole('treeitem', { selected: true })).toHaveFocus();
    fireEvent.keyDown(screen.getByRole('treeitem', { selected: true }), { key: 'Home' });
    expect(screen.getByRole('treeitem', { selected: true })).toHaveAttribute('data-key', 'f1');
    expect(screen.getByRole('treeitem', { selected: true })).toHaveFocus();
    expect(document.documentElement.scrollTop).toBe(0);
  });

  it('holds the visible wrapped row and focused item through a ResizeObserver width change', () => {
    const resize = mockWrappedMapLayout();
    const many = Array.from({ length: 2_000 }, (_, index) => ev(index + 1, null, `Wrap frame ${index + 1}`));
    render(<CanvasView events={many} selectedFrameId="f1" onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const tree = screen.getByRole('tree');
    const selected = screen.getByRole('treeitem', { selected: true });
    selected.focus();
    tree.scrollTop = 44 * 1_000 + 12;
    fireEvent.scroll(tree);
    resize(280);
    const anchor = firstVisibleMapRow(tree);
    expect(anchor.key).not.toBe('f1');
    const priorHeight = screen.getByRole('treeitem', { name: `Wrap frame ${anchor.key?.slice(1)}` }).getBoundingClientRect().height;

    resize(160);
    expect(firstVisibleMapRow(tree)).toEqual(anchor);
    expect(screen.getByRole('treeitem', { name: `Wrap frame ${anchor.key?.slice(1)}` }).getBoundingClientRect().height).toBeGreaterThan(priorHeight);
    expect(selected).toHaveFocus();
    expect(screen.getAllByRole('treeitem').length).toBeLessThanOrEqual(MAP_TREE_ROW_LIMIT);
  });

  it('keeps the scrolled Expand button focused through expansion and collapse', () => {
    const resize = mockWrappedMapLayout();
    const many = Array.from({ length: 2_000 }, (_, index) =>
      ev(index + 1, null, index === 1_000 || index === 1_001 ? 'Wrap repeated' : `Call ${index + 1}`));
    render(<CanvasView events={many} selectedFrameId="f1002" onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const tree = screen.getByRole('tree');
    resize(280);
    const button = screen.getByRole('button', { name: /Expand 2 repeated calls of Wrap repeated/ });
    button.focus();
    expect(tree.scrollTop).toBeGreaterThan(0);
    fireEvent.click(button);
    expect(button).toHaveFocus();
    expect(screen.getByRole('treeitem', { selected: true })).toHaveAttribute('data-key', 'f1001/f1002');
    expect(button.closest('[role="treeitem"]')).toHaveAttribute('aria-expanded', 'true');
    fireEvent.click(button);
    expect(button).toHaveFocus();
    expect(screen.getByRole('treeitem', { selected: true })).toHaveAttribute('data-key', 'f1001');
    expect(button.closest('[role="treeitem"]')).toHaveAttribute('aria-expanded', 'false');
    expect(screen.getAllByRole('treeitem').length).toBeLessThanOrEqual(MAP_TREE_ROW_LIMIT);
  });

  it('navigates both rows when a repeated group and its first member share a frame id', () => {
    function Controlled() {
      const [frame, setFrame] = useState('f2');
      return <CanvasView events={events} selectedFrameId={frame} onSelectFrame={setFrame} onNavigate={() => undefined} />;
    }
    render(<Controlled />);
    fireEvent.click(screen.getByRole('button', { name: /Expand 2 repeated calls of Repo/ }));
    const group = screen.getByRole('treeitem', { selected: true });
    expect(group).toHaveAttribute('data-key', 'f2');
    group.focus();
    fireEvent.keyDown(group, { key: 'ArrowDown' });
    const first = screen.getByRole('treeitem', { selected: true });
    expect(first).toHaveAttribute('data-key', 'f2/f2');
    expect(first).toHaveFocus();
    fireEvent.keyDown(first, { key: 'ArrowDown' });
    expect(screen.getByRole('treeitem', { selected: true })).toHaveAttribute('data-key', 'f2/f3');
  });

  it('keeps every evidence note in a named keyboard-reachable region when several limitations apply', () => {
    const large = Array.from({ length: 450 }, (_, index) => ev(index + 1, null, `Call${index + 1}`));
    const noisy = [...large, large[0], { ...ev(451, null, 'Unavailable'), frameId: null }];
    render(<CanvasView events={noisy} selectedFrameId="f450" onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const notes = screen.getByRole('region', { name: 'Frame graph evidence' });
    expect(notes.tabIndex).toBe(0);
    expect(notes.querySelectorAll('.evidence-state')).toHaveLength(4);
    expect(notes).toHaveTextContent('Parent links were not observed');
    expect(notes).toHaveTextContent('1 events have no frame id');
    expect(notes).toHaveTextContent('1 events are not drawn or listed');
    expect(notes).toHaveTextContent('Drawing the shallowest 400 of 450 nodes');
    notes.focus();
    expect(notes).toHaveFocus();
  });

  it('reveals a remounted Steps selection inside its rail while the mode button keeps focus', () => {
    mockScrollGeometry();
    render(<button>Steps</button>);
    const modeButton = screen.getByRole('button', { name: 'Steps' });
    modeButton.focus();
    const { container, rerender } = render(<StepsList events={events} selected={events[3]} onPick={() => undefined} onMove={() => undefined} />);
    const rail = container.querySelector('.event-rail') as HTMLElement;
    expect(rail.scrollTop).toBe(706);
    expect(container.querySelector('.event[aria-current="true"] .event-seq')).toHaveTextContent('4');
    expect(document.documentElement.scrollTop).toBe(0);
    expect(document.body.scrollTop).toBe(0);
    expect(modeButton).toHaveFocus();
    rail.scrollLeft = 19;
    rerender(<StepsList events={events} selected={events[0]} onPick={() => undefined} onMove={() => undefined} />);
    expect(rail.scrollLeft).toBe(19);
    expect(modeButton).toHaveFocus();
  });

  it('marks gap frames visibly and in the tree text', () => {
    const gap = [ev(1, null, 'Root'), { ...ev(2, 'f1', 'missing'), kind: 'gap' } as unknown as ReplayEvent];
    render(<CanvasView events={gap} selectedFrameId={null} onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const item = screen.getAllByRole('treeitem')[1];
    expect(item).toHaveAttribute('data-kind', 'gap');
    expect(item).toHaveTextContent('evidence gap');
  });

  it('names the scrollable drawing region and keeps it keyboard focusable', () => {
    render(<CanvasView events={events} selectedFrameId={null} onSelectFrame={() => undefined} onNavigate={() => undefined} />);
    const region = screen.getByRole('region', { name: 'Frame graph drawing' });
    expect(region.tabIndex).toBe(0);
  });
});
