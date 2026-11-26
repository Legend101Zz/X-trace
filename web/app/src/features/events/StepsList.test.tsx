import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { ReplayEvent } from '../../types';
import { StepsList } from './StepsList';
import { filteredSteps, loadedTiming, STEP_FILTERS } from '../../replay/loaded-tools';

afterEach(cleanup);

it('keeps the mounted row bound and exact selected event when filters shrink a full retained window', () => {
  const events = Array.from({ length: 2_000 }, (_, index) => ({
    sequence: String((index + 1) * 2), frameId: index === 1_999 ? null : 'shared-frame',
    kind: `recording_event_kind:${index % 2 === 0 ? 'line_cursor' : 'frame_enter'}`,
    monotonicNs: String(index + 10), symbol: 'Synthetic.method', line: index + 1,
  })) as ReplayEvent[];
  const selected = events[1_999];
  const renderFiltered = (kinds: readonly string[]) => <section id="events-panel">
    <StepsList events={filteredSteps(events, { kinds }, selected)} selected={selected} timing={loadedTiming(events)}
      onMove={() => undefined} onPick={() => undefined} />
  </section>;
  const { rerender } = render(renderFiltered(STEP_FILTERS[2].kinds));
  const list = screen.getByRole('list', { name: 'Loaded replay steps' });
  const selection = () => list.querySelector<HTMLElement>('[data-step-sequence="4000"]');
  expect(list.querySelectorAll('.step-row').length).toBeLessThanOrEqual(80);
  expect(selection()).toHaveAttribute('aria-posinset', '1001');
  expect(selection()).toHaveAttribute('aria-setsize', '1001');
  expect(selection()?.querySelector('.event')).toHaveAttribute('aria-current', 'true');
  expect(selection()).toHaveTextContent('+1999 ns');
  rerender(renderFiltered(STEP_FILTERS[4].kinds));
  expect(list.querySelectorAll('.step-row')).toHaveLength(1);
  expect(selection()?.querySelector('.event')).toHaveAttribute('aria-current', 'true');
  expect(selection()).toHaveTextContent('Frame ID unavailable');
  expect(selection()).toHaveTextContent('+1999 ns');
});

it('bounds a retained window, pins exact selection and restores a virtualized Why disclosure', () => {
  const events = Array.from({ length: 160 }, (_, index) => ({
    sequence: String(2 + index * 2),
    kind: index === 159 ? 'recording_event_kind:gap' : 'recording_event_kind:frame_enter',
    frameId: index === 159 ? null : 'shared-frame',
    symbol: 'Synthetic.method',
    monotonicNs: '1',
    gap: index === 159 ? { count: '1', reason: 'line_budget' } : null,
  })) as unknown as ReplayEvent[];
  const onMove = vi.fn();
  const onPick = vi.fn();
  const renderList = (selected: ReplayEvent) => <section id="events-panel">
    <StepsList events={events} selected={selected} onMove={onMove} onPick={onPick} />
  </section>;
  const { rerender } = render(renderList(events[159]));
  const list = screen.getByRole('list', { name: 'Loaded replay steps' });
  const tail = () => list.querySelector<HTMLElement>('[data-step-sequence="320"]');
  expect(within(list).getAllByRole('listitem').length).toBeLessThanOrEqual(80);
  expect(tail()).toHaveAttribute('aria-posinset', '160');
  expect(tail()).toHaveAttribute('aria-setsize', '160');
  expect(tail()?.querySelector('.event')).toHaveAttribute('aria-current', 'true');
  expect(tail()).toHaveTextContent('Frame ID unavailable');
  const disclosure = tail()!.querySelector('details')!;
  disclosure.open = true;
  fireEvent(disclosure, new Event('toggle'));

  rerender(renderList(events[0]));
  expect(tail()).toBeNull();
  rerender(renderList(events[159]));
  expect(tail()?.querySelector('details')).toHaveAttribute('open');
  expect(tail()?.querySelector('.event')).toHaveAttribute('aria-current', 'true');
});

it('keeps a late remounted selection visible through layout, then respects manual scrolling', () => {
  const events = Array.from({ length: 160 }, (_, index) => ({
    sequence: String(index + 1), kind: 'recording_event_kind:frame_enter', frameId: 'shared-frame',
    monotonicNs: '1', symbol: 'Synthetic.method',
  })) as unknown as ReplayEvent[];
  const view = (showSteps: boolean, items = events) => <section id="events-panel">
    <button>View mode</button>
    {showSteps && <StepsList events={items} selected={events[159]} onMove={() => undefined} onPick={() => undefined} />}
  </section>;
  const height = vi.spyOn(Element.prototype, 'clientHeight', 'get').mockImplementation(function (this: Element) {
    return this.id === 'events-panel' ? 180 : 0;
  });
  const geometry = vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (this: Element) {
    if (this.id === 'events-panel') return new DOMRect(0, 0, 320, 180);
    const panel = this.closest('#events-panel');
    const position = Number(this.closest('[aria-posinset]')?.getAttribute('aria-posinset') ?? 1);
    return new DOMRect(0, (position - 1) * 60 - (panel?.scrollTop ?? 0), 320, 60);
  });
  try {
    const { container, rerender } = render(view(false));
    const mode = screen.getByRole('button', { name: 'View mode' });
    mode.focus();
    rerender(view(true));
    const pane = container.querySelector<HTMLElement>('#events-panel')!;
    const row = pane.querySelector<HTMLElement>('.event[aria-current="true"]')!;
    expect(row.closest('[aria-posinset]')).toHaveAttribute('aria-posinset', '160');
    expect(row.getBoundingClientRect().bottom).toBe(180);
    expect(mode).toHaveFocus();
    pane.scrollTop = 600;
    fireEvent.scroll(pane);
    rerender(view(true, events.slice()));
    expect(pane.scrollTop).toBe(600);
    expect(row).toHaveAttribute('aria-current', 'true');
    expect(mode).toHaveFocus();
  } finally {
    geometry.mockRestore();
    height.mockRestore();
  }
});

it('notifies the pane when the focused nonselected row is released, without changing selection', () => {
  const events = ['2', '4', '6'].map((sequence) => ({
    sequence, kind: 'recording_event_kind:frame_enter', frameId: 'shared-frame', monotonicNs: '1',
    symbol: `Synthetic ${sequence}`,
  })) as unknown as ReplayEvent[];
  const release = vi.fn();
  const renderList = (window: ReplayEvent[]) => <section id="events-panel">
    <StepsList events={window} selected={events[1]} onMove={() => undefined} onPick={() => undefined}
      onFocusedRowReleased={release} />
  </section>;
  const { rerender } = render(renderList(events));
  const discarded = screen.getByRole('button', { name: /Called Synthetic 2/ });
  act(() => discarded.focus());
  expect(discarded).toHaveFocus();
  rerender(renderList(events.slice(1)));
  expect(release).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button', { name: /Called Synthetic 4/ })).toHaveAttribute('aria-current', 'true');
});

it('holds the exact visible row offset when unknown variable-height rows are prepended', () => {
  const events = ['2', '4', '6', '8'].map((sequence) => ({
    sequence, kind: 'recording_event_kind:frame_enter', frameId: 'shared-frame', monotonicNs: '1',
    symbol: `Synthetic ${sequence}`,
  })) as unknown as ReplayEvent[];
  const actualHeights: Record<string, number> = { '2': 36, '4': 124, '6': 84, '8': 70 };
  const renderList = (window: ReplayEvent[]) => <section id="events-panel">
    <StepsList events={window} selected={events[2]} onMove={() => undefined} onPick={() => undefined} />
  </section>;
  const { container, rerender } = render(renderList(events.slice(2)));
  const pane = container.querySelector<HTMLElement>('#events-panel')!;
  const list = screen.getByRole('list', { name: 'Loaded replay steps' });
  Object.defineProperty(pane, 'clientHeight', { value: 55 });
  const box = (top: number, height: number) => new DOMRect(0, top, 320, height);
  let headerHeight = 0;
  const geometry = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
    if (this === pane) return box(10, 55);
    const top = 10 + headerHeight - pane.scrollTop;
    if (this === list) return box(top, 0);
    const sequence = this.dataset.stepSequence;
    if (sequence) {
      let offset = 0;
      for (let previous = this.previousElementSibling; previous; previous = previous.previousElementSibling) {
        offset += actualHeights[(previous as HTMLElement).dataset.stepSequence ?? ''] ?? 0;
      }
      return box(top + offset, actualHeights[sequence]);
    }
    return box(top, 0);
  });
  try {
    pane.scrollTop = 13;
    fireEvent.scroll(pane);
    const row = list.querySelector<HTMLElement>('[data-step-sequence="6"]')!;
    const anchor = row.getBoundingClientRect().top - pane.getBoundingClientRect().top;

    headerHeight = 23;
    rerender(renderList(events));
    expect(row.getBoundingClientRect().top - pane.getBoundingClientRect().top).toBe(anchor);
    expect(pane.scrollTop).toBe(13 + 36 + 124 + 23);
  } finally {
    geometry.mockRestore();
  }
});

it('browses past the mounted range with plain arrows when the selection is unavailable', () => {
  const events = Array.from({ length: 100 }, (_, index) => ({
    sequence: String(index + 1), kind: 'recording_event_kind:frame_enter',
    frameId: 'shared-frame', monotonicNs: '1', symbol: 'Synthetic.method',
  })) as unknown as ReplayEvent[];
  const onMove = vi.fn();
  render(<section id="events-panel">
    <StepsList events={events} selected={undefined} onMove={onMove} onPick={() => undefined} />
  </section>);
  const list = screen.getByRole('list', { name: 'Loaded replay steps' });
  const boundary = within(list).getAllByRole('listitem').at(-1)!;
  const position = Number(boundary.getAttribute('aria-posinset'));
  expect(position).toBeLessThan(events.length);
  const successor = () => list.querySelector<HTMLElement>(`[aria-posinset="${position + 1}"] .event`);
  expect(successor()).toBeNull();
  const browse = within(boundary).getByRole('button');
  act(() => browse.focus());
  fireEvent.keyDown(browse, { key: 'ArrowDown' });
  expect(successor()).toHaveFocus();
  expect(list.querySelector('.event[aria-current="true"]')).toBeNull();
  expect(onMove).not.toHaveBeenCalled();
});

it('starts each loaded-row browse group from the visible position after a manual scroll', () => {
  const events = Array.from({ length: 55 }, (_, index) => ({
    sequence: String(index + 1), kind: 'recording_event_kind:frame_enter',
    frameId: 'shared-frame', monotonicNs: '1', symbol: 'Synthetic.method',
  })) as unknown as ReplayEvent[];
  const { container } = render(<section id="events-panel">
    <StepsList events={events} selected={events[0]} onMove={() => undefined} onPick={() => undefined} />
  </section>);
  const pane = container.querySelector<HTMLElement>('#events-panel')!;
  const list = screen.getByRole('list', { name: 'Loaded replay steps' });
  Object.defineProperty(pane, 'clientHeight', { value: 180 });
  const geometry = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
    if (this === pane) return new DOMRect(0, 0, 320, 180);
    const position = Number(this.getAttribute('aria-posinset') ?? 1);
    return new DOMRect(0, (position - 1) * 60 - pane.scrollTop, 320, this === list ? 3_300 : 60);
  });
  const step = (sequence: string) => list.querySelector<HTMLElement>(`[data-step-sequence="${sequence}"] .event`);
  try {
    const later = screen.getByRole('button', { name: 'Later loaded rows' });
    fireEvent.click(later);
    expect(step('10')).toHaveFocus();
    pane.scrollTop = 30 * 60;
    fireEvent.scroll(pane);
    expect(screen.getByText('Loaded position 31 of 55')).toBeInTheDocument();
    fireEvent.click(later);
    expect(step('40')).toHaveFocus();
    expect(step('1')).toHaveAttribute('aria-current', 'true');
  } finally {
    geometry.mockRestore();
  }
});
