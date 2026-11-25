import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { ReplayEvent } from '../../types';
import { StepsList } from './StepsList';

afterEach(cleanup);

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
