import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ReplayEvent } from '../../types';

export const STEP_ROW_LIMIT = 80;
const ESTIMATED_ROW_HEIGHT = 60;
const OVERSCAN = 8;

function scrollOwner(list: HTMLElement) {
  const content = list.closest<HTMLElement>('.steps-content');
  if (content && getComputedStyle(content).overflowY === 'auto') return content;
  return list.closest<HTMLElement>('#events-panel');
}

function firstVisible(offsets: readonly number[], top: number) {
  let low = 0;
  let high = offsets.length - 1;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (offsets[middle + 1] <= top) low = middle + 1;
    else high = middle;
  }
  return Math.min(low, offsets.length - 2);
}

export function useStepWindow(events: readonly ReplayEvent[], selected: string | undefined) {
  const list = useRef<HTMLOListElement>(null);
  const heights = useRef(new Map<string, number>());
  const measuredWidth = useRef(0);
  const anchor = useRef<{ sequence: string; displacement: number } | null>(null);
  const [revision, measure] = useState(0);
  const [viewport, setViewport] = useState({ top: 0, height: 800 });
  const [focused, setFocused] = useState<string>();
  const indexes = useMemo(() => new Map(events.map((event, index) => [event.sequence, index])), [events]);
  const offsets = useMemo(() => {
    const result = [0];
    for (const event of events) result.push(result.at(-1)! + (heights.current.get(event.sequence) ?? ESTIMATED_ROW_HEIGHT));
    return result;
  }, [events, revision]);

  const first = firstVisible(offsets, Math.max(0, viewport.top));
  const last = firstVisible(offsets, Math.max(0, viewport.top + viewport.height));
  const start = events.length <= STEP_ROW_LIMIT ? 0 : Math.max(0, first - OVERSCAN);
  const end = events.length <= STEP_ROW_LIMIT ? events.length
    : Math.min(events.length, last + OVERSCAN + 1, start + STEP_ROW_LIMIT - 2);
  const indices = new Set(Array.from({ length: end - start }, (_, offset) => start + offset));
  for (const sequence of [selected ?? events[0]?.sequence, focused]) {
    const index = sequence === undefined ? undefined : indexes.get(sequence);
    if (index !== undefined) indices.add(index);
  }

  function captureViewport() {
    const element = list.current;
    const owner = element && scrollOwner(element);
    if (!element || !owner || !owner.clientHeight) return;
    const top = owner.getBoundingClientRect().top - element.getBoundingClientRect().top;
    const index = firstVisible(offsets, Math.max(0, top));
    anchor.current = top + owner.clientHeight <= 0 || !events[index] ? null : {
      sequence: events[index].sequence, displacement: top - offsets[index],
    };
    setViewport((current) => current.top === top && current.height === owner.clientHeight
      ? current : { top, height: owner.clientHeight });
  }

  useLayoutEffect(() => {
    const element = list.current;
    const owner = element && scrollOwner(element);
    if (!element || !owner) return;
    for (const sequence of heights.current.keys()) if (!indexes.has(sequence)) heights.current.delete(sequence);
    const kept = anchor.current;
    const index = kept ? indexes.get(kept.sequence) : undefined;
    if (kept && index !== undefined && owner.clientHeight) {
      const actual = owner.getBoundingClientRect().top - element.getBoundingClientRect().top;
      owner.scrollTop += offsets[index] + kept.displacement - actual;
    }
    captureViewport();
  }, [events, offsets]);

  const mounted = [...indices].sort((left, right) => left - right);
  const mountedKey = mounted.join(',');
  useLayoutEffect(() => {
    const element = list.current;
    const owner = element && scrollOwner(element);
    if (!element || !owner) return;
    const scrollports = new Set([
      owner,
      element.closest<HTMLElement>('.steps-content'),
      element.closest<HTMLElement>('#events-panel'),
    ]);
    scrollports.forEach((port) => port?.addEventListener('scroll', captureViewport, { passive: true }));
    window.addEventListener('resize', captureViewport);
    const mountedRows = [...element.querySelectorAll<HTMLElement>('[data-step-sequence]')];
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver((entries) => {
      const width = element.clientWidth;
      if (!width) return;
      const changedWidth = width !== measuredWidth.current;
      measuredWidth.current = width;
      if (changedWidth) heights.current.clear();
      let changed = changedWidth;
      const rows = changedWidth ? mountedRows : entries.map(({ target }) => target as HTMLElement);
      for (const row of rows) {
        const sequence = row.dataset.stepSequence;
        if (sequence === undefined) continue;
        const height = row.getBoundingClientRect().height;
        if (height > 0 && Math.abs((heights.current.get(sequence) ?? ESTIMATED_ROW_HEIGHT) - height) > 0.25) {
          heights.current.set(sequence, height);
          changed = true;
        }
      }
      if (changed) measure((prior) => prior + 1);
      else captureViewport();
    });
    scrollports.forEach((port) => { if (port) observer?.observe(port); });
    mountedRows.forEach((row) => observer?.observe(row));
    return () => {
      observer?.disconnect();
      scrollports.forEach((port) => port?.removeEventListener('scroll', captureViewport));
      window.removeEventListener('resize', captureViewport);
    };
  }, [events, offsets, mountedKey]);

  function revealIndex(index: number) {
    const target = Math.max(0, Math.min(events.length - 1, index));
    const element = list.current;
    const owner = element && scrollOwner(element);
    const sequence = events[target]?.sequence;
    if (!element || !owner || sequence === undefined) return;
    setFocused(sequence);
    const currentTop = owner.getBoundingClientRect().top - element.getBoundingClientRect().top;
    owner.scrollTop += offsets[target] - currentTop;
    captureViewport();
    return sequence;
  }

  return { list, mounted, offsets, first, setFocused, revealIndex, groupSize: OVERSCAN + 1 };
}
