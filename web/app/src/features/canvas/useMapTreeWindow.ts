import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { revealWithin } from '../common/reveal-within';

const ESTIMATED_HEIGHT = 44;
const ROW_GAP = 2;
const OVERSCAN = 8;
export const MAP_TREE_ROW_LIMIT = 80;
const ROW_SELECTOR = ':scope > [role="treeitem"]';

function rowAt(offsets: readonly number[], top: number) {
  let low = 0;
  let high = offsets.length - 1;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (offsets[middle + 1] <= top) low = middle + 1;
    else high = middle;
  }
  return Math.min(low, offsets.length - 2);
}

export function useMapTreeWindow(rows: ReadonlyArray<{ key: string }>, rovingKey: string | null, selectedFrameId: string | null) {
  const tree = useRef<HTMLUListElement>(null);
  const heights = useRef(new Map<string, number>());
  const width = useRef(0);
  const anchor = useRef<{ key: string; offset: number } | undefined>(undefined);
  const [version, measure] = useState(0);
  const [viewport, setViewport] = useState({ top: 0, height: 320 });
  const [focusedKey, setFocusedKey] = useState<string>();
  const indexes = useMemo(() => new Map(rows.map(({ key }, index) => [key, index])), [rows]);
  const offsets = useMemo(() => {
    const result = [0];
    for (const { key } of rows) result.push(result.at(-1)! + (heights.current.get(key) ?? ESTIMATED_HEIGHT));
    return result;
  }, [rows, version]);

  const start = Math.max(0, rowAt(offsets, viewport.top) - OVERSCAN);
  const last = rowAt(offsets, viewport.top + viewport.height);
  const pinned = [rovingKey, focusedKey, anchor.current?.key];
  const end = Math.min(rows.length, last + OVERSCAN + 1, start + MAP_TREE_ROW_LIMIT - pinned.length);
  const indices = new Set<number>();
  for (let index = start; index < end; index++) indices.add(index);
  for (const key of pinned) {
    const index = key === null || key === undefined ? undefined : indexes.get(key);
    if (index !== undefined) indices.add(index);
  }
  const mounted = [...indices].sort((a, b) => a - b);
  const mountedKey = mounted.join(',');

  function itemFor(key: string) {
    return [...tree.current?.querySelectorAll<HTMLElement>(ROW_SELECTOR) ?? []]
      .find((item) => item.dataset.key === key);
  }

  function captureViewport() {
    const element = tree.current;
    if (!element || !element.clientHeight) return;
    const top = element.getBoundingClientRect().top + element.clientTop;
    const bottom = top + element.clientHeight;
    anchor.current = undefined;
    for (const item of element.querySelectorAll<HTMLElement>(ROW_SELECTOR)) {
      const box = item.getBoundingClientRect();
      if (item.dataset.key && box.bottom > top && box.top < bottom) {
        anchor.current = { key: item.dataset.key, offset: box.top - top };
        break;
      }
    }
    const scrollTop = element.scrollTop;
    const height = element.clientHeight;
    setViewport((current) => current.top === scrollTop && current.height === height
      ? current : { top: scrollTop, height });
  }

  useLayoutEffect(() => {
    const element = tree.current;
    if (!element) return;
    for (const key of heights.current.keys()) if (!indexes.has(key)) heights.current.delete(key);
    const kept = anchor.current;
    const item = kept && itemFor(kept.key);
    if (kept && item && element.clientHeight) {
      const top = element.getBoundingClientRect().top + element.clientTop;
      element.scrollTop += item.getBoundingClientRect().top - top - kept.offset;
    }
    captureViewport();
  }, [indexes, mountedKey, offsets]);

  useLayoutEffect(() => {
    const element = tree.current;
    if (!element || typeof ResizeObserver === 'undefined') return;
    const items = [...element.querySelectorAll<HTMLElement>(ROW_SELECTOR)];
    const observer = new ResizeObserver(() => {
      if (!element.clientWidth) return;
      let changed = false;
      if (width.current !== element.clientWidth) {
        width.current = element.clientWidth;
        heights.current.clear();
        changed = true;
      }
      for (const item of items) {
        const key = item.dataset.key;
        const height = item.getBoundingClientRect().height;
        if (key === undefined || height <= 0) continue;
        const measured = height + ROW_GAP;
        if (Math.abs((heights.current.get(key) ?? ESTIMATED_HEIGHT) - measured) > 0.25) {
          heights.current.set(key, measured);
          changed = true;
        }
      }
      if (changed) measure((value) => value + 1);
      else captureViewport();
    });
    observer.observe(element);
    for (const item of items) observer.observe(item);
    return () => observer.disconnect();
  }, [rows, mountedKey]);

  useLayoutEffect(() => {
    if (rovingKey === null) return;
    const item = itemFor(rovingKey);
    if (!item) return;
    if (selectedFrameId !== null) revealWithin(tree.current, item, 'both');
    // A selection only takes focus from a tree row, never its Expand button or another pane.
    const active = document.activeElement;
    if (active?.getAttribute('role') === 'treeitem' && tree.current?.contains(active) && active !== item) {
      item.focus({ preventScroll: true });
    }
    captureViewport();
  }, [selectedFrameId, rovingKey]);

  useLayoutEffect(() => {
    if (!focusedKey || indexes.has(focusedKey)) return;
    setFocusedKey(undefined);
    // A retained-window change can remove the focused row before React fires blur.
    if (rovingKey !== null && document.activeElement === document.body) {
      const replacement = itemFor(rovingKey);
      if (replacement) {
        revealWithin(tree.current, replacement, 'both');
        replacement.focus({ preventScroll: true });
        captureViewport();
      }
    }
  }, [focusedKey, indexes, rovingKey]);

  return { tree, mounted, offsets, captureViewport, setFocusedKey };
}
