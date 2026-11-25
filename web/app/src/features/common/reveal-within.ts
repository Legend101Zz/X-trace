/** Reveal a selection only inside its owner; ancestor/page scroll and focus stay untouched. */
export function revealWithin(scrollport: HTMLElement | null, selected: Element | null, axes: 'both' | 'vertical') {
  if (!scrollport || !selected || scrollport.clientHeight === 0 || (axes === 'both' && scrollport.clientWidth === 0)) return;
  const viewport = scrollport.getBoundingClientRect();
  const row = selected.getBoundingClientRect();
  const nearest = (start: number, end: number, origin: number, size: number) => {
    const limit = origin + size;
    if (start < origin && end > limit) return 0;
    if (start < origin) return Math.max(start - origin, end - limit);
    if (end > limit) return Math.min(start - origin, end - limit);
    return 0;
  };
  if (axes === 'both') {
    scrollport.scrollLeft += nearest(row.left, row.right, viewport.left + scrollport.clientLeft, scrollport.clientWidth);
  }
  scrollport.scrollTop += nearest(row.top, row.bottom, viewport.top + scrollport.clientTop, scrollport.clientHeight);
}
