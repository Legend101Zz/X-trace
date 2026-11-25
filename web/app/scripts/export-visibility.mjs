/** Browser-evaluated geometry: measuring never scrolls or changes focus. */
export function visibleControl(control) {
  const box = control.getBoundingClientRect();
  if (getComputedStyle(control).visibility !== 'visible' || getComputedStyle(control).opacity === '0'
    || box.width <= 0 || box.height <= 0 || box.left < 0 || box.top < 0
    || box.right > innerWidth + 1 || box.bottom > innerHeight + 1) return false;
  for (let parent = control.parentElement; parent; parent = parent.parentElement) {
    const style = getComputedStyle(parent);
    if (style.visibility !== 'visible' || style.opacity === '0') return false;
    const clipX = /^(auto|scroll|hidden|clip)$/.test(style.overflowX);
    const clipY = /^(auto|scroll|hidden|clip)$/.test(style.overflowY);
    if (!clipX && !clipY) continue;
    const bounds = parent.getBoundingClientRect();
    const left = bounds.left + parent.clientLeft;
    const top = bounds.top + parent.clientTop;
    if (clipX && (box.left < left - 1 || box.right > left + parent.clientWidth + 1)) return false;
    if (clipY && (box.top < top - 1 || box.bottom > top + parent.clientHeight + 1)) return false;
  }
  const insetX = Math.min(4, box.width / 4);
  const insetY = Math.min(4, box.height / 4);
  const points = [[box.left + box.width / 2, box.top + box.height / 2],
    [box.left + insetX, box.top + insetY], [box.right - insetX, box.top + insetY],
    [box.left + insetX, box.bottom - insetY], [box.right - insetX, box.bottom - insetY]];
  return points.every(([x, y]) => {
    const hit = document.elementFromPoint(x, y);
    return hit === control || hit !== null && control.contains(hit);
  });
}
