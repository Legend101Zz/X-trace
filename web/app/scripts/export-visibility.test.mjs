import { afterEach, expect, it, vi } from 'vitest';
import { visibleControl } from './export-visibility.mjs';

function fixture() {
  document.body.innerHTML = '<div id="scroller"><button><span>Save file</span></button></div><aside></aside>';
  const parent = document.querySelector('#scroller');
  const button = parent.querySelector('button');
  Object.defineProperties(parent, { clientWidth: { value: 320 }, clientHeight: { value: 450 } });
  parent.getBoundingClientRect = () => new DOMRect(0, 0, 320, 450);
  button.getBoundingClientRect = () => new DOMRect(20, 400, 280, 44);
  vi.stubGlobal('innerWidth', 320);
  vi.stubGlobal('innerHeight', 450);
  Object.defineProperty(document, 'elementFromPoint', { configurable: true, value: vi.fn(() => button.querySelector('span')) });
  return { parent, button };
}
afterEach(() => { document.body.innerHTML = ''; vi.unstubAllGlobals(); });

it('accepts visible source coordinates and descendant hit targets without scrolling', () => {
  const { parent, button } = fixture();
  parent.scrollTop = 12;
  expect(visibleControl(button)).toBe(true);
  expect(parent.scrollTop).toBe(12);
  expect(document.activeElement).toBe(document.body);
});

it('rejects a button inside the viewport but clipped by a scrolling ancestor', () => {
  const { parent, button } = fixture();
  parent.style.overflowY = 'auto';
  parent.getBoundingClientRect = () => new DOMRect(0, -50, 320, 450);
  expect(visibleControl(button)).toBe(false);
});

it('rejects a center or corner covered by another element', () => {
  const { button } = fixture();
  const overlay = document.querySelector('aside');
  document.elementFromPoint.mockImplementationOnce(() => overlay);
  expect(visibleControl(button)).toBe(false);
  document.elementFromPoint.mockImplementation((x) => x < 30 ? overlay : button);
  expect(visibleControl(button)).toBe(false);
});

it('rejects a primary action below the short viewport until native scrolling reveals it', () => {
  const { button } = fixture();
  vi.stubGlobal('innerHeight', 260);
  expect(visibleControl(button)).toBe(false);
  button.getBoundingClientRect = () => new DOMRect(20, 210, 280, 44);
  expect(visibleControl(button)).toBe(true);
});
