import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ViewerDialog } from './ViewerDialog';

const prototype = HTMLDialogElement.prototype;
const missingModal = typeof prototype.showModal !== 'function';
const missingClose = typeof prototype.close !== 'function';

beforeEach(() => {
  // jsdom supplies neither native modal behavior nor layout. These fixtures
  // exercise the boundary selection only; Chromium must verify real traversal.
  if (missingModal) Object.defineProperty(prototype, 'showModal', {
    configurable: true, value(this: HTMLDialogElement) { this.open = true; },
  });
  if (missingClose) Object.defineProperty(prototype, 'close', {
    configurable: true, value(this: HTMLDialogElement) { this.open = false; },
  });
  vi.spyOn(HTMLElement.prototype, 'getClientRects').mockReturnValue({ length: 1 } as DOMRectList);
});

afterEach(() => {
  cleanup();
  document.querySelectorAll('[data-dialog-opener]').forEach(element => element.remove());
  vi.restoreAllMocks();
  if (missingModal) Reflect.deleteProperty(prototype, 'showModal');
  if (missingClose) Reflect.deleteProperty(prototype, 'close');
});

function sheet(children: ReactNode, headerAccessory?: ReactNode) {
  const opener = document.createElement('button');
  opener.dataset.dialogOpener = 'true';
  opener.textContent = 'Tools';
  document.body.append(opener);
  const onClose = vi.fn();
  const view = render(<ViewerDialog title="Send again" opener={opener} onClose={onClose} headerAccessory={headerAccessory}>
    {children}
  </ViewerDialog>);
  const dialog = screen.getByRole('dialog', { name: 'Send again' });
  const close = within(dialog).getByRole('button', { name: 'Close' });
  return { ...view, dialog, close, opener, onClose };
}

it('wraps from Close to the native summary of a collapsed last disclosure', () => {
  const { dialog, close } = sheet(<>
    <input aria-label="Catalog revision ID" />
    <details><summary>Open an existing plan</summary>
      <input aria-label="Saved plan hash" /><button>Show saved plan</button>
    </details>
  </>);
  const summary = dialog.querySelector('summary')!;
  // A native summary remains sequential even in DOMs whose property reports -1.
  Object.defineProperty(summary, 'tabIndex', { configurable: true, get: () => -1 });
  expect(close).toHaveFocus();
  fireEvent.keyDown(close, { key: 'Tab', shiftKey: true });
  expect(summary).toHaveFocus();
  fireEvent.keyDown(summary, { key: 'Tab' });
  expect(close).toHaveFocus();
});

it('keeps every control in an expanded disclosure reachable and honors explicit opt-out', () => {
  const { dialog, close } = sheet(<details open><summary tabIndex={-1}>Open an existing plan</summary>
    <input aria-label="Saved plan hash" /><button>Show saved plan</button>
  </details>);
  const saved = within(dialog).getByRole('button', { name: 'Show saved plan' });
  fireEvent.keyDown(close, { key: 'Tab', shiftKey: true });
  expect(saved).toHaveFocus();
  fireEvent.keyDown(saved, { key: 'Tab' });
  expect(close).toHaveFocus();
});

it('excludes nested collapsed descendants and inert controls from the wrapping boundary', () => {
  const { dialog, close } = sheet(<>
    <details><summary>Outer disclosure</summary>
      <details open><summary>Hidden nested disclosure</summary><button>Hidden nested action</button></details>
    </details>
    <div inert><button>Inert action</button></div>
  </>);
  fireEvent.keyDown(close, { key: 'Tab', shiftKey: true });
  expect(dialog.querySelector('summary')).toHaveFocus();
});

it('excludes secondary and standalone summaries unless explicitly made sequential', () => {
  const { dialog, close } = sheet(<>
    <details open><summary>Native disclosure</summary><summary>Secondary summary</summary></details>
    <summary>Standalone summary</summary>
  </>);
  const summaries = [...dialog.querySelectorAll('summary')];
  for (const summary of summaries) Object.defineProperty(summary, 'tabIndex', { configurable: true, get: () => 0 });
  fireEvent.keyDown(close, { key: 'Tab', shiftKey: true });
  expect(summaries[0]).toHaveFocus();
  summaries[1].setAttribute('tabindex', '0');
  close.focus();
  fireEvent.keyDown(close, { key: 'Tab', shiftKey: true });
  expect(summaries[1]).toHaveFocus();
});

it('skips disabled fieldset controls while retaining its enabled legend control', () => {
  const { dialog, close } = sheet(<fieldset disabled>
    <legend><button>Available help</button></legend>
    <input aria-label="Busy input" /><button>Busy write</button>
  </fieldset>);
  fireEvent.keyDown(close, { key: 'Tab', shiftKey: true });
  expect(within(dialog).getByRole('button', { name: 'Available help' })).toHaveFocus();
});

it('recovers focus after a busy change disables the focused write control', () => {
  const { dialog, close } = sheet(<><button>Save replacement plan</button><button>Refresh saved plan</button></>);
  const save = within(dialog).getByRole('button', { name: 'Save replacement plan' }) as HTMLButtonElement;
  const refresh = within(dialog).getByRole('button', { name: 'Refresh saved plan' });
  save.focus();
  save.disabled = true;
  fireEvent.keyDown(dialog, { key: 'Tab' });
  expect(close).toHaveFocus();
  save.disabled = false;
  save.focus();
  save.disabled = true;
  fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
  expect(refresh).toHaveFocus();
});

it('recovers after the focused control is removed without changing heading Tab behavior', () => {
  const { dialog, close } = sheet(<><h3 tabIndex={-1}>Review</h3><button>Temporary action</button></>);
  const temporary = within(dialog).getByRole('button', { name: 'Temporary action' });
  temporary.focus();
  temporary.remove();
  fireEvent.keyDown(dialog, { key: 'Tab' });
  expect(close).toHaveFocus();
  const heading = within(dialog).getByRole('heading', { name: 'Review' });
  heading.focus();
  expect(fireEvent.keyDown(heading, { key: 'Tab' })).toBe(true);
  expect(heading).toHaveFocus();
});

it('preserves positive tabindex order ahead of native DOM order', () => {
  const { dialog, close } = sheet(<><button tabIndex={2}>Second</button><button tabIndex={1}>First</button></>);
  const first = within(dialog).getByRole('button', { name: 'First' });
  const second = within(dialog).getByRole('button', { name: 'Second' });
  // Close has tabindex 0 and follows both explicit positive positions.
  fireEvent.keyDown(close, { key: 'Tab' });
  expect(first).toHaveFocus();
  fireEvent.keyDown(first, { key: 'Tab', shiftKey: true });
  expect(close).toHaveFocus();
  second.focus();
  expect(fireEvent.keyDown(second, { key: 'Tab' })).toBe(true);
});

it('preserves initial Close focus, native cancellation, Escape and the connected opener', () => {
  const { dialog, close, opener, onClose, unmount } = sheet(<input aria-label="Catalog revision ID" />);
  expect((dialog as HTMLDialogElement).open).toBe(true);
  expect(close).toHaveFocus();
  expect(fireEvent(dialog, new Event('cancel', { cancelable: true }))).toBe(false);
  expect(onClose).toHaveBeenCalledTimes(1);
  fireEvent.keyDown(close, { key: 'Escape' });
  expect(onClose).toHaveBeenCalledTimes(2);
  opener.setAttribute('aria-disabled', 'true');
  unmount();
  expect(opener).toHaveFocus();
  expect((dialog as HTMLDialogElement).open).toBe(false);
});
