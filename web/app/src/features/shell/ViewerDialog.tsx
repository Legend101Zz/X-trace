import { useId, useLayoutEffect, useRef } from 'react';
import type { ReactNode } from 'react';

function available(control: HTMLElement, dialog: HTMLDialogElement): boolean {
  if (control.matches(':disabled') || control.closest('[inert]') || control.getClientRects().length === 0 ||
      getComputedStyle(control).visibility !== 'visible') return false;
  for (let parent = control.parentElement; parent && parent !== dialog; parent = parent.parentElement) {
    if (parent instanceof HTMLDetailsElement && !parent.open &&
        !parent.querySelector(':scope > summary')?.contains(control)) return false;
  }
  return true;
}

function tabStops(dialog: HTMLDialogElement): HTMLElement[] {
  return [...dialog.querySelectorAll<HTMLElement>(
    'button, select, input:not([type="hidden"]), textarea, a[href], summary, [tabindex]',
  )].filter((control) => {
    if (!available(control, dialog)) return false;
    // The first summary is a native tab stop even when its default tabIndex
    // property is negative. An explicit negative tabindex still opts it out.
    const nativeSummary = control.localName === 'summary' && !control.hasAttribute('tabindex') &&
      control.parentElement instanceof HTMLDetailsElement &&
      control.parentElement.querySelector(':scope > summary') === control;
    return control.localName === 'summary' && !control.hasAttribute('tabindex') ? nativeSummary : control.tabIndex >= 0;
  }).sort((left, right) => (left.tabIndex > 0 ? left.tabIndex : Infinity) -
    (right.tabIndex > 0 ? right.tabIndex : Infinity));
}

export function ViewerDialog({ title, opener, onClose, children, headerAccessory }: {
  title: string;
  opener: HTMLElement;
  onClose: () => void;
  children: ReactNode;
  headerAccessory?: ReactNode;
}) {
  const titleId = useId();
  const dialog = useRef<HTMLDialogElement>(null);
  const close = useRef<HTMLButtonElement>(null);

  useLayoutEffect(() => {
    const element = dialog.current;
    if (!element) return;
    element.showModal();
    close.current?.focus({ preventScroll: true });
    return () => {
      if (element.open) element.close();
      if (opener.isConnected) opener.focus({ preventScroll: true });
    };
  }, [opener]);

  return <dialog className="viewer-dialog" ref={dialog} aria-modal="true" aria-labelledby={titleId}
    onCancel={(event) => {
      event.preventDefault();
      onClose();
    }}
    onKeyDown={(event) => {
      // Window replay shortcuts must not move the recording behind the modal.
      event.stopPropagation();
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
      }
      if (event.key !== 'Tab') return;
      const element = event.currentTarget;
      const reachable = tabStops(element);
      const first = reachable[0];
      const last = reachable.at(-1);
      const active = document.activeElement;
      // A pending write can disable/remove the focused field. Recover within the
      // modal, while letting a visible programmatic heading keep native Tab order.
      const displaced = !(active instanceof HTMLElement) || !element.contains(active) || active === element ||
        !available(active, element);
      if (event.shiftKey && (active === first || displaced)) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && (active === last || displaced)) {
        event.preventDefault();
        first?.focus();
      }
    }}>
    <header className="viewer-dialog-header"><h2 id={titleId}>{title}</h2>
      {headerAccessory}
      <button type="button" className="button" ref={close} onClick={onClose}>Close</button>
    </header>
    <div className="viewer-dialog-body">{children}</div>
  </dialog>;
}
