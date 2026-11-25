import { useId, useLayoutEffect, useRef } from 'react';
import type { ReactNode } from 'react';

export function ViewerDialog({ title, opener, onClose, children }: {
  title: string;
  opener: HTMLElement;
  onClose: () => void;
  children: ReactNode;
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
      const reachable = [...event.currentTarget.querySelectorAll<HTMLElement>(
        'button:not(:disabled), select:not(:disabled), input:not(:disabled), a[href]',
      )].filter((control) => control.tabIndex >= 0 && control.getClientRects().length > 0);
      const first = reachable[0];
      const last = reachable.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    }}>
    <header className="viewer-dialog-header"><h2 id={titleId}>{title}</h2>
      <button type="button" className="button" ref={close} onClick={onClose}>Close</button>
    </header>
    <div className="viewer-dialog-body">{children}</div>
  </dialog>;
}
