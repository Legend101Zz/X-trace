import { useState } from 'react';
import { createPortal } from 'react-dom';
import type { Endpoint } from '../../types';
import { ViewerDialog } from '../shell/ViewerDialog';
import { ExportSheet } from './ExportSheet';

/** Keep the endpoint that opened this sheet even if the Requests tree updates during preview. */
export function ExportAction({ endpoint, label }: { endpoint: Endpoint | null; label: string }) {
  const [opened, setOpened] = useState<{ button: HTMLButtonElement; endpoint: Endpoint | null } | null>(null);
  const close = () => setOpened(null);
  return <>
    <button type="button" className="button export-trigger" aria-haspopup="dialog"
      onClick={(event) => setOpened({ button: event.currentTarget, endpoint })}>{label}</button>
    {opened && createPortal(<ViewerDialog title="Export" opener={opened.button} onClose={close}>
      <ExportSheet endpoint={opened.endpoint} onClose={close} />
    </ViewerDialog>, document.body)}
  </>;
}
