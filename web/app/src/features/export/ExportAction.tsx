import { createContext, useContext, useState } from 'react';
import { createPortal } from 'react-dom';
import type { Endpoint } from '../../types';
import { ViewerDialog } from '../shell/ViewerDialog';
import { ExportProgress, ExportSheet } from './ExportSheet';
import type { ExportPhase } from './ExportSheet';

export const BeforeExportOpen = createContext<() => void>(() => undefined);

/** Keep the endpoint that opened this sheet even if the Requests tree updates during preview. */
export function ExportAction({ endpoint, label }: { endpoint: Endpoint | null; label: string }) {
  const beforeOpen = useContext(BeforeExportOpen);
  const [opened, setOpened] = useState<{ button: HTMLButtonElement; endpoint: Endpoint | null } | null>(null);
  const [phase, setPhase] = useState<ExportPhase>('Choose');
  const close = () => setOpened(null);
  return <>
    <button type="button" className="button export-trigger" aria-haspopup="dialog"
      onClick={(event) => {
        beforeOpen();
        setPhase('Choose');
        setOpened({ button: event.currentTarget, endpoint });
      }}>{label}</button>
    {opened && createPortal(<ViewerDialog title="Export" opener={opened.button} onClose={close}
      headerAccessory={<ExportProgress phase={phase} />}>
      <ExportSheet endpoint={opened.endpoint} onClose={close} onPhaseChange={setPhase} />
    </ViewerDialog>, document.body)}
  </>;
}
