import { createContext, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';
import type { Detail, Endpoint } from '../../types';
import { ViewerDialog } from '../shell/ViewerDialog';
import { PlanSheet } from './PlanSheet';
import type { Binding } from './client';
import './plan.css';

type TriggerState = { reason: string; open: (button: HTMLElement) => void };
const PlanLauncher = createContext<TriggerState | null>(null);

export function PlanHost({ children, detail, endpoint, connected, prepare }: {
  children: ReactNode; detail: Detail | null; endpoint: Endpoint | null; connected: boolean; prepare: () => void;
}) {
  const [opened, setOpened] = useState<{ opener: HTMLElement; binding: Binding } | null>(null);
  // Only the last hash is retained across close. Draft inputs and review values leave with the dialog.
  const [last, setLast] = useState<{ recording: string; hash: string } | null>(null);
  const [unconfirmedRecording, setUnconfirmedRecording] = useState<string | null>(null);
  const [writing, setWriting] = useState(false);
  const reason = !connected ? 'viewer offline' : !detail || !endpoint || detail.projectId !== endpoint.projectId ? 'no linked endpoint' : '';
  const visible = opened && !reason && opened.binding.recording === detail?.recordingId &&
    opened.binding.project === detail.projectId && opened.binding.operation === endpoint?.operationId;
  useEffect(() => { if (opened && !visible) setOpened(null); }, [opened, visible]);
  function open(opener: HTMLElement) {
    if (reason || writing || !detail || !endpoint) return;
    prepare();
    setOpened({ opener, binding: { project: detail.projectId, recording: detail.recordingId,
      operation: endpoint.operationId, method: endpoint.method, route: endpoint.routeTemplate } });
  }
  return <PlanLauncher.Provider value={{ reason: writing ? 'saving plan' : reason, open }}>
    {children}
    {visible && createPortal(<ViewerDialog title="Send again" opener={opened.opener} onClose={() => setOpened(null)}>
      <PlanSheet binding={opened.binding} lastHash={last?.recording === opened.binding.recording ? last.hash : ''}
        onWrite={setWriting} missingReceipt={unconfirmedRecording === opened.binding.recording}
        onMissingReceipt={() => setUnconfirmedRecording(opened.binding.recording)}
        remember={hash => setLast({ recording: opened.binding.recording, hash })} />
    </ViewerDialog>, document.body)}
  </PlanLauncher.Provider>;
}

export function PlanAction({ placement, returnFocus, closeTools }: {
  placement: 'bar' | 'more' | 'tools'; returnFocus?: HTMLElement | null; closeTools?: () => void;
}) {
  const launcher = useContext(PlanLauncher);
  if (!launcher) return null;
  return <button type="button" className={'button plan-trigger plan-trigger--' + placement}
    aria-disabled={Boolean(launcher.reason)} aria-haspopup="dialog" onClick={e => {
      if (launcher.reason) return;
      const opener = returnFocus ?? e.currentTarget;
      closeTools?.();
      launcher.open(opener);
    }}>{launcher.reason ? 'Send again · ' + launcher.reason : 'Send again…'}</button>;
}
