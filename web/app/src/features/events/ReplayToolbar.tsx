import { useId, useState } from 'react';
import type { ReactNode } from 'react';
import type { NavAction, NavControl } from '../../replay/navigation';

const FRAME_STEPS = [
  { action: 'into', label: 'Step in' },
  { action: 'over', label: 'Step over' },
  { action: 'out', label: 'Step out' },
] as const;

export function ReplayToolbar({ backReason, nextReason, frameControls, onMove, onNavigate, tools }: {
  backReason: string | null;
  nextReason: string | null;
  frameControls: readonly NavControl[];
  onMove: (direction: -1 | 1) => void;
  onNavigate: (action: NavAction) => void;
  tools?: ReactNode;
}) {
  const id = useId();
  const [focusedAction, setFocusedAction] = useState<string | null>(null);
  const [pointedAction, setPointedAction] = useState<string | null>(null);
  const controls = [
    { action: 'back', label: 'Back', reason: backReason, run: () => onMove(-1) },
    { action: 'next', label: 'Next', reason: nextReason, run: () => onMove(1) },
    ...FRAME_STEPS.map(({ action, label }) => ({
      action, label, reason: frameControls.find((control) => control.action === action)?.reason ?? null,
      run: () => onNavigate(action),
    })),
  ];
  const visibleReason = focusedAction ?? pointedAction ?? controls.find((control) => control.reason)?.action;
  return <div className="replay-toolbar" role="group" aria-label="Replay navigation">
    <div className="button-row">
      {controls.map(({ action, label, reason, run }) => <button key={action} type="button" className="button"
        aria-disabled={Boolean(reason)} aria-describedby={reason ? `${id}-${action}` : undefined}
        onFocus={() => setFocusedAction(action)} onBlur={() => setFocusedAction(null)}
        onMouseEnter={() => setPointedAction(action)} onMouseLeave={() => setPointedAction(null)}
        onClick={() => { setPointedAction(action); run(); }}>{label}</button>)}
      {tools}
    </div>
    {controls.map(({ action, label, reason }) => reason
      ? <p key={action} id={`${id}-${action}`} className={action === visibleReason ? "replay-reason" : "sr-only"}>{label} · {reason}</p> : null)}
  </div>;
}
