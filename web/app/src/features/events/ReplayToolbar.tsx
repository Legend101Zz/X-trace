import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { useViewport } from '../shell/viewport';
import { ReplayControls } from '../shell/ReplayControls';
import type { Playback, PlaybackSpeed } from '../../replay/state';
import type { ReactNode } from 'react';
import type { NavAction, NavControl } from '../../replay/navigation';

const FRAME_STEPS = [
  { action: 'into', label: 'Step in' },
  { action: 'over', label: 'Step over' },
  { action: 'out', label: 'Step out' },
] as const;

export interface PhoneReplayControls {
  playback: Playback;
  reason: string | null;
  pacing: string;
  toggle: () => void;
  pause: () => void;
  speed: (speed: PlaybackSpeed) => void;
  inspect: () => void;
}

export function ReplayToolbar({ backReason, nextReason, frameControls, onMove, onNavigate, tools, phone, viewTabs }: {
  backReason: string | null;
  nextReason: string | null;
  frameControls: readonly NavControl[];
  onMove: (direction: -1 | 1) => void;
  onNavigate: (action: NavAction) => void;
  tools?: ReactNode;
  viewTabs?: ReactNode;
  phone: PhoneReplayControls;
}) {
  const id = useId();
  const isPhone = useViewport('(max-width: 699px)');
  const [more, setMore] = useState(false);
  const moreButton = useRef<HTMLButtonElement>(null);
  const morePanel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!more || !isPhone) return;
    const outside = (event: PointerEvent) => {
      if (event.target instanceof Element && event.target.closest('dialog, [role="dialog"]')) return;
      if (event.target instanceof Node && !morePanel.current?.contains(event.target) && !moreButton.current?.contains(event.target)) setMore(false);
    };
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  }, [more, isPhone]);
  useLayoutEffect(() => { if (more) morePanel.current?.querySelector<HTMLButtonElement>('button')?.focus(); }, [more]);
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
  const stepButton = ({ action, label, reason, run }: typeof controls[number]) =>
    <button key={action} type="button" className="button"
      aria-disabled={Boolean(reason)} aria-describedby={reason ? `${id}-${action}` : undefined}
      onFocus={() => setFocusedAction(action)} onBlur={() => setFocusedAction(null)}
      onMouseEnter={() => setPointedAction(action)} onMouseLeave={() => setPointedAction(null)}
      onClick={() => { setPointedAction(action); run(); }}>{label}</button>;
  if (isPhone) {
    const playing = phone.playback.status === 'playing';
    const closeMore = () => { setMore(false); moreButton.current?.focus(); };
    return <div className="replay-toolbar phone-replay-toolbar" role="group" aria-label="Replay navigation">
      <div hidden={!more} className="phone-more" id={`${id}-more`} ref={morePanel} role="group" aria-label="More replay controls" onKeyDown={(event) => {
        if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); closeMore(); }
      }}>
        {controls.slice(2).map(stepButton)}
        {tools}
        <ReplayControls speedOnly playback={phone.playback} reason={phone.reason} pacing={phone.pacing}
          onToggle={phone.toggle} onPause={phone.pause} onSpeed={phone.speed} />
        <button type="button" className="button" onClick={closeMore}>Close</button>
      </div>
      <div className="phone-actions">
        {stepButton(controls[0])}
        <button type="button" className="button replay-start" aria-keyshortcuts="Alt+P Escape" aria-pressed={playing} aria-disabled={!playing && phone.reason !== null}
          aria-describedby={`${id}-playback`} onClick={phone.toggle}>{playing ? 'Pause' : 'Replay'}</button>
        {stepButton(controls[1])}
        <button type="button" className="button" ref={moreButton} aria-controls={`${id}-more`} aria-expanded={more} onClick={() => setMore(!more)}>More</button>
        <button type="button" className="button" onClick={phone.inspect}>Inspect</button>
      </div>
      <p className="replay-reason replay-playback-status" id={`${id}-playback`}>{phone.playback.stopReason ?? (playing ? phone.pacing : phone.reason ?? 'Replay is paused at the selected step.')}</p>
      <div className="phone-navigation-reasons">
        {controls.map(({ action, label, reason }) => reason ? <p key={action} id={`${id}-${action}`}
          className="replay-reason" data-visible={action === visibleReason}>{label} · {reason}</p> : null)}
      </div>
    </div>;
  }
  return <div className="replay-toolbar" role="group" aria-label="Replay navigation">
    <div className="button-row">
      {viewTabs}
      {controls.map(stepButton)}
      {tools}
    </div>
    {controls.map(({ action, label, reason }) => reason
      ? <p key={action} id={`${id}-${action}`} className={action === visibleReason ? "replay-reason" : "sr-only"}>{label} · {reason}</p> : null)}
  </div>;
}
