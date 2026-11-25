import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { PLAYBACK_SPEEDS } from '../../replay/state';
import type { Playback, PlaybackSpeed } from '../../replay/state';
import './replay-controls.css';

/** Explicit display replay; it never sends a request to the recorded application. */
export function ReplayControls({ playback, reason, pacing, onToggle, onPause, onSpeed }: {
  playback: Playback;
  reason: string | null;
  pacing: string;
  onToggle: () => void;
  onPause: () => void;
  onSpeed: (speed: PlaybackSpeed) => void;
}) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const id = useId();
  const playing = playback.status === 'playing';
  const message = playback.stopReason ?? (playing ? pacing : reason ?? 'Replay is paused at the selected step.');
  function close(restore = true) {
    setOpen(false);
    if (restore) trigger.current?.focus({ preventScroll: true });
  }
  useLayoutEffect(() => {
    if (!open) return;
    const element = panel.current;
    if (!element) return;
    const position = () => {
      const anchor = trigger.current?.getBoundingClientRect();
      if (!anchor) return;
      element.style.left = `${Math.max(8, Math.min(anchor.right - element.offsetWidth, window.innerWidth - element.offsetWidth - 8))}px`;
      element.style.top = `${Math.max(8, Math.min(anchor.bottom + 4, window.innerHeight - element.offsetHeight - 8))}px`;
    };
    position();
    element.querySelector<HTMLElement>('[aria-pressed="true"]')?.focus({ preventScroll: true });
    window.addEventListener('resize', position);
    window.addEventListener('scroll', position, true);
    return () => { window.removeEventListener('resize', position); window.removeEventListener('scroll', position, true); };
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const outside = (event: PointerEvent) => {
      if (event.target instanceof Node && !panel.current?.contains(event.target) && !trigger.current?.contains(event.target)) close(false);
    };
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  }, [open]);
  return <div className="replay-playback" role="group" aria-label="Replay playback">
    <div className="replay-playback-actions">
      <button type="button" className="button replay-start" aria-pressed={playing}
        aria-disabled={!playing && reason !== null} aria-describedby={`${id}-status`} aria-keyshortcuts="Alt+P Escape"
        onClick={onToggle}>{playing ? 'Pause' : 'Replay'}</button>
      <button type="button" className="button" ref={trigger} aria-label={`Replay speed, ${playback.speed}×`}
        aria-haspopup="dialog" aria-expanded={open} aria-controls={open ? `${id}-speed` : undefined}
        onClick={() => open ? close() : setOpen(true)}>{playback.speed}×</button>
    </div>
    <p className="replay-playback-status" id={`${id}-status`}>{message}</p>
    {open ? createPortal(<div className="replay-speed-panel" role="dialog" aria-label="Replay speed" id={`${id}-speed`} ref={panel}
      onKeyDown={(event) => {
        if (event.key !== 'Escape') return;
        event.preventDefault(); event.stopPropagation();
        if (playing) onPause();
        close();
      }} onBlur={(event) => {
        if (event.relatedTarget instanceof Node && !event.currentTarget.contains(event.relatedTarget) && event.relatedTarget !== trigger.current) close(false);
      }}>
      <h3>Replay speed</h3>
      <div className="replay-speed-options">{PLAYBACK_SPEEDS.map((speed) => <button type="button" key={speed} className="button"
        aria-pressed={playback.speed === speed} onClick={() => { onSpeed(speed); close(); }}>{speed}×</button>)}</div>
      <p>Replay follows recorded event order. Display delays use recorded timestamps divided by speed, capped at 2 s. Long waits are compressed. This is display pacing, not a step duration.</p>
      <button type="button" className="button" onClick={() => close()}>Close</button>
    </div>, document.body) : null}
  </div>;
}
