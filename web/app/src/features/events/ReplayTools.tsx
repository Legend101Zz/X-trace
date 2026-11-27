import { Fragment, useContext, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import type { RefObject } from 'react';
import { createPortal } from 'react-dom';
import type { ReplayEvent } from '../../types';
import type { ReplayFilter } from '../../replay/state';
import { JUMP_KINDS, STEP_FILTERS, jumpTarget, matchesJump } from '../../replay/loaded-tools';
import { useViewerPreferences, ViewerPreferencesUpdateContext } from '../shell/viewer-preferences';
import { PlanAction } from '../exercise/PlanAction';
import { useViewport } from '../shell/viewport';
import { focusStepControl } from './useStepWindow';

type Panel = 'tools' | 'filter' | 'goto' | 'jump';

export function ReplayTools({ events, selected, filter, busy, onFilter, onGo, onActivate, onAnnounce, controlRef }: {
  events: readonly ReplayEvent[];
  selected: ReplayEvent | undefined;
  filter: ReplayFilter;
  busy: boolean;
  onFilter: (kinds: readonly string[]) => void;
  onGo: (sequence: string) => void;
  onActivate: () => void;
  onAnnounce: (message: string) => void;
  controlRef: RefObject<HTMLButtonElement | null>;
}) {
  const wide = useViewport('(min-width: 1280px)');
  const compactPlan = useViewport('(max-width: 1023px)');
  const preferences = useViewerPreferences();
  const update = useContext(ViewerPreferencesUpdateContext);
  const [panel, setPanel] = useState<Panel | null>(null);
  const [sequence, setSequence] = useState('');
  const [message, setMessage] = useState('');
  const root = useRef<HTMLDivElement>(null);
  const body = useRef<HTMLDivElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const id = useId();
  const filtered = filter.kinds.length > 0;

  function close(restore = true) {
    setPanel(null);
    if (restore) {
      const target = opener.current?.isConnected && opener.current.getClientRects().length ? opener.current : controlRef.current;
      if (target) focusStepControl(target);
    }
  }
  function open(next: Panel, trigger?: HTMLElement) {
    if (trigger && !body.current?.contains(trigger)) opener.current = trigger;
    setMessage('');
    setPanel(next);
    onActivate();
  }
  function report(text: string) { setMessage(text); onAnnounce(text); }
  function toggleTiming(trigger?: HTMLElement) {
    if (trigger && !body.current?.contains(trigger)) opener.current = trigger;
    update?.('timing', preferences.timing === 'on' ? 'off' : 'on');
    onAnnounce(preferences.timing === 'on' ? 'Timing hidden.' : 'Timing shown: time since the first loaded step, not a duration.');
    close();
  }

  useLayoutEffect(() => {
    if (!panel) return;
    const element = body.current;
    const tools = root.current;
    if (!element || !tools) return;
    function position() {
      if (!element || !tools) return;
      const anchor = tools.getBoundingClientRect();
      const paneWidth = tools.closest('#events-panel')?.getBoundingClientRect().width || window.innerWidth;
      const width = Math.min(420, paneWidth - 12, window.innerWidth - 16);
      element.style.width = `${Math.max(0, width)}px`;
      element.style.left = `${Math.max(8, Math.min(anchor.right - width, window.innerWidth - width - 8))}px`;
      element.style.top = `${Math.max(8, Math.min(anchor.bottom + 4, window.innerHeight - element.getBoundingClientRect().height - 8))}px`;
    }
    position();
    element.querySelector<HTMLElement>('input, button')?.focus({ preventScroll: true });
    // A portal keeps the panel clear of the independently scrolling and clipped Steps pane.
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(position);
    observer?.observe(element);
    window.addEventListener('resize', position);
    window.addEventListener('scroll', position, true);
    return () => {
      observer?.disconnect();
      window.removeEventListener('resize', position);
      window.removeEventListener('scroll', position, true);
    };
  }, [panel]);

  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if (event.defaultPrevented || !event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
      if (event.target instanceof Element && event.target.closest('input, select, textarea, [contenteditable]:not([contenteditable="false"]), [role="dialog"]')) return;
      const next = ({ KeyQ: 'filter', KeyJ: 'goto', KeyG: 'jump' } as const)[event.code as 'KeyQ' | 'KeyJ' | 'KeyG'];
      if (!next) return;
      event.preventDefault();
      open(next, event.target instanceof HTMLElement ? event.target : undefined);
    }
    window.addEventListener('keydown', shortcut);
    return () => window.removeEventListener('keydown', shortcut);
  });

  useEffect(() => {
    if (!panel) return;
    function outside(event: PointerEvent) {
      if (event.target instanceof Node && !root.current?.contains(event.target) && !body.current?.contains(event.target)) close(false);
    }
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  });

  const trigger = (target: Panel, label: string, ref?: RefObject<HTMLButtonElement | null>) => <button type="button" className="button"
    ref={ref} aria-expanded={panel === target || (target === 'tools' && panel !== null)} aria-controls={panel ? id : undefined}
    onClick={(event) => panel === target ? close() : open(target, event.currentTarget)}>{label}{filtered && (target === 'filter' || target === 'tools') ? ' · 1' : ''}</button>;
  const searchLimit = <p>Only the {events.length} loaded steps ({events[0]?.sequence}–{events.at(-1)?.sequence}) are searched. Use Load earlier or Load later for other windows. No match here does not mean no match in the recording.</p>;
  const status = <p className="replay-tool-message" id={`${id}-message`}>{message}</p>;

  return <div className="replay-tools" ref={root} onKeyDown={(event) => {
    if (event.key === 'Escape' && panel) { event.preventDefault(); event.stopPropagation(); close(); }
  }} onBlur={(event) => {
    if (event.relatedTarget instanceof Node && !event.currentTarget.contains(event.relatedTarget) && !body.current?.contains(event.relatedTarget)) close(false);
  }}>
    {wide ? <>{trigger('filter', 'Filter')}{trigger('goto', 'Go to step', controlRef)}
      <button className="button" type="button" aria-pressed={preferences.timing === 'on'} disabled={!update} onClick={(event) => toggleTiming(event.currentTarget)}>Show timing</button>
      {trigger('jump', 'Jump')}</> : trigger('tools', 'Tools', controlRef)}
    {panel ? createPortal(<div className={panel === 'jump' ? 'replay-tool-panel replay-tool-panel--jump' : 'replay-tool-panel'}
      ref={body} role="dialog" aria-label={{ tools: 'Tools', filter: 'Filter steps', goto: 'Go to step', jump: 'Jump to' }[panel]} id={id}>
      {panel === 'tools' ? <div className="replay-tool-options">
        <button className="button" type="button" onClick={() => open('filter')}>Filter steps{filtered ? ' · 1' : ''}</button>
        <button className="button" type="button" onClick={() => open('goto')}>Go to step</button>
        <button className="button" type="button" onClick={() => open('jump')}>Jump to…</button>
        <button className="button" type="button" aria-pressed={preferences.timing === 'on'} disabled={!update} onClick={() => toggleTiming()}>Show timing</button>
        {compactPlan && <PlanAction placement="tools" returnFocus={controlRef.current} closeTools={() => close(false)} />}
      </div> : null}
      {panel === 'filter' ? <>
        <h3>Show these steps</h3>
        <div className="replay-tool-options">{STEP_FILTERS.map((option) => <button className="button" key={option.id} type="button"
          aria-pressed={option.kinds.length === filter.kinds.length && option.kinds.every((kind) => filter.kinds.includes(kind))}
          onClick={() => { onFilter(option.kinds); close(); }}>{option.label}</button>)}</div>
        <p>Filters the steps already loaded on this machine. The selected step always stays listed.</p>
      </> : null}
      {panel === 'goto' ? <>
        <form onSubmit={(event) => {
          event.preventDefault();
          if (busy) { report('Loading event window…'); return; }
          const raw = sequence.trim();
          if (!/^\d+$/.test(raw)) { report('Enter a whole step number.'); return; }
          const canonical = raw.replace(/^0+(?=\d)/, '');
          if (!events.some((event) => event.sequence === canonical)) {
            report('Event sequence is not in the loaded window. Use Load earlier or Load later to reach another window.');
            return;
          }
          close(false);
          onGo(canonical);
        }}>
          <label htmlFor={`${id}-sequence`}>Go to step number</label>
          <div className="replay-tool-sequence"><input id={`${id}-sequence`} type="text" inputMode="numeric" value={sequence}
            onChange={(event) => setSequence(event.currentTarget.value)} />
            <button className="button" type="submit" disabled={busy}>Go</button></div>
        </form>
        <button className="link-button" type="button" onClick={() => open('jump')}>Jump to the next not-recorded stretch, exception or call…</button>
      </> : null}
      {panel === 'jump' ? <div className="replay-jump-content">
        <h3>Jump to the previous or next</h3>
        {JUMP_KINDS.map(({ id: kind, label }) => <div className="replay-jump-row" key={kind}>
          <span>{label} · {events.filter((event) => matchesJump(event, kind)).length}</span>
          {([-1, 1] as const).map((direction) => {
            const word = direction === -1 ? 'Previous' : 'Next';
            const target = jumpTarget(events, selected, kind, direction);
            const reason = !selected ? 'Selected event is not in the loaded window.'
              : `No ${direction === -1 ? 'earlier' : 'later'} ${label.toLowerCase()} in the loaded steps.`;
            const unavailable = busy ? 'Loading event window…' : !target ? reason : null;
            const reasonId = `${id}-${kind}-${direction}-reason`;
            return <Fragment key={direction}><button className="button" type="button" aria-label={`${word} ${label.toLowerCase()}`}
              aria-disabled={busy || !target} aria-describedby={unavailable ? reasonId : undefined}
              onFocus={() => setMessage(busy ? 'Loading event window…' : !target ? reason : '')}
              onMouseEnter={() => setMessage(busy ? 'Loading event window…' : !target ? reason : '')} onClick={() => {
                if (busy) { report('Loading event window…'); return; }
                if (!target) { report(reason); return; }
                close(false);
                onGo(target.sequence);
              }}>{word}</button>
              {unavailable ? <span className="sr-only" id={reasonId}>{unavailable}</span> : null}</Fragment>;
          })}
        </div>)}
        {searchLimit}
        {status}
      </div> : null}
      {panel === 'goto' ? searchLimit : null}
      {panel !== 'jump' ? status : null}
      <button className="button" type="button" onClick={() => close()}>Close</button>
    </div>, document.body) : null}
  </div>;
}
