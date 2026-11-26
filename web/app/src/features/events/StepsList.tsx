import { useLayoutEffect, useRef, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { displaySymbol } from '../../replay/display-symbol';
import { stepSentence } from '../../replay/step-sentence';
import type { ReplayEvent } from '../../types';
import { revealWithin } from '../common/reveal-within';
import { stepScrollOwner, useStepWindow } from './useStepWindow';
import './steps.css';

export function StepsList({ events, selected, timing, onPick, onMove, onFocusedRowReleased }: {
  events: readonly ReplayEvent[];
  selected: ReplayEvent | undefined;
  timing?: ReadonlyMap<string, string>;
  onPick: (event: ReplayEvent) => void;
  onMove: (direction: -1 | 1) => void;
  onFocusedRowReleased?: (sequence: string) => void;
}) {
  const rail = useRef<HTMLDivElement>(null);
  const selectedRow = useRef<HTMLButtonElement>(null);
  const pendingFocus = useRef<string | undefined>(undefined);
  const [disclosures, setDisclosures] = useState<ReadonlySet<string>>(new Set());
  const { list, mounted, offsets, first, focused, setFocused, revealIndex, groupSize } = useStepWindow(events, selected?.sequence);

  useLayoutEffect(() => {
    if (focused === undefined || events.some(({ sequence }) => sequence === focused)) return;
    setFocused(undefined);
    if (document.activeElement === document.body) onFocusedRowReleased?.(focused);
  }, [events, focused, onFocusedRowReleased, setFocused]);

  useLayoutEffect(() => {
    const row = selectedRow.current;
    const element = list.current;
    if (!row || !element) return;
    // A mode switch remounts Steps. Reveal the pinned selection in its own scrollport.
    revealWithin(stepScrollOwner(element), row, 'vertical');
    if (rail.current?.contains(document.activeElement)) row.focus({ preventScroll: true });
  }, [selected?.sequence]);

  useLayoutEffect(() => {
    if (!pendingFocus.current) return;
    const row = Array.from(list.current?.querySelectorAll<HTMLElement>('[data-step-sequence]') ?? [])
      .find((item) => item.dataset.stepSequence === pendingFocus.current);
    if (row) {
      row.querySelector<HTMLButtonElement>('.event')?.focus({ preventScroll: true });
      pendingFocus.current = undefined;
    }
  });

  useLayoutEffect(() => {
    setDisclosures((open) => {
      const retained = new Set(events.filter(({ sequence }) => open.has(sequence)).map(({ sequence }) => sequence));
      return retained.size === open.size ? open : retained;
    });
  }, [events]);

  const browseTo = (index: number) => {
    pendingFocus.current = revealIndex(index);
  };

  const rows: ReactNode[] = [];
  let previous = 0;
  for (const index of mounted) {
    const item = events[index];
    if (index > previous) rows.push(<li key={`spacer-${index}`} className="steps-spacer" aria-hidden="true"
      style={{ height: offsets[index] - offsets[previous] }} />);
    previous = index + 1;
    const step = stepSentence(item);
    const symbol = item.symbol ? displaySymbol(item.symbol) : null;
    const active = item === selected;
    const indentation = step.depth === null ? undefined : { '--event-indent': `${Math.min(step.depth, 100) * 18}px` } as CSSProperties;
    rows.push(<li key={item.sequence} className="step-row" style={indentation}
      data-step-sequence={item.sequence} aria-posinset={index + 1} aria-setsize={events.length}
      onFocus={() => setFocused(item.sequence)} onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setFocused(undefined);
      }}>
      <button className={`event${step.gap ? ' gap-event' : ''}${timing ? ' event-with-timing' : ''}`} ref={active ? selectedRow : undefined}
        data-event-kind={item.kind} aria-current={active} tabIndex={active || (!selected && index === 0) ? 0 : -1}
        onKeyDown={(key) => {
          if (key.altKey || key.ctrlKey || key.metaKey || (key.key !== 'ArrowUp' && key.key !== 'ArrowDown')) return;
          key.preventDefault();
          const direction = key.key === 'ArrowDown' ? 1 : -1;
          if (active) onMove(direction);
          else browseTo(index + direction);
        }}
        onClick={() => onPick(item)}>
        <span className="event-seq">{item.sequence}</span>
        <span className="event-copy">
          <span className="event-kind" title={item.kind}>{step.text}</span>
          {symbol && !step.text.includes(symbol) ? <span className="event-symbol">{symbol}</span> : null}
          {item.frameId == null ? <span className="event-symbol">Frame ID unavailable</span> : null}
        </span>
        <span className="event-time">{timing?.get(item.sequence)}</span>
      </button>
      {step.gap ? <details className="step-why" open={disclosures.has(item.sequence)} onToggle={(event) => {
        const open = event.currentTarget.open;
        setDisclosures((current) => {
          if (current.has(item.sequence) === open) return current;
          const next = new Set(current);
          if (open) next.add(item.sequence);
          else next.delete(item.sequence);
          return next;
        });
      }}>
        <summary>Why?</summary>
        <p>{step.gap.wording}</p>
        {step.gap.reason ? <p>{step.gap.reason}</p> : null}
        {!step.gap.reason ? <p>{item.gap?.reason ? `Recorded reason code · ${item.gap.reason}` : 'Reason unavailable'}</p> : null}
      </details> : null}
    </li>);
  }
  if (previous < events.length) rows.push(<li key="spacer-end" className="steps-spacer" aria-hidden="true"
    style={{ height: offsets[events.length] - offsets[previous] }} />);

  return <div className="event-rail" ref={rail}>
    <div className="window-note"><span>{events.length} ordered events</span><span>ALT + ↑ / ↓ to step</span></div>
    <div className="step-groups" role="group" aria-label="Browse loaded Steps">
      <button className="button" disabled={first <= 0} onClick={() => browseTo(first - groupSize)}>Earlier loaded rows</button>
      <button className="button" disabled={first >= events.length - 1} onClick={() => browseTo(first + groupSize)}>Later loaded rows</button>
      <span>Loaded position {first + 1} of {events.length}</span>
    </div>
    <ol className="steps-list" role="list" aria-label="Loaded replay steps" ref={list}>{rows}</ol>
  </div>;
}
