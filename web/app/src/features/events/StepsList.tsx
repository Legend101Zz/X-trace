import { useLayoutEffect, useRef } from 'react';
import type { CSSProperties } from 'react';
import { displaySymbol } from '../../replay/display-symbol';
import { stepSentence } from '../../replay/step-sentence';
import type { ReplayEvent } from '../../types';
import { revealWithin } from '../common/reveal-within';
import './steps.css';

export function StepsList({ events, selected, onPick, onMove }: {
  events: readonly ReplayEvent[];
  selected: ReplayEvent | undefined;
  onPick: (event: ReplayEvent) => void;
  onMove: (direction: -1 | 1) => void;
}) {
  const rail = useRef<HTMLDivElement>(null);
  const selectedRow = useRef<HTMLButtonElement>(null);

  useLayoutEffect(() => {
    const scrollport = rail.current;
    const row = selectedRow.current;
    if (!scrollport || !row) return;
    // A mode switch remounts this rail. Reveal its selection without scrolling any ancestor.
    revealWithin(scrollport, row, 'vertical');
    if (scrollport.contains(document.activeElement)) row.focus({ preventScroll: true });
  }, [selected?.sequence]);

  return <div className="event-rail" ref={rail} aria-label="Loaded replay steps">
    <div className="window-note"><span>{events.length} ordered events</span><span>ALT + ↑ / ↓ to step</span></div>
    {events.map((item, index) => {
      const step = stepSentence(item);
      const symbol = item.symbol ? displaySymbol(item.symbol) : null;
      const active = item === selected;
      const indentation = step.depth === null ? undefined : { '--event-indent': `${Math.min(step.depth, 100) * 18}px` } as CSSProperties;
      return <div key={item.sequence} className="step-row" style={indentation}>
        <button className={`event${step.gap ? ' gap-event' : ''}`} ref={active ? selectedRow : undefined}
          data-event-kind={item.kind} aria-current={active} tabIndex={active || (!selected && index === 0) ? 0 : -1}
          onKeyDown={(key) => {
            if (key.altKey || key.ctrlKey || key.metaKey || (key.key !== 'ArrowUp' && key.key !== 'ArrowDown')) return;
            key.preventDefault();
            onMove(key.key === 'ArrowDown' ? 1 : -1);
          }}
          onClick={() => onPick(item)}>
          <span className="event-seq">{item.sequence}</span>
          <span className="event-copy">
            <span className="event-kind" title={item.kind}>{step.text}</span>
            {symbol && !step.text.includes(symbol) ? <span className="event-symbol">{symbol}</span> : null}
            {item.frameId == null ? <span className="event-symbol">Frame ID unavailable</span> : null}
          </span>
          <span className="event-time">{item.monotonicNs} ns</span>
        </button>
        {step.gap ? <details className="step-why">
          <summary>Why?</summary>
          <p>{step.gap.wording}</p>
          {step.gap.reason ? <p>{step.gap.reason}</p> : null}
          {!step.gap.reason ? <p>{item.gap?.reason ? `Recorded reason code · ${item.gap.reason}` : 'Reason unavailable'}</p> : null}
        </details> : null}
      </div>;
    })}
  </div>;
}
