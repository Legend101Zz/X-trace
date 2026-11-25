import { useLayoutEffect, useRef } from 'react';
import type { CSSProperties } from 'react';
import { stepSentence } from '../../replay/step-sentence';
import type { ReplayEvent } from '../../types';
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
    if (rail.current?.contains(document.activeElement)) selectedRow.current?.focus();
  }, [selected?.sequence]);

  return <div className="event-rail" ref={rail} aria-label="Loaded replay steps">
    <div className="window-note"><span>{events.length} ordered events</span><span>ALT + ↑ / ↓ to step</span></div>
    {events.map((item, index) => {
      const step = stepSentence(item);
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
            {item.symbol && !step.text.includes(item.symbol) ? <span className="event-symbol">{item.symbol}</span> : null}
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
