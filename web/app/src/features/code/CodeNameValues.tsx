import { Fragment, useId, useLayoutEffect, useRef, useState } from 'react';
import type { ReplayEvent } from '../../types';
import { BindingList } from '../evidence/Values';
import { javaNameMatches } from './java-name-matches';

export function CodeNameValues({ event, text }: { event: ReplayEvent; text: string }) {
  const matches = javaNameMatches(event);
  const [opened, setOpened] = useState<number | null>(null);
  const opener = useRef<HTMLButtonElement>(null);
  const close = useRef<HTMLButtonElement>(null);
  const cardId = useId();
  useLayoutEffect(() => {
    if (opened !== null) close.current?.focus();
  }, [opened]);

  function dismiss() {
    setOpened(null);
    opener.current?.focus({ preventScroll: true });
  }

  const active = opened === null ? undefined : matches[opened];
  let end = 0;
  return <>
    <code className="source-text">{matches.map(({ from, to, binding }, index) => {
      const prefix = text.slice(end, from);
      end = to;
      return <Fragment key={from}>{prefix}<button type="button" className="source-name-match"
        aria-label={`Recorded value for ${binding.name}, matched by name`}
        aria-expanded={opened === index} aria-controls={opened === index ? cardId : undefined}
        onClick={(event) => {
          if (opened === index) dismiss();
          else {
            opener.current = event.currentTarget;
            setOpened(index);
          }
        }}>{text.slice(from, to)}</button></Fragment>;
    })}{text.slice(end)}</code>
    {active ? <section className="source-name-card" id={cardId} aria-label={`Recorded value for ${active.binding.name}`}
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          event.stopPropagation();
          dismiss();
        }
      }}>
      <button type="button" className="button" ref={close} onClick={dismiss}>Close value</button>
      <p>Event sequence {event.sequence} · Matched by name only</p>
      <BindingList bindings={[active.binding]} inline />
    </section> : null}
  </>;
}
