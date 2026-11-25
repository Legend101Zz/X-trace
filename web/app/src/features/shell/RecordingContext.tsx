import { outcomeBanner } from '../../replay/outcome';
import { stepSentence } from '../../replay/step-sentence';
import type { Detail, Endpoint, ReplayEvent } from '../../types';
import type { ReactNode } from 'react';

export function RecordingContext({ detail, endpoint, event, playback }: {
  detail: Detail;
  endpoint: Endpoint | null;
  event: ReplayEvent | undefined;
  playback?: ReactNode;
}) {
  const outcome = outcomeBanner(detail);
  const status = { complete: 'Complete', partial: 'Partial', invalid: 'Invalid', unavailable: 'Completion unavailable' }[outcome.tone];
  const http = detail.outcome?.httpStatus;
  return <section className="replay-context" aria-label="Recording summary">
    <div className="replay-context-request">
      <span className="replay-context-route mono">{endpoint ? `${endpoint.method} ${endpoint.routeTemplate}` : 'Not linked to an endpoint'}</span>
      <span className="replay-context-http mono">
        <span className="sr-only">{http == null ? 'HTTP status unavailable' : `HTTP ${http}`}</span>
        <span aria-hidden="true">{http ?? 'HTTP —'}</span>
      </span>
      <span className={`replay-context-status replay-context-status--${outcome.tone}`}>{status}</span>
      <details className="replay-context-why" onKeyDown={(event) => {
        if (event.key !== 'Escape') return;
        event.currentTarget.open = false;
        event.currentTarget.querySelector('summary')?.focus();
      }}>
        <summary aria-label="Why? Recording outcome">Why?</summary>
        <div className="replay-context-explanation">
          <strong>{outcome.headline}</strong>
          <ul>{outcome.lines.map((line, index) => <li key={index}>{line}</li>)}</ul>
          {detail.limitations?.length ? <ul aria-label="Recorded capture limitations">
            {detail.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
          </ul> : null}
        </div>
      </details>
    </div>
    {playback}
    {event ? <p className="replay-context-event">
      <span className="mono">Event sequence {event.sequence}</span><span>{stepSentence(event).text}</span>
    </p> : null}
  </section>;
}
