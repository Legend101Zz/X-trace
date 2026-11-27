import { PlanAction } from '../exercise/PlanAction';
import { ExportAction } from '../export/ExportAction';
import honesty from '../../../../../schema/fixtures/replay/honesty-strings.json';
import { nsToLabel, outcomeBanner } from '../../replay/outcome';
import { stepSentence } from '../../replay/step-sentence';
import type { Detail, Endpoint, ReplayEvent } from '../../types';
import type { KeyboardEvent, ReactNode } from 'react';

function closeOnEscape(event: KeyboardEvent<HTMLDetailsElement>) {
  if (event.key !== 'Escape' || !event.currentTarget.open) return;
  event.stopPropagation();
  event.currentTarget.open = false;
  event.currentTarget.querySelector('summary')?.focus();
}

export function RecordingContext({ detail, endpoint, event, playback }: {
  detail: Detail;
  endpoint: Endpoint | null;
  event: ReplayEvent | undefined;
  playback?: ReactNode;
}) {
  const outcome = outcomeBanner(detail);
  const status = { complete: 'Complete', partial: 'Partial', invalid: 'Invalid', unavailable: 'Completion unavailable' }[outcome.tone];
  const http = detail.outcome?.httpStatus;
  const limitations = detail.limitations ?? [];
  // This daemon-issued limitation explicitly records a downgrade to standard policy.
  // Local bindings or the absence of a limitation do not identify the applied policy.
  const standard = limitations.includes('capture_policy_not_armed');
  const duration = detail.durationNs == null ? 'unavailable' : nsToLabel(detail.durationNs);
  const captureExplanation = standard ? honesty.unavailableReasons.focused_capture_not_armed : 'Capture mode unavailable for this recording.';
  const limitationList = limitations.length ? <ul aria-label="Recorded capture limitations">
    {limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
  </ul> : null;
  return <section className="replay-context" aria-label="Recording summary">
    <div className="replay-context-request">
      <span className="replay-context-route mono">{endpoint ? `${endpoint.method} ${endpoint.routeTemplate}` : 'Not linked to an endpoint'}</span>
      <span className="replay-context-http mono">
        <span className="sr-only">{http == null ? 'HTTP status unavailable' : `HTTP ${http}`}</span>
        <span aria-hidden="true">{http ?? 'HTTP —'}</span>
      </span>
      <span className={`replay-context-status replay-context-status--${outcome.tone}`}>{status}</span>
      <details name="recording-bar-disclosure" className="replay-context-why" onKeyDown={closeOnEscape}>
        <summary aria-label="Why? Recording outcome">Why?</summary>
        <div className="replay-context-explanation">
          <strong>{outcome.headline}</strong>
          <ul>{outcome.lines.map((line, index) => <li key={index}>{line}</li>)}</ul>
          <div className="compact-capture-evidence">
            {standard && <strong>Standard capture</strong>}
            <p>{captureExplanation}</p>
          </div>
          {limitationList}
        </div>
      </details>
      <span className="recording-duration mono">
        {duration !== 'unavailable' && <span className="sr-only">Adapter-observed duration </span>}
        <span className="recording-duration-value">{duration === 'unavailable' ? 'Duration unavailable' : duration}</span>
      </span>
      <details name="recording-bar-disclosure" className="recording-capture" onKeyDown={closeOnEscape}>
        <summary aria-label="Capture evidence">{standard ? 'Standard' : 'Capture'}</summary>
        <div className="replay-context-explanation">
          <strong>{standard ? 'Standard capture' : 'Capture evidence'}</strong>
          <p>{captureExplanation}</p>
          {limitationList}
        </div>
      </details>
      <details name="recording-bar-disclosure" className="recording-more" onKeyDown={closeOnEscape}>
        <summary aria-label="More recording actions">⋯</summary>
        <div className="recording-more-options"><PlanAction placement="more" /><ExportAction endpoint={endpoint} label="Export…" /></div>
      </details>
    </div>
    {playback}
    <PlanAction placement="bar" />
    {event ? <p className="replay-context-event">
      <span className="mono">Event sequence {event.sequence}</span><span>{stepSentence(event).text}</span>
    </p> : null}
  </section>;
}
