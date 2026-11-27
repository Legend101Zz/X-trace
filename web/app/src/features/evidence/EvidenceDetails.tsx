import honesty from '../../../../../schema/fixtures/replay/honesty-strings.json';
import { sessionContextText } from '../../replay/outcome';
import { sourceStateText } from '../../replay/source-states';
import { NavigationControls } from './NavigationControls';
import { WhyDisclosure } from './WhyDisclosure';
import type { NavAction, NavFrameNavigation } from '../../replay/navigation';
import type { Detail, ReplayEvent } from '../../types';

const INTERACTION_FIELDS = ['kind', 'driver', 'schema', 'table', 'host', 'method'] as const;
const FRAMES = [
  ['Recorded gaps', 'framesWithGap'],
  ['Hidden bindings', 'framesWithRedacted'],
  ['Cut-short bindings', 'framesWithTruncated'],
  ['Unavailable bindings', 'framesWithUnavailable'],
  ['Dropped bindings', 'framesWithDropped'],
  ['Unobserved parents', 'framesWithOrphanParent'],
] as const;

function adapterSummary(summary: Detail['adapterSummary']) {
  if (!summary) return null;
  if ('Redacted' in summary) return { label: 'Hidden', explanation: [honesty.markers.redacted] };
  if ('Unavailable' in summary) {
    const reason = summary.Unavailable.reason;
    return { label: 'Unavailable', explanation: [honesty.markers.unavailable, Object.hasOwn(honesty.unavailableReasons, reason)
      ? honesty.unavailableReasons[reason] : reason] };
  }
  if ('Dropped' in summary) {
    const reason = summary.Dropped.reason;
    return { label: 'Dropped', explanation: [honesty.markers.dropped, Object.hasOwn(honesty.dropReasons, reason)
      ? honesty.dropReasons[reason] : reason] };
  }
  return null;
}

export function EvidenceDetails({ detail, event, selectionUnavailable, showSourceExplanation, onNavigate }: {
  detail: Detail;
  event: ReplayEvent | undefined;
  selectionUnavailable: string | null;
  showSourceExplanation: boolean;
  onNavigate: (action: NavAction, frameId: string) => void;
}) {
  const frames = detail.honesty?.recording;
  const capacity = detail.capacity;
  const summary = adapterSummary(detail.adapterSummary);
  const loadedFrameIds = new Set(detail.events.flatMap((item) => item.frameId ? [item.frameId] : []));
  return <>
    {event ? <>
      <section className="inspector-section" aria-label="Event details">
        <h2 className="inspector-label">Event identity</h2>
        <div className="inspector-value mono" data-event-field="event-id">{event.eventId || 'Unavailable'}</div>
        {event.symbol ? <div className="inspector-value">Recorded symbol · <span className="mono" data-event-field="symbol">{event.symbol}</span></div> : null}
        <div className="inspector-value">Recorded kind · <span className="mono">{event.kind || 'Unavailable'}</span></div>
        <div className="inspector-value">Event sequence · <span className="mono">{event.sequence}</span></div>
        <div className="inspector-value">Frame ID · <span className="mono">{event.frameId ?? 'Unavailable'}</span></div>
        <div className="inspector-value">Recorded depth · <span className="mono">{event.depth ?? 'Unavailable'}</span></div>
        {event.exception ? <div className="inspector-value">Thrown exception: <span className="mono">{event.exception.exceptionType ?? 'type not observed'}</span> · cause chain not observed</div> : null}
        <div className="inspector-value">Parent: <span className="mono">{event.parentEventId || 'Unavailable'}</span></div>
        <div className="inspector-value">Parent frame: <span className="mono">{event.parentFrameId ?? 'Unavailable'}</span></div>
        <div className="inspector-value">Async parent: <span className="mono">{event.asyncParentEventId || 'Unavailable'}</span></div>
        <div className="inspector-value">Async parent frame: <span className="mono">{event.asyncParentFrameId ?? 'Unavailable'}</span></div>
        <div className="inspector-value">Source binding · <span className="mono">{event.sourceBinding || 'Unavailable'}</span></div>
        {event.source ? <>
          <div className="inspector-value">Source status · <span className="mono">{event.source.status}</span></div>
          <div className="inspector-value">Recorded source path · <span className="mono">{event.source.path}</span></div>
        </> : null}
        {showSourceExplanation && (event.source || (event.sourceBinding && event.sourceBinding !== 'unspecified'))
          ? <p className="evidence-state">{sourceStateText(event.sourceBinding, event.source)}</p> : null}
        {INTERACTION_FIELDS.flatMap((field) => event.interaction?.[field]
          ? [<div className="inspector-value" key={field}>{field}: <span className="mono">{event.interaction[field]}</span></div>]
          : [])}
        {!(event.interaction && INTERACTION_FIELDS.some((field) => event.interaction?.[field]))
          ? <div className="inspector-value">No interaction fields persisted</div> : null}
        {(event.fieldTruncations ?? []).map((item, index) => <div key={index} className="evidence-state">{item.field} {item.representation} · {item.originalBytes} bytes</div>)}
        <div className="inspector-value">Monotonic timestamp: <span className="mono">{event.monotonicNs} ns</span></div>
        <div className="evidence-state">Per-event duration is not recorded</div>
      </section>
      <NavigationControls navigation={event.navigation as NavFrameNavigation} loadedFrameIds={loadedFrameIds}
        actions={['previous', 'next']} onNavigate={onNavigate} />
    </> : <p className="evidence-state">{selectionUnavailable ?? 'Select an event for event details.'}</p>}
    <section className="inspector-section" aria-label="Recording details">
      <h2 className="inspector-label">Recording details</h2>
      <p className="inspector-value">Recording ID · <span className="mono">{detail.recordingId}</span></p>
      <p className="inspector-value">Completion · {detail.completion}</p>
      {capacity ? <>
        <p className="inspector-value">Event capacity · {capacity.eventCap}</p>
        <p className="inspector-value">Capacity event count · {capacity.eventCount}</p>
        <p className="inspector-value">Capacity drops · {capacity.capacityDroppedEvents}</p>
      </> : <p className="evidence-state">Event capacity facts unavailable</p>}
      {Object.entries(detail.dropCountsByPriority ?? {}).map(([priority, count]) =>
        <p key={priority} className="inspector-value">Priority {priority} drops · {count}</p>)}
      <h3 className="inspector-label">Indexed recording frames</h3>
      {frames?.countsAvailable ? FRAMES.map(([label, key]) =>
        <p key={key} className="inspector-value">{label} · {frames[key] ?? 'Unavailable'}</p>)
        : <p className="evidence-state">Indexed frame counts unavailable</p>}
      <h3 className="inspector-label">Adapter summary</h3>
      <p className="inspector-value">{summary?.label ?? 'Unavailable'} · producer-declared, separate from response outcome</p>
      {summary ? <WhyDisclosure lines={summary.explanation} /> : null}
    </section>
    {detail.sessionContext ? <section className="inspector-section" aria-label="Session context">
      <h2 className="inspector-label">Session context</h2>
      <p className="inspector-value">{sessionContextText(detail.sessionContext)}</p>
    </section> : null}
  </>;
}
