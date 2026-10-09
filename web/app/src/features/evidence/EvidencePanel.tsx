import type { Detail, ReplayEvent } from '../../types';

export interface EvidencePanelProps {
  active: boolean;
  currentStatus: string;
  detail: Detail | null;
  event: ReplayEvent | undefined;
  selectedEvent: number;
  eventCount: number;
  onMoveEvent: (delta: number) => void;
}

export function EvidencePanel({ active, currentStatus, detail, event, selectedEvent, eventCount, onMoveEvent }: EvidencePanelProps) {
  return <section className="pane" role="tabpanel" id="evidence-panel" aria-labelledby="evidence-tab" data-active={active} aria-label="Evidence inspector">
        <div className="pane-head"><div><div className="eyebrow">Persisted facts</div><h1>Evidence inspector</h1></div><span className="top-meta">{currentStatus}</span></div>
        <div className="inspector">
          {event ? <>
            <div className="inspector-section"><div className="inspector-label">Event identity</div><div className="inspector-value mono">{event.eventId || 'Unavailable'}</div></div>
            <div className="inspector-section"><div className="inspector-label">Relationships</div><div className="inspector-value">Parent: <span className="mono">{event.parentEventId || 'Unavailable'}</span></div><div className="inspector-value">Async parent: <span className="mono">{event.asyncParentEventId || 'Unavailable'}</span></div></div>
            <div className="inspector-section"><div className="inspector-label">Persisted interaction</div>{event.interaction ? Object.entries(event.interaction).filter(([, value]) => value).map(([key, value]) => <div className="inspector-value" key={key}>{key}: <span className="mono">{value}</span></div>) : <div className="inspector-value">No interaction fields persisted</div>}</div>
            {event.fieldTruncations.map((item) => <div key={item.field} className="evidence-state">{item.field} {item.representation} · {item.originalBytes} bytes</div>)}
            {detail?.incompleteEvidence.map((item, index) => <div key={`${item}-${index}`} className="evidence-state">Persisted incomplete evidence: {item}</div>)}
            <div className="inspector-section"><div className="inspector-label">Recorded source evidence</div>{event.source ? <><div className="inspector-value">{event.source.path} · debug range L{event.source.startLine}{event.source.endLine && event.source.endLine !== event.source.startLine ? `–L${event.source.endLine}` : ''}</div><div className="evidence-state">{event.source.status === 'matched' ? 'Adapter reported a compile-time source binding; current source matches the recorded identity' : event.source.status === 'mismatch' ? 'Adapter reported a compile-time source binding; current source differs from the recorded identity' : 'Current source could not be verified safely'}</div>{event.source.excerpt ? <pre className="source-excerpt">{event.source.excerpt}</pre> : null}{event.source.truncated ? <div className="evidence-state">Source excerpt is bounded</div> : null}</> : <div className="evidence-state">{event.sourceBinding === 'attestation_missing' ? 'Build source attestation was absent' : event.sourceBinding === 'class_bytes_mismatch' ? 'Loaded class bytes did not match the adapter-reported build attestation' : event.sourceBinding === 'debug_metadata_absent' ? 'Compiled method line metadata was absent' : event.sourceBinding === 'source_metadata_invalid' ? 'Build source metadata was invalid' : 'Source location is unavailable for this event'}</div>}<div className="evidence-state">Values were not projected · response outcome is not event-verified</div></div>
            <div className="inspector-section"><div className="inspector-label">Timing</div><div className="inspector-value">Monotonic timestamp: <span className="mono">{event.monotonicNs} ns</span></div><div className="evidence-state">Duration unavailable for this capture</div></div>
            <div className="page-controls"><button className="button" onClick={() => onMoveEvent(-1)} disabled={selectedEvent <= 0}>Previous</button><button className="button" onClick={() => onMoveEvent(1)} disabled={selectedEvent >= eventCount - 1}>Next</button></div>
          </> : <div className="empty"><strong>Select an event</strong><p>Event selection synchronizes this evidence inspector.</p></div>}
        </div>
      </section>;
}
