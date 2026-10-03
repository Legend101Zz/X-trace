import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { components } from './api.generated';
import { retainPage } from './retained-page';
import './style.css';

type Recording = components['schemas']['ObservedRecording'];
type Endpoint = components['schemas']['ObservedEndpoint'];
type Detail = components['schemas']['RecordingDetail'];
type Pane = 'recordings' | 'events' | 'evidence';
type CatalogMode = 'endpoints' | 'linked' | 'unmatched';

const MAX_RETAINED_ROWS = 500;
const MAX_RETAINED_EVENTS = 2_000;

class ApiError extends Error {
  constructor(readonly status: number) {
    super(`Request failed (${status})`);
  }
}

async function api<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'X-XTrace-Client': 'viewer-v1' },
  });
  if (!response.ok) {
    throw new ApiError(response.status);
  }
  return (await response.json()) as T;
}

function failureMessage(error: unknown): string {
  if (error instanceof ApiError) return `Request failed with status ${error.status}.`;
  return 'The local viewer could not complete this request. Retry to continue.';
}

/** Read-only local browser for bounded observed endpoints and persisted recordings. */
export default function App() {
  const [auth, setAuth] = useState<'checking' | 'ready' | 'expired' | 'error'>('checking');
  const [authError, setAuthError] = useState('');
  const [catalogMode, setCatalogMode] = useState<CatalogMode>('endpoints');
  const [activePane, setActivePane] = useState<Pane>('recordings');
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [endpointCursor, setEndpointCursor] = useState<string | null>(null);
  const [selectedOperation, setSelectedOperation] = useState('');
  const [selectedEndpointSnapshot, setSelectedEndpointSnapshot] = useState<Endpoint | null>(null);
  const [linked, setLinked] = useState<Recording[]>([]);
  const [linkedCursor, setLinkedCursor] = useState<string | null>(null);
  const [unmatched, setUnmatched] = useState<Recording[]>([]);
  const [unmatchedCursor, setUnmatchedCursor] = useState<string | null>(null);
  const [selectedRecording, setSelectedRecording] = useState('');
  const [detail, setDetail] = useState<Detail | null>(null);
  const [selectedEvent, setSelectedEvent] = useState(0);
  const [olderEndpointsReleased, setOlderEndpointsReleased] = useState(false);
  const [olderLinkedReleased, setOlderLinkedReleased] = useState(false);
  const [olderUnmatchedReleased, setOlderUnmatchedReleased] = useState(false);
  const [olderEventsReleased, setOlderEventsReleased] = useState(false);
  const [endpointBusy, setEndpointBusy] = useState(false);
  const [linkedBusy, setLinkedBusy] = useState(false);
  const [unmatchedBusy, setUnmatchedBusy] = useState(false);
  const [detailBusy, setDetailBusy] = useState(false);
  const [endpointError, setEndpointError] = useState('');
  const [linkedError, setLinkedError] = useState('');
  const [unmatchedError, setUnmatchedError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [announcement, setAnnouncement] = useState('');
  const authStarted = useRef(false);
  const endpointsRef = useRef<Endpoint[]>([]);
  const linkedRef = useRef<Recording[]>([]);
  const unmatchedRef = useRef<Recording[]>([]);
  const detailRef = useRef<Detail | null>(null);
  const selectedRecordingRef = useRef('');
  const selectedOperationRef = useRef('');
  const catalogModeRef = useRef<CatalogMode>('endpoints');
  const endpointHasLoaded = useRef(false);
  const endpointGeneration = useRef(0);
  const linkedGeneration = useRef(0);
  const unmatchedGeneration = useRef(0);
  const detailGeneration = useRef(0);

  useEffect(() => { endpointsRef.current = endpoints; }, [endpoints]);
  useEffect(() => { linkedRef.current = linked; }, [linked]);
  useEffect(() => { unmatchedRef.current = unmatched; }, [unmatched]);
  useEffect(() => { detailRef.current = detail; }, [detail]);

  const markExpired = (error: unknown) => {
    if (!(error instanceof ApiError) || error.status !== 401) return;
    endpointGeneration.current += 1; linkedGeneration.current += 1;
    unmatchedGeneration.current += 1; detailGeneration.current += 1;
    setEndpointBusy(false); setLinkedBusy(false); setUnmatchedBusy(false); setDetailBusy(false);
    setAuth('expired');
  };

  const loadEndpoints = useCallback(async (cursor: string | null = null, append = false) => {
    const generation = ++endpointGeneration.current;
    setEndpointBusy(true);
    setEndpointError('');
    try {
      const query = cursor ? `?limit=100&cursor=${encodeURIComponent(cursor)}` : '?limit=100';
      const page = await api<components['schemas']['ObservedEndpointPage']>(`/api/v1/endpoints${query}`);
      if (generation !== endpointGeneration.current) return;
      const result = retainPage(append ? endpointsRef.current : [], page.items, MAX_RETAINED_ROWS, page.nextCursor);
      endpointsRef.current = result.items;
      setEndpoints(result.items);
      setEndpointCursor(result.nextCursor);
      setOlderEndpointsReleased(result.released > 0);
      endpointHasLoaded.current = true;
      if (catalogModeRef.current === 'endpoints') setAnnouncement(`${page.items.length} observed endpoints loaded`);
    } catch (error) {
      if (generation !== endpointGeneration.current) return;
      markExpired(error);
      setEndpointError(failureMessage(error));
    } finally {
      if (generation === endpointGeneration.current) {
        setEndpointBusy(false);
      }
    }
  }, []);

  const loadLinked = useCallback(async (operationId: string, cursor: string | null = null, append = false) => {
    if (!operationId || selectedOperationRef.current !== operationId) return;
    const generation = ++linkedGeneration.current;
    setLinkedBusy(true);
    setLinkedError('');
    try {
      const query = cursor ? `?limit=50&cursor=${encodeURIComponent(cursor)}` : '?limit=50';
      const page = await api<components['schemas']['ObservedRecordingPage']>(`/api/v1/endpoints/${encodeURIComponent(operationId)}/recordings${query}`);
      if (generation !== linkedGeneration.current || selectedOperationRef.current !== operationId) return;
      const result = retainPage(append ? linkedRef.current : [], page.items, MAX_RETAINED_ROWS, page.nextCursor);
      linkedRef.current = result.items;
      setLinked(result.items);
      setLinkedCursor(result.nextCursor);
      setOlderLinkedReleased(result.released > 0);
      if (catalogModeRef.current === 'linked') setAnnouncement(`${page.items.length} linked recordings loaded`);
    } catch (error) {
      if (generation !== linkedGeneration.current || selectedOperationRef.current !== operationId) return;
      markExpired(error);
      setLinkedError(failureMessage(error));
    } finally {
      if (generation === linkedGeneration.current && selectedOperationRef.current === operationId) {
        setLinkedBusy(false);
      }
    }
  }, []);

  const loadUnmatched = useCallback(async (cursor: string | null = null, append = false) => {
    const generation = ++unmatchedGeneration.current;
    setUnmatchedBusy(true);
    setUnmatchedError('');
    try {
      const query = cursor ? `?unmatched=true&limit=50&cursor=${encodeURIComponent(cursor)}` : '?unmatched=true&limit=50';
      const page = await api<components['schemas']['ObservedRecordingPage']>(`/api/v1/recordings${query}`);
      if (generation !== unmatchedGeneration.current) return;
      const result = retainPage(append ? unmatchedRef.current : [], page.items, MAX_RETAINED_ROWS, page.nextCursor);
      unmatchedRef.current = result.items;
      setUnmatched(result.items);
      setUnmatchedCursor(result.nextCursor);
      setOlderUnmatchedReleased(result.released > 0);
      if (catalogModeRef.current === 'unmatched') setAnnouncement(`${page.items.length} unmatched recordings loaded`);
    } catch (error) {
      if (generation !== unmatchedGeneration.current) return;
      markExpired(error);
      setUnmatchedError(failureMessage(error));
    } finally {
      if (generation === unmatchedGeneration.current) {
        setUnmatchedBusy(false);
      }
    }
  }, []);

  const loadDetail = useCallback(async (recordingId: string, cursor: string | null = null, append = false) => {
    if (!recordingId || selectedRecordingRef.current !== recordingId) return;
    const generation = ++detailGeneration.current;
    setDetailBusy(true);
    setDetailError('');
    try {
      const query = cursor ? `?limit=200&cursor=${encodeURIComponent(cursor)}` : '?limit=200';
      const next = await api<Detail>(`/api/v1/recordings/${encodeURIComponent(recordingId)}${query}`);
      if (generation !== detailGeneration.current || selectedRecordingRef.current !== recordingId) return;
      const previous = append ? detailRef.current : null;
      const result = retainPage(previous?.events ?? [], next.events, MAX_RETAINED_EVENTS, next.nextCursor ?? null);
      const updated = { ...next, events: result.items, nextCursor: result.nextCursor };
      detailRef.current = updated;
      setDetail(updated);
      setOlderEventsReleased(result.released > 0);
      if (!append) setSelectedEvent(0);
      else if (result.released > 0) setSelectedEvent((current) => Math.max(0, current - result.released));
      setAnnouncement(`${next.events.length} events available for selection`);
    } catch (error) {
      if (generation !== detailGeneration.current || selectedRecordingRef.current !== recordingId) return;
      markExpired(error);
      setDetailError(failureMessage(error));
    } finally {
      if (generation === detailGeneration.current && selectedRecordingRef.current === recordingId) {
        setDetailBusy(false);
      }
    }
  }, []);

  function selectRecording(recordingId: string) {
    const changed = selectedRecordingRef.current !== recordingId;
    selectedRecordingRef.current = recordingId;
    setSelectedRecording(recordingId);
    setActivePane('events');
    if (changed) {
      detailGeneration.current += 1;
      detailRef.current = null;
      setDetail(null);
      setDetailError('');
      setDetailBusy(false);
      setSelectedEvent(0);
      setOlderEventsReleased(false);
      void loadDetail(recordingId);
    }
    setAnnouncement(`Recording ${recordingId} selected`);
  }

  useEffect(() => {
    if (authStarted.current) return;
    authStarted.current = true;
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const token = fragment.get('token');
    // Always discard the one-time fragment before rendering an error or sending a request.
    window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    if (!token) {
      setAuth('error');
      setAuthError('The one-time viewer link is missing. Restart xtrace open --viewer.');
      return;
    }
    void fetch('/api/v1/auth/exchange', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-XTrace-Client': 'viewer-v1' },
      body: JSON.stringify({ token }),
    }).then(async (response) => {
      if (!response.ok) throw new Error('Viewer link is invalid or expired. Restart xtrace open --viewer.');
      setAuth('ready');
      catalogModeRef.current = 'endpoints';
      setCatalogMode('endpoints');
      await loadEndpoints();
    }).catch((cause: unknown) => {
      setAuth('error');
      setAuthError(cause instanceof Error ? cause.message : 'Viewer authentication failed');
    });
  }, [loadEndpoints]);

  const selectedEndpoint = selectedEndpointSnapshot;
  const currentRows = catalogMode === 'linked' ? linked : unmatched;
  const currentRecording = currentRows.find((item) => item.recordingId === selectedRecording);
  const currentStatus = currentRecording?.status ?? (detail?.recordingId === selectedRecording ? detail.status : 'no selection');
  const eventCount = useMemo(() => detail?.events.length ?? 0, [detail]);
  const event = detail?.events[selectedEvent];

  const moveEvent = useCallback((delta: number) => {
    if (eventCount === 0) return;
    setSelectedEvent((current) => {
      const next = Math.max(0, Math.min(eventCount - 1, current + delta));
      if (next !== current) setAnnouncement(`Event ${detail?.events[next]?.sequence ?? ''} selected`);
      return next;
    });
  }, [detail, eventCount]);

  useEffect(() => {
    const onKeyDown = (keyboard: KeyboardEvent) => {
      if (!keyboard.altKey || (keyboard.key !== 'ArrowDown' && keyboard.key !== 'ArrowUp')) return;
      keyboard.preventDefault();
      moveEvent(keyboard.key === 'ArrowDown' ? 1 : -1);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [moveEvent]);

  function openEndpoint(endpoint: Endpoint) {
    endpointGeneration.current += 1; setEndpointBusy(false);
    unmatchedGeneration.current += 1; setUnmatchedBusy(false); setUnmatchedError('');
    catalogModeRef.current = 'linked';
    selectedOperationRef.current = endpoint.operationId;
    selectedRecordingRef.current = '';
    setSelectedOperation(endpoint.operationId);
    setSelectedEndpointSnapshot(endpoint);
    setSelectedRecording('');
    setCatalogMode('linked');
    setLinked([]); linkedRef.current = []; setLinkedCursor(null); setLinkedError('');
    linkedGeneration.current += 1; setLinkedBusy(false);
    detailGeneration.current += 1; setDetailBusy(false); setDetailError('');
    detailRef.current = null; setDetail(null); setSelectedEvent(0);
    setOlderEventsReleased(false);
    setOlderLinkedReleased(false);
    void loadLinked(endpoint.operationId);
  }

  function openUnmatched() {
    endpointGeneration.current += 1; setEndpointBusy(false); setEndpointError('');
    linkedGeneration.current += 1; setLinkedBusy(false); setLinkedError('');
    catalogModeRef.current = 'unmatched';
    selectedOperationRef.current = '';
    selectedRecordingRef.current = '';
    setSelectedOperation('');
    setSelectedEndpointSnapshot(null);
    setSelectedRecording('');
    setCatalogMode('unmatched');
    setUnmatched([]); unmatchedRef.current = []; setUnmatchedCursor(null); setUnmatchedError('');
    unmatchedGeneration.current += 1; setUnmatchedBusy(false);
    detailGeneration.current += 1; setDetailBusy(false); setDetailError('');
    detailRef.current = null; setDetail(null); setSelectedEvent(0);
    setOlderEventsReleased(false);
    setOlderUnmatchedReleased(false);
    void loadUnmatched();
  }

  function backToEndpoints() {
    linkedGeneration.current += 1; setLinkedBusy(false); setLinkedError('');
    unmatchedGeneration.current += 1; setUnmatchedBusy(false); setUnmatchedError('');
    catalogModeRef.current = 'endpoints';
    selectedOperationRef.current = ''; selectedRecordingRef.current = '';
    setSelectedOperation(''); setSelectedEndpointSnapshot(null); setSelectedRecording(''); setCatalogMode('endpoints');
    setLinked([]); linkedRef.current = []; setLinkedCursor(null);
    detailGeneration.current += 1; setDetailBusy(false); setDetailError('');
    detailRef.current = null; setDetail(null); setSelectedEvent(0);
    setOlderEventsReleased(false);
    if (!endpointHasLoaded.current) void loadEndpoints();
  }

  const nextEndpoints = () => endpointCursor && void loadEndpoints(endpointCursor, true);
  const nextLinked = () => linkedCursor && selectedOperation && void loadLinked(selectedOperation, linkedCursor, true);
  const nextUnmatched = () => unmatchedCursor && void loadUnmatched(unmatchedCursor, true);
  const nextDetail = () => detail?.nextCursor && selectedRecording && void loadDetail(selectedRecording, detail.nextCursor, true);

  return <div className="shell">
    <header className="topbar">
      <div className="brand"><span className="brand-mark">X/</span><span>X-trace</span><span className="top-meta">local recording viewer</span></div>
      <div className="top-meta">experimental · read only</div>
    </header>
    <nav className="tabs" role="tablist" aria-label="Viewer panes" onKeyDown={(keyboard) => {
      if (keyboard.key !== 'ArrowRight' && keyboard.key !== 'ArrowLeft') return;
      keyboard.preventDefault();
      const panes = ['recordings', 'events', 'evidence'] as const;
      const direction = keyboard.key === 'ArrowRight' ? 1 : -1;
      const next = panes[(panes.indexOf(activePane) + direction + panes.length) % panes.length];
      setActivePane(next);
      document.getElementById(`${next}-tab`)?.focus();
    }}>
      {(['recordings', 'events', 'evidence'] as const).map((pane) => <button key={pane} role="tab" id={`${pane}-tab`} aria-controls={`${pane}-panel`} tabIndex={activePane === pane ? 0 : -1} className="pane-tab" aria-selected={activePane === pane} onClick={() => setActivePane(pane)}>{pane}</button>)}
    </nav>
    <main className="workspace">
      <section className="pane" role="tabpanel" id="recordings-panel" aria-labelledby="recordings-tab" data-active={activePane === 'recordings'} aria-label="Recordings">
        <div className="pane-head"><div><div className="eyebrow">Observed catalog</div><h1>{catalogMode === 'endpoints' ? 'Endpoints' : catalogMode === 'linked' ? 'Linked recordings' : 'Unmatched recordings'}</h1></div>
          <button className="button" onClick={() => catalogMode === 'endpoints' ? void loadEndpoints() : catalogMode === 'linked' ? void loadLinked(selectedOperation) : void loadUnmatched()} disabled={endpointBusy || linkedBusy || unmatchedBusy}>Refresh</button></div>
        {catalogMode === 'linked' ? <div className="catalog-back"><div className="catalog-actions"><button className="button" onClick={backToEndpoints}>← Observed endpoints</button><button className="button" onClick={openUnmatched}>Unmatched recordings</button></div><span>{selectedEndpoint?.method} {selectedEndpoint?.routeTemplate}</span><small>Component: {selectedEndpoint?.applicationComponent} · Binding: {selectedEndpoint?.binding}</small></div> : null}
        {catalogMode === 'endpoints' ? <>
          <div className="catalog-switch"><button className="button" aria-current="page">Observed endpoints</button><button className="button" onClick={openUnmatched}>Unmatched recordings</button></div>
          <div className="policy-note"><strong>Operator-selected policy</strong><span>{endpoints[0]?.observationPolicy ?? 'spring-orders-v1'} does not attest which adapter or application produced the event.</span></div>
          {endpointBusy && endpoints.length === 0 ? <div className="loading">Reading observed endpoints…</div> : null}
          {endpointError ? <ErrorState message={endpointError} onRetry={() => void loadEndpoints()} /> : null}
          {!endpointBusy && !endpointError && endpoints.length === 0 ? <div className="empty"><strong>No observed endpoints</strong><p>A persisted capture must include the exact operator-selected policy and approved route.</p></div> : null}
          <div className="recording-list endpoint-list">{endpoints.map((endpoint) => <button className="recording endpoint-card" key={endpoint.operationId} onClick={() => openEndpoint(endpoint)}>
            <span className="endpoint-method">{endpoint.method}</span><span><span className="recording-title">{endpoint.routeTemplate}</span><span className="recording-sub">Component: {endpoint.applicationComponent}<br />Binding: {endpoint.binding}</span><span className="recording-status">observed</span></span>
          </button>)}</div>
          {endpointCursor ? <div className="page-controls"><span className="top-meta">More endpoints</span><button className="button" onClick={nextEndpoints} disabled={endpointBusy}>Load next page</button></div> : null}
        </> : null}
        {catalogMode === 'linked' ? <>
          <div className="policy-note"><strong>Operator-selected policy</strong><span>{selectedEndpoint?.observationPolicy ?? 'spring-orders-v1'} does not attest which adapter or application produced the event.</span></div>
          {linkedBusy && linked.length === 0 ? <div className="loading">Reading linked recordings…</div> : null}
          {linkedError ? <ErrorState message={linkedError} onRetry={() => void loadLinked(selectedOperation)} /> : null}
          {!linkedBusy && !linkedError && linked.length === 0 ? <div className="empty"><strong>No linked recordings</strong><p>This endpoint has no persisted linked recording in the current page.</p></div> : null}
          <RecordingRows items={linked} selected={selectedRecording} onSelect={selectRecording} />
          {linkedCursor ? <div className="page-controls"><span className="top-meta">More linked recordings</span><button className="button" onClick={nextLinked} disabled={linkedBusy}>Load next page</button></div> : null}
        </> : null}
        {catalogMode === 'unmatched' ? <>
          <div className="catalog-switch"><button className="button" onClick={backToEndpoints}>Observed endpoints</button><button className="button" aria-current="page">Unmatched recordings</button></div>
          <div className="context-note unmatched-note">These recordings have no observed endpoint association. A historical recording may have no reason code.</div>
          {unmatchedBusy && unmatched.length === 0 ? <div className="loading">Reading unmatched recordings…</div> : null}
          {unmatchedError ? <ErrorState message={unmatchedError} onRetry={() => void loadUnmatched()} /> : null}
          {!unmatchedBusy && !unmatchedError && unmatched.length === 0 ? <div className="empty"><strong>No unmatched recordings</strong><p>Unlinked and legacy recordings appear here.</p></div> : null}
          <RecordingRows items={unmatched} selected={selectedRecording} onSelect={selectRecording} />
          {unmatchedCursor ? <div className="page-controls"><span className="top-meta">More unmatched recordings</span><button className="button" onClick={nextUnmatched} disabled={unmatchedBusy}>Load next page</button></div> : null}
        </> : null}
        {(catalogMode === 'endpoints' ? olderEndpointsReleased : catalogMode === 'linked' ? olderLinkedReleased : olderUnmatchedReleased) ? <p className="window-retention" role="status">Earlier rows were released from memory. Continue from the current page cursor.</p> : null}
        <aside className="context-note">Only persisted endpoint and recording evidence is shown. No handler discovery or application attestation is implied.</aside>
      </section>
      <section className="pane" role="tabpanel" id="events-panel" aria-labelledby="events-tab" data-active={activePane === 'events'} aria-label="Ordered event window">
        <div className="pane-head center-head"><div className="center-title"><div className="eyebrow">Linear event window</div><h1>{selectedRecording || 'Select a recording'}</h1></div><button className="button" onClick={() => selectedRecording && void loadDetail(selectedRecording)} disabled={detailBusy}>Refresh</button></div>
        {detailError ? <ErrorState message={detailError} onRetry={() => selectedRecording && void loadDetail(selectedRecording)} /> : null}
        {!selectedRecording && !detailError ? <div className="empty"><strong>No recording selected</strong><p>Choose a linked or unmatched recording from the left pane.</p></div> : null}
        {detailBusy && !detail ? <div className="loading">Verifying persisted event window…</div> : null}
        {detail && detail.events.length === 0 ? <div className="empty"><strong>No projected events</strong><p>The persisted recording has no event window to display.</p></div> : null}
        {detail && detail.events.length ? <div className="event-rail">
          <div className="window-note"><span>{detail.events.length} ordered events</span><span>ALT + ↑ / ↓ to step</span></div>
          {detail.events.map((item, index) => <button key={`${item.sequence}-${index}`} className={`event ${item.kind.toLowerCase().endsWith(':gap') || item.kind.toLowerCase() === 'gap' ? 'gap-event' : ''}`} aria-current={index === selectedEvent} onClick={() => { setSelectedEvent(index); setActivePane('evidence'); setAnnouncement(`Event ${item.sequence} selected`); }}>
            <span className="event-seq">{item.sequence}</span><span className="event-copy"><span className="event-kind" title={item.kind}>{item.kind}</span><span className="event-symbol">{item.symbol || 'No symbol persisted'}</span></span><span className="event-time">{item.monotonicNs} ns</span>
          </button>)}
        </div> : null}
        {olderEventsReleased ? <p className="window-retention" role="status">Earlier events were released from memory. Continue from the current event cursor.</p> : null}
        {detail?.nextCursor ? <div className="page-controls"><span className="top-meta">More events in verified window</span><button className="button button-primary" onClick={nextDetail} disabled={detailBusy}>Load next window</button></div> : null}
      </section>
      <section className="pane" role="tabpanel" id="evidence-panel" aria-labelledby="evidence-tab" data-active={activePane === 'evidence'} aria-label="Evidence inspector">
        <div className="pane-head"><div><div className="eyebrow">Persisted facts</div><h1>Evidence inspector</h1></div><span className="top-meta">{currentStatus}</span></div>
        <div className="inspector">
          {event ? <>
            <div className="inspector-section"><div className="inspector-label">Event identity</div><div className="inspector-value mono">{event.eventId || 'Unavailable'}</div></div>
            <div className="inspector-section"><div className="inspector-label">Relationships</div><div className="inspector-value">Parent: <span className="mono">{event.parentEventId || 'Unavailable'}</span></div><div className="inspector-value">Async parent: <span className="mono">{event.asyncParentEventId || 'Unavailable'}</span></div></div>
            <div className="inspector-section"><div className="inspector-label">Persisted interaction</div>{event.interaction ? Object.entries(event.interaction).filter(([, value]) => value).map(([key, value]) => <div className="inspector-value" key={key}>{key}: <span className="mono">{value}</span></div>) : <div className="inspector-value">No interaction fields persisted</div>}</div>
            {event.fieldTruncations.map((item) => <div key={item.field} className="evidence-state">{item.field} {item.representation} · {item.originalBytes} bytes</div>)}
            {detail?.incompleteEvidence.map((item, index) => <div key={`${item}-${index}`} className="evidence-state">Persisted incomplete evidence: {item}</div>)}
            <div className="inspector-section"><div className="inspector-label">Unavailable for this capture</div><div className="evidence-state">Source unavailable for this capture</div><div className="evidence-state">Values were not projected</div><div className="evidence-state">Completion semantics unavailable</div></div>
            <div className="inspector-section"><div className="inspector-label">Timing</div><div className="inspector-value">Monotonic timestamp: <span className="mono">{event.monotonicNs} ns</span></div><div className="evidence-state">Duration unavailable for this capture</div></div>
            <div className="page-controls"><button className="button" onClick={() => moveEvent(-1)} disabled={selectedEvent <= 0}>Previous</button><button className="button" onClick={() => moveEvent(1)} disabled={selectedEvent >= eventCount - 1}>Next</button></div>
          </> : <div className="empty"><strong>Select an event</strong><p>Event selection synchronizes this evidence inspector.</p></div>}
        </div>
      </section>
    </main>
    <div className="sr-only" role="status" aria-live="polite">{announcement}</div>
    {auth === 'checking' ? <div className="sr-only" role="status">Authenticating viewer link</div> : null}
    {auth === 'expired' ? <div role="alert" className="auth-overlay"><div><strong>Viewer session expired</strong><p>Restart the foreground viewer to create a new one-time link.</p></div></div> : null}
    {auth === 'error' ? <div role="alert" className="auth-overlay"><div><strong>Viewer authentication failed</strong><p>{authError}</p></div></div> : null}
  </div>;
}

function RecordingRows({ items, selected, onSelect }: { items: Recording[]; selected: string; onSelect: (id: string) => void }) {
  return <div className="recording-list">{items.map((recording) => <button className="recording" key={recording.recordingId} aria-current={selected === recording.recordingId} onClick={() => onSelect(recording.recordingId)}>
    <span className={`status-mark status-mark--${recording.status}`} aria-hidden="true" />
    <span><span className="recording-title">{recording.recordingId}</span><span className="recording-sub">{recording.eventCount} persisted events · {recording.openedAt}</span><span className="recording-status">{recording.status}</span>{recording.unmatchedReason ? <span className="recording-reason">{recording.unmatchedReason}</span> : recording.operationId === null ? <span className="recording-reason">No historical reason recorded</span> : null}</span>
  </button>)}</div>;
}

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <div className="message error-state" role="alert"><strong>Could not load persisted evidence</strong><p>{message}</p><button className="button" onClick={onRetry}>Retry</button></div>;
}
