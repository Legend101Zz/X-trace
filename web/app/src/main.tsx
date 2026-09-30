import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { components } from './api.generated';
import { retainPage } from './retained-page';
import './style.css';

type Recording = components['schemas']['Recording'];
type Page = components['schemas']['RecordingList'];
type Detail = components['schemas']['RecordingDetail'];
type Problem = components['schemas']['Problem'];

const MAX_RETAINED_RECORDINGS = 500;
const MAX_RETAINED_EVENTS = 2_000;

async function api<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'X-XTrace-Client': 'viewer-v1' },
  });
  if (!response.ok) {
    const problem = (await response.json().catch(() => null)) as Problem | null;
    const error = new Error(problem?.detail ?? `Request failed (${response.status})`);
    Object.assign(error, { status: response.status, requestId: problem?.requestId });
    throw error;
  }
  return (await response.json()) as T;
}

export default function App() {
  const [auth, setAuth] = useState<'checking' | 'ready' | 'expired' | 'error'>('checking');
  const [authError, setAuthError] = useState('');
  const [recordings, setRecordings] = useState<Recording[]>([]);
  const [selectedRecording, setSelectedRecording] = useState('');
  const [detail, setDetail] = useState<Detail | null>(null);
  const [selectedEvent, setSelectedEvent] = useState(0);
  const [listCursor, setListCursor] = useState<string | null>(null);
  const [olderRecordingsReleased, setOlderRecordingsReleased] = useState(false);
  const [olderEventsReleased, setOlderEventsReleased] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activePane, setActivePane] = useState<'recordings' | 'events' | 'evidence'>('events');
  const [announcement, setAnnouncement] = useState('');
  const authStarted = useRef(false);
  const recordingsRef = useRef<Recording[]>([]);
  const detailRef = useRef<Detail | null>(null);
  const selectedRecordingRef = useRef('');
  const listRequestGeneration = useRef(0);
  const detailRequestGeneration = useRef(0);
  const listRequestActive = useRef(false);
  const detailRequestActive = useRef(false);

  useEffect(() => { recordingsRef.current = recordings; }, [recordings]);
  useEffect(() => { detailRef.current = detail; }, [detail]);

  const loadList = useCallback(async (cursor: string | null = null, append = false) => {
    const generation = ++listRequestGeneration.current;
    listRequestActive.current = true;
    setLoading(true); setError('');
    try {
      const page = await api<Page>(`/api/v1/recordings?limit=50${cursor ? `&after=${encodeURIComponent(cursor)}` : ''}`);
      if (generation !== listRequestGeneration.current) return;
      const { items: retained, released, nextCursor } = retainPage(
        append ? recordingsRef.current : [],
        page.recordings,
        MAX_RETAINED_RECORDINGS,
        page.nextAfter ?? null,
      );
      recordingsRef.current = retained;
      setRecordings(retained);
      if (released > 0) setOlderRecordingsReleased(true);
      else if (!append) setOlderRecordingsReleased(false);
      if (page.recordings.length && !selectedRecordingRef.current) {
        selectedRecordingRef.current = page.recordings[0].recordingId;
        setSelectedRecording(selectedRecordingRef.current);
      }
      setListCursor(nextCursor);
      setAnnouncement(released > 0
        ? `Earlier recording rows were released. ${retained.length} recordings remain in the current window.`
        : `${page.recordings.length} recordings loaded`);
    } catch (cause) {
      if (generation !== listRequestGeneration.current) return;
      const status = (cause as Error & { status?: number }).status;
      if (status === 401) setAuth('expired');
      else setError(cause instanceof Error ? cause.message : 'Recordings could not be loaded');
    } finally {
      if (generation === listRequestGeneration.current) {
        listRequestActive.current = false;
        setLoading(detailRequestActive.current);
      }
    }
  }, []);

  const loadDetail = useCallback(async (recordingId: string, cursor: string | null = null, append = false) => {
    if (!recordingId || selectedRecordingRef.current !== recordingId) return;
    const generation = ++detailRequestGeneration.current;
    detailRequestActive.current = true;
    setLoading(true); setError('');
    try {
      const query = cursor ? `?limit=200&cursor=${encodeURIComponent(cursor)}` : '?limit=200';
      const next = await api<Detail>(`/api/v1/recordings/${encodeURIComponent(recordingId)}${query}`);
      if (generation !== detailRequestGeneration.current || selectedRecordingRef.current !== recordingId) return;
      const previous = append ? detailRef.current : null;
      const { items: retained, released, nextCursor } = retainPage(
        previous?.events ?? [],
        next.events,
        MAX_RETAINED_EVENTS,
        next.nextCursor ?? null,
      );
      const updated = { ...next, events: retained, nextCursor };
      detailRef.current = updated;
      setDetail(updated);
      if (released > 0) setOlderEventsReleased(true);
      else if (!append) setOlderEventsReleased(false);
      if (!append) setSelectedEvent(0);
      else if (released > 0) {
        setSelectedEvent((current) => Math.max(0, current - released));
      }
      setAnnouncement(released > 0
        ? `Earlier events were released. ${retained.length} events remain in the current window.`
        : `${next.events.length} events available for selection`);
    } catch (cause) {
      if (generation !== detailRequestGeneration.current || selectedRecordingRef.current !== recordingId) return;
      const status = (cause as Error & { status?: number }).status;
      if (status === 401) setAuth('expired');
      else setError(cause instanceof Error ? cause.message : 'Recording could not be loaded');
    } finally {
      if (generation === detailRequestGeneration.current) {
        detailRequestActive.current = false;
        setLoading(listRequestActive.current);
      }
    }
  }, []);

  useEffect(() => {
    if (authStarted.current) return;
    authStarted.current = true;
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const token = fragment.get('token');
    if (!token) { setAuth('error'); setAuthError('The one-time viewer link is missing. Restart xtrace open --viewer.'); return; }
    window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    void fetch('/api/v1/auth/exchange', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-XTrace-Client': 'viewer-v1' },
      body: JSON.stringify({ token }),
    }).then(async (response) => {
      if (!response.ok) throw new Error('Viewer link is invalid or expired. Restart xtrace open --viewer.');
      setAuth('ready');
      await loadList();
    }).catch((cause: unknown) => {
      setAuth('error'); setAuthError(cause instanceof Error ? cause.message : 'Viewer authentication failed');
    });
  }, [loadList]);

  useEffect(() => {
    if (auth === 'ready' && selectedRecording) {
      void loadDetail(selectedRecording);
    } else {
      detailRequestGeneration.current += 1;
      detailRequestActive.current = false;
      setLoading(listRequestActive.current);
      detailRef.current = null;
      setDetail(null);
    }
  }, [auth, selectedRecording, loadDetail]);

  const event = detail?.events[selectedEvent];
  const currentRecording = recordings.find((item) => item.recordingId === selectedRecording);
  const currentStatus = currentRecording?.status
    ?? (detail?.recordingId === selectedRecording ? detail.status : 'no selection');
  const eventCount = useMemo(() => detail?.events.length ?? 0, [detail]);

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
      if (keyboard.altKey && keyboard.key === 'ArrowDown') { keyboard.preventDefault(); moveEvent(1); }
      if (keyboard.altKey && keyboard.key === 'ArrowUp') { keyboard.preventDefault(); moveEvent(-1); }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [moveEvent]);

  const nextListPage = () => {
    if (!listCursor) return;
    void loadList(listCursor, true);
  };
  const nextDetailPage = () => {
    if (!detail?.nextCursor || !selectedRecording) return;
    void loadDetail(selectedRecording, detail.nextCursor ?? null, true);
  };

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
      const current = panes.indexOf(activePane);
      const next = panes[(current + direction + panes.length) % panes.length];
      setActivePane(next);
      document.getElementById(`${next}-tab`)?.focus();
    }}>
      {(['recordings', 'events', 'evidence'] as const).map((pane) => <button key={pane} role="tab" id={`${pane}-tab`} aria-controls={`${pane}-panel`} tabIndex={activePane === pane ? 0 : -1} className="pane-tab" aria-selected={activePane === pane} onClick={() => setActivePane(pane)}>{pane}</button>)}
    </nav>
    <main className="workspace">
      <section className="pane" role="tabpanel" id="recordings-panel" aria-labelledby="recordings-tab" data-active={activePane === 'recordings'} aria-label="Recordings">
        <div className="pane-head"><div><div className="eyebrow">Project recordings</div><h1>Captured requests</h1></div><button className="button" onClick={() => { recordingsRef.current = []; setRecordings([]); setListCursor(null); setOlderRecordingsReleased(false); void loadList(); }}>Refresh</button></div>
        {loading && recordings.length === 0 ? <div className="loading">Reading persisted recordings…</div> : null}
        {error ? <ErrorState message={error} onRetry={() => void loadList()} /> : null}
        {!loading && !error && recordings.length === 0 ? <div className="empty"><strong>No recordings yet</strong><p>Run a Spring application through X-trace and send a request to create persisted evidence.</p></div> : null}
        <div className="recording-list">
          {recordings.map((recording) => <button className="recording" key={recording.recordingId} aria-current={selectedRecording === recording.recordingId} onClick={() => {
            const changed = selectedRecordingRef.current !== recording.recordingId;
            selectedRecordingRef.current = recording.recordingId;
            if (changed) {
              detailRequestGeneration.current += 1;
              detailRequestActive.current = false;
              detailRef.current = null;
              setDetail(null);
              setSelectedEvent(0);
              setLoading(listRequestActive.current);
              setError('');
              setSelectedRecording(recording.recordingId);
            }
            setActivePane('events');
            setAnnouncement(`Recording ${recording.recordingId} selected`);
          }}>
            <span className={`status-mark status-mark--${recording.status}`} aria-hidden="true" />
            <span><span className="recording-title">{recording.recordingId}</span><span className="recording-sub">{recording.eventCount} persisted events · {recording.openedAt}</span><span className="recording-status">{recording.status}</span></span>
          </button>)}
        </div>
        {olderRecordingsReleased ? <p className="window-retention" role="status">Earlier recordings were released from memory. Continue from the current page cursor.</p> : null}
        {listCursor ? <div className="page-controls"><span className="top-meta">More recordings</span><button className="button" onClick={nextListPage} disabled={loading}>Load next page</button></div> : null}
        <aside className="context-note">Only persisted recording evidence is shown. This view does not infer endpoints or execution results.</aside>
      </section>
      <section className="pane" role="tabpanel" id="events-panel" aria-labelledby="events-tab" data-active={activePane === 'events'} aria-label="Ordered event window">
        <div className="pane-head center-head"><div className="center-title"><div className="eyebrow">Linear event window</div><h1>{selectedRecording || 'Select a recording'}</h1></div><button className="button" onClick={() => selectedRecording && void loadDetail(selectedRecording)}>Refresh</button></div>
        {error ? <ErrorState message={error} onRetry={() => selectedRecording && void loadDetail(selectedRecording)} /> : null}
        {!selectedRecording && !error ? <div className="empty"><strong>No recording selected</strong><p>Choose a persisted recording from the left pane.</p></div> : null}
        {loading && !detail ? <div className="loading">Verifying persisted event window…</div> : null}
        {detail && detail.events.length === 0 ? <div className="empty"><strong>No projected events</strong><p>The persisted recording has no event window to display.</p></div> : null}
        {detail && detail.events.length ? <div className="event-rail">
          <div className="window-note"><span>{detail.events.length} ordered events</span><span>ALT + ↑ / ↓ to step</span></div>
          {detail.events.map((item, index) => <button key={`${item.sequence}-${index}`} className={`event ${item.kind.toLowerCase().endsWith(':gap') || item.kind.toLowerCase() === 'gap' ? 'gap-event' : ''}`} aria-current={index === selectedEvent} onClick={() => { setSelectedEvent(index); setActivePane('evidence'); setAnnouncement(`Event ${item.sequence} selected`); }}>
            <span className="event-seq">{item.sequence}</span><span className="event-copy"><span className="event-kind" title={item.kind}>{item.kind}</span><span className="event-symbol">{item.symbol || 'No symbol persisted'}</span></span><span className="event-time">{item.monotonicNs} ns</span>
          </button>)}
        </div> : null}
        {olderEventsReleased ? <p className="window-retention" role="status">Earlier events were released from memory. Continue from the current event cursor.</p> : null}
        {detail?.nextCursor ? <div className="page-controls"><span className="top-meta">More events in verified window</span><button className="button button-primary" onClick={nextDetailPage} disabled={loading}>Load next window</button></div> : null}
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

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <div className="message error-state" role="alert"><strong>Could not load persisted evidence</strong><p>{message}</p><button className="button" onClick={onRetry}>Retry</button></div>;
}
