import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import type { components } from './api.generated';
import { api, ApiError, failureMessage } from './api';
import { AppShell } from './app-shell';
import { CatalogPanel } from './features/catalog/CatalogPanel';
import { EventsPanel } from './features/events/EventsPanel';
import { EvidencePanel } from './features/evidence/EvidencePanel';
import { retainPage } from './retained-page';
import { initialReplayState, replayReducer } from './replay/state';
import type { NavAction } from './replay/navigation';
import { useLane } from './state/lane';
import { MAX_RETAINED_EVENTS, MAX_RETAINED_ROWS } from './types';
import type { AuthState, CatalogMode, Detail, Endpoint, Pane, Recording } from './types';
import './style.css';

/** Read-only local browser for bounded observed endpoints and persisted recordings. */
export default function App() {
  const [auth, setAuth] = useState<AuthState>('checking');
  const [authError, setAuthError] = useState('');
  const [replay, dispatchReplay] = useReducer(replayReducer, initialReplayState);
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
  const endpointLane = useLane();
  const linkedLane = useLane();
  const unmatchedLane = useLane();
  const detailLane = useLane();

  useEffect(() => { endpointsRef.current = endpoints; }, [endpoints]);
  useEffect(() => { linkedRef.current = linked; }, [linked]);
  useEffect(() => { unmatchedRef.current = unmatched; }, [unmatched]);
  useEffect(() => { detailRef.current = detail; }, [detail]);

  const markExpired = (error: unknown) => {
    if (!(error instanceof ApiError) || error.status !== 401) return;
    endpointLane.invalidate(); linkedLane.invalidate();
    unmatchedLane.invalidate(); detailLane.invalidate();
    setEndpointBusy(false); setLinkedBusy(false); setUnmatchedBusy(false); setDetailBusy(false);
    setAuth('expired');
  };

  const loadEndpoints = useCallback(async (cursor: string | null = null, append = false) => {
    const { generation, signal } = endpointLane.begin();
    setEndpointBusy(true);
    setEndpointError('');
    try {
      const query = cursor ? `?limit=100&cursor=${encodeURIComponent(cursor)}` : '?limit=100';
      const page = await api<components['schemas']['ObservedEndpointPage']>(`/api/v1/endpoints${query}`, signal);
      if (!endpointLane.isCurrent(generation)) return;
      const result = retainPage(append ? endpointsRef.current : [], page.items, MAX_RETAINED_ROWS, page.nextCursor);
      endpointsRef.current = result.items;
      setEndpoints(result.items);
      setEndpointCursor(result.nextCursor);
      setOlderEndpointsReleased(result.released > 0);
      endpointHasLoaded.current = true;
      if (catalogModeRef.current === 'endpoints') setAnnouncement(`${page.items.length} observed endpoints loaded`);
    } catch (error) {
      if (!endpointLane.isCurrent(generation)) return;
      markExpired(error);
      setEndpointError(failureMessage(error));
    } finally {
      if (endpointLane.isCurrent(generation)) {
        setEndpointBusy(false);
      }
    }
  }, []);

  const loadLinked = useCallback(async (operationId: string, cursor: string | null = null, append = false) => {
    if (!operationId || selectedOperationRef.current !== operationId) return;
    const { generation, signal } = linkedLane.begin();
    setLinkedBusy(true);
    setLinkedError('');
    try {
      const query = cursor ? `?limit=50&cursor=${encodeURIComponent(cursor)}` : '?limit=50';
      const page = await api<components['schemas']['ObservedRecordingPage']>(`/api/v1/endpoints/${encodeURIComponent(operationId)}/recordings${query}`, signal);
      if (!linkedLane.isCurrent(generation) || selectedOperationRef.current !== operationId) return;
      const result = retainPage(append ? linkedRef.current : [], page.items, MAX_RETAINED_ROWS, page.nextCursor);
      linkedRef.current = result.items;
      setLinked(result.items);
      setLinkedCursor(result.nextCursor);
      setOlderLinkedReleased(result.released > 0);
      if (catalogModeRef.current === 'linked') setAnnouncement(`${page.items.length} linked recordings loaded`);
    } catch (error) {
      if (!linkedLane.isCurrent(generation) || selectedOperationRef.current !== operationId) return;
      markExpired(error);
      setLinkedError(failureMessage(error));
    } finally {
      if (linkedLane.isCurrent(generation) && selectedOperationRef.current === operationId) {
        setLinkedBusy(false);
      }
    }
  }, []);

  const loadUnmatched = useCallback(async (cursor: string | null = null, append = false) => {
    const { generation, signal } = unmatchedLane.begin();
    setUnmatchedBusy(true);
    setUnmatchedError('');
    try {
      const query = cursor ? `?unmatched=true&limit=50&cursor=${encodeURIComponent(cursor)}` : '?unmatched=true&limit=50';
      const page = await api<components['schemas']['ObservedRecordingPage']>(`/api/v1/recordings${query}`, signal);
      if (!unmatchedLane.isCurrent(generation)) return;
      const result = retainPage(append ? unmatchedRef.current : [], page.items, MAX_RETAINED_ROWS, page.nextCursor);
      unmatchedRef.current = result.items;
      setUnmatched(result.items);
      setUnmatchedCursor(result.nextCursor);
      setOlderUnmatchedReleased(result.released > 0);
      if (catalogModeRef.current === 'unmatched') setAnnouncement(`${page.items.length} unmatched recordings loaded`);
    } catch (error) {
      if (!unmatchedLane.isCurrent(generation)) return;
      markExpired(error);
      setUnmatchedError(failureMessage(error));
    } finally {
      if (unmatchedLane.isCurrent(generation)) {
        setUnmatchedBusy(false);
      }
    }
  }, []);

  const loadDetail = useCallback(async (recordingId: string, cursor: string | null = null, append = false) => {
    if (!recordingId || selectedRecordingRef.current !== recordingId) return;
    const { generation, signal } = detailLane.begin();
    setDetailBusy(true);
    setDetailError('');
    try {
      const query = cursor ? `?limit=200&cursor=${encodeURIComponent(cursor)}` : '?limit=200';
      const next = await api<Detail>(`/api/v1/recordings/${encodeURIComponent(recordingId)}${query}`, signal);
      if (!detailLane.isCurrent(generation) || selectedRecordingRef.current !== recordingId) return;
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
      if (!detailLane.isCurrent(generation) || selectedRecordingRef.current !== recordingId) return;
      markExpired(error);
      setDetailError(failureMessage(error));
    } finally {
      if (detailLane.isCurrent(generation) && selectedRecordingRef.current === recordingId) {
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
      detailLane.invalidate();
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
    endpointLane.invalidate(); setEndpointBusy(false);
    unmatchedLane.invalidate(); setUnmatchedBusy(false); setUnmatchedError('');
    catalogModeRef.current = 'linked';
    selectedOperationRef.current = endpoint.operationId;
    selectedRecordingRef.current = '';
    setSelectedOperation(endpoint.operationId);
    setSelectedEndpointSnapshot(endpoint);
    setSelectedRecording('');
    setCatalogMode('linked');
    setLinked([]); linkedRef.current = []; setLinkedCursor(null); setLinkedError('');
    linkedLane.invalidate(); setLinkedBusy(false);
    detailLane.invalidate(); setDetailBusy(false); setDetailError('');
    detailRef.current = null; setDetail(null); setSelectedEvent(0);
    setOlderEventsReleased(false);
    setOlderLinkedReleased(false);
    void loadLinked(endpoint.operationId);
  }

  function openUnmatched() {
    endpointLane.invalidate(); setEndpointBusy(false); setEndpointError('');
    linkedLane.invalidate(); setLinkedBusy(false); setLinkedError('');
    catalogModeRef.current = 'unmatched';
    selectedOperationRef.current = '';
    selectedRecordingRef.current = '';
    setSelectedOperation('');
    setSelectedEndpointSnapshot(null);
    setSelectedRecording('');
    setCatalogMode('unmatched');
    setUnmatched([]); unmatchedRef.current = []; setUnmatchedCursor(null); setUnmatchedError('');
    unmatchedLane.invalidate(); setUnmatchedBusy(false);
    detailLane.invalidate(); setDetailBusy(false); setDetailError('');
    detailRef.current = null; setDetail(null); setSelectedEvent(0);
    setOlderEventsReleased(false);
    setOlderUnmatchedReleased(false);
    void loadUnmatched();
  }

  function backToEndpoints() {
    linkedLane.invalidate(); setLinkedBusy(false); setLinkedError('');
    unmatchedLane.invalidate(); setUnmatchedBusy(false); setUnmatchedError('');
    catalogModeRef.current = 'endpoints';
    selectedOperationRef.current = ''; selectedRecordingRef.current = '';
    setSelectedOperation(''); setSelectedEndpointSnapshot(null); setSelectedRecording(''); setCatalogMode('endpoints');
    setLinked([]); linkedRef.current = []; setLinkedCursor(null);
    detailLane.invalidate(); setDetailBusy(false); setDetailError('');
    detailRef.current = null; setDetail(null); setSelectedEvent(0);
    setOlderEventsReleased(false);
    if (!endpointHasLoaded.current) void loadEndpoints();
  }

  const nextEndpoints = () => endpointCursor && void loadEndpoints(endpointCursor, true);
  const nextLinked = () => linkedCursor && selectedOperation && void loadLinked(selectedOperation, linkedCursor, true);
  const nextUnmatched = () => unmatchedCursor && void loadUnmatched(unmatchedCursor, true);
  const nextDetail = () => detail?.nextCursor && selectedRecording && void loadDetail(selectedRecording, detail.nextCursor, true);

  const refreshCatalog = () => catalogMode === 'endpoints' ? void loadEndpoints() : catalogMode === 'linked' ? void loadLinked(selectedOperation) : void loadUnmatched();
  const refreshDetail = () => selectedRecording && void loadDetail(selectedRecording);
  const pickEvent = (index: number) => {
    setSelectedEvent(index);
    setActivePane('evidence');
    setAnnouncement(`Event ${detail?.events[index]?.sequence ?? ''} selected`);
  };

  const navigateToFrame = (action: string, frameId: string) => {
    const index = detail?.events.findIndex((item) => item.frameId === frameId) ?? -1;
    if (index < 0) {
      setAnnouncement(`${action}: the target frame is outside the loaded window. Load more events to reach it; paging backward is not available yet.`);
      return;
    }
    setSelectedEvent(index);
    setAnnouncement(`Selected event ${detail?.events[index]?.sequence ?? ''}`);
  };

  const selectFrame = (frameId: string) => navigateToFrame('select', frameId);
  const navigateKey = (action: NavAction) => {
    const result = (event?.navigation as Partial<Record<NavAction, { state: string; frameId?: string }>> | undefined)?.[action];
    if (result?.state === 'target' && result.frameId) navigateToFrame(action, result.frameId);
    else setAnnouncement(`${action}: ${result?.state === 'boundary' ? 'boundary, no further frame in this direction' : 'unavailable for this frame'}`);
  };

  return <AppShell activePane={activePane} onPane={setActivePane} announcement={announcement} auth={auth} authError={authError}>
    <CatalogPanel
      active={activePane === 'recordings'}
      catalogMode={catalogMode}
      endpointLane={{ items: endpoints, cursor: endpointCursor, busy: endpointBusy, error: endpointError, released: olderEndpointsReleased }}
      linkedLane={{ items: linked, cursor: linkedCursor, busy: linkedBusy, error: linkedError, released: olderLinkedReleased }}
      unmatchedLane={{ items: unmatched, cursor: unmatchedCursor, busy: unmatchedBusy, error: unmatchedError, released: olderUnmatchedReleased }}
      selectedEndpoint={selectedEndpoint}
      selectedRecording={selectedRecording}
      onRefresh={refreshCatalog}
      onRetryEndpoints={() => void loadEndpoints()}
      onRetryLinked={() => void loadLinked(selectedOperation)}
      onRetryUnmatched={() => void loadUnmatched()}
      onNextEndpoints={nextEndpoints}
      onNextLinked={nextLinked}
      onNextUnmatched={nextUnmatched}
      onOpenEndpoint={openEndpoint}
      onOpenUnmatched={openUnmatched}
      onBack={backToEndpoints}
      onSelectRecording={selectRecording}
    />
    <EventsPanel
      active={activePane === 'events'}
      selectedRecording={selectedRecording}
      detail={detail}
      detailBusy={detailBusy}
      detailError={detailError}
      selectedEvent={selectedEvent}
      olderEventsReleased={olderEventsReleased}
      onRefresh={refreshDetail}
      onPickEvent={pickEvent}
      onNextWindow={nextDetail}
      mode={replay.mode}
      onMode={(mode) => dispatchReplay({ type: 'set-mode', mode })}
      onSelectFrame={selectFrame}
      onNavigateKey={navigateKey}
    />
    <EvidencePanel active={activePane === 'evidence'} currentStatus={currentStatus} detail={detail} event={event} selectedEvent={selectedEvent} eventCount={eventCount} onMoveEvent={moveEvent} onNavigate={navigateToFrame} />
  </AppShell>;
}
