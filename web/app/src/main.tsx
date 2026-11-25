import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import type { components } from './api.generated';
import { api, ApiError, failureMessage } from './api';
import { AppShell } from './app-shell';
import { recentlyObserved } from './features/catalog/recording-arrivals';
import { CatalogPanel } from './features/catalog/CatalogPanel';
import type { OpenRecording } from './features/shell/RecordingTabs';
import { EventsPanel } from './features/events/EventsPanel';
import { EvidencePanel } from './features/evidence/EvidencePanel';
import { retainPage } from './retained-page';
import { initialReplayState, replayReducer } from './replay/state';
import { navigationControls } from './replay/navigation';
import type { NavAction, NavFrameNavigation } from './replay/navigation';
import { useLane } from './state/lane';
import { MAX_RETAINED_EVENTS, MAX_RETAINED_ROWS } from './types';
import type { AuthState, CatalogMode, Detail, Endpoint, Pane, Recording, ReplayEvent } from './types';
import './style.css';

interface TabSelection {
  frameId: string | null;
  sequence: string | null;
  cursor: string | null;
}

/** Read-only local browser for bounded observed endpoints and persisted recordings. */
export default function App() {
  const [auth, setAuth] = useState<AuthState>('checking');
  const [authError, setAuthError] = useState('');
  const [replay, dispatchReplay] = useReducer(replayReducer, initialReplayState);
  const selectedRecording = replay.recordingId;
  const [openRecordings, setOpenRecordings] = useState<OpenRecording[]>([]);
  const tabSelections = useRef(new Map<string, TabSelection>());
  // Only the active retained window is indexed. Inactive tabs hold one cursor and event identity each.
  const eventPageCursors = useRef(new Map<string, string | null>());
  const eventWindowStartCursor = useRef<string | null>(null);
  const [arrivals, setArrivals] = useState<ReadonlySet<string>>(new Set());
  const [selectedOperation, setSelectedOperation] = useState('');
  const [catalogMode, setCatalogMode] = useState<CatalogMode>('endpoints');
  const [activePane, setActivePane] = useState<Pane>('recordings');
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [endpointCursor, setEndpointCursor] = useState<string | null>(null);
  const [selectedEndpointSnapshot, setSelectedEndpointSnapshot] = useState<Endpoint | null>(null);
  const [linked, setLinked] = useState<Recording[]>([]);
  const [linkedCursor, setLinkedCursor] = useState<string | null>(null);
  const [unmatched, setUnmatched] = useState<Recording[]>([]);
  const [unmatchedCursor, setUnmatchedCursor] = useState<string | null>(null);
  const [detail, setDetail] = useState<Detail | null>(null);
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
  // Background checks refresh the first page only; a manually loaded continuation stays intact.
  const linkedFirstPage = useRef(false);
  const unmatchedFirstPage = useRef(false);
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
      if (!append && linkedFirstPage.current) {
        const observed = recentlyObserved(linkedRef.current, page.items);
        setArrivals((current) => new Set(page.items.filter((item) => current.has(item.recordingId) || observed.has(item.recordingId)).map((item) => item.recordingId)));
      }
      linkedFirstPage.current = !append;
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
    if (catalogModeRef.current !== 'unmatched') return;
    const { generation, signal } = unmatchedLane.begin();
    setUnmatchedBusy(true);
    setUnmatchedError('');
    try {
      const query = cursor ? `?unmatched=true&limit=50&cursor=${encodeURIComponent(cursor)}` : '?unmatched=true&limit=50';
      const page = await api<components['schemas']['ObservedRecordingPage']>(`/api/v1/recordings${query}`, signal);
      if (!unmatchedLane.isCurrent(generation) || catalogModeRef.current !== 'unmatched') return;
      if (!append && unmatchedFirstPage.current) {
        const observed = recentlyObserved(unmatchedRef.current, page.items);
        setArrivals((current) => new Set(page.items.filter((item) => current.has(item.recordingId) || observed.has(item.recordingId)).map((item) => item.recordingId)));
      }
      unmatchedFirstPage.current = !append;
      const result = retainPage(append ? unmatchedRef.current : [], page.items, MAX_RETAINED_ROWS, page.nextCursor);
      unmatchedRef.current = result.items;
      setUnmatched(result.items);
      setUnmatchedCursor(result.nextCursor);
      setOlderUnmatchedReleased(result.released > 0);
      if (catalogModeRef.current === 'unmatched') setAnnouncement(`${page.items.length} unmatched recordings loaded`);
    } catch (error) {
      if (!unmatchedLane.isCurrent(generation) || catalogModeRef.current !== 'unmatched') return;
      markExpired(error);
      setUnmatchedError(failureMessage(error));
    } finally {
      if (unmatchedLane.isCurrent(generation) && catalogModeRef.current === 'unmatched') {
        setUnmatchedBusy(false);
      }
    }
  }, []);

  const loadDetail = useCallback(async (recordingId: string, cursor: string | null = null, append = false) => {
    if (!recordingId || selectedRecordingRef.current !== recordingId) return;
    const { generation, signal } = detailLane.begin();
    if (!append) eventWindowStartCursor.current = cursor;
    setDetailBusy(true);
    setDetailError('');
    try {
      const query = cursor ? `?limit=200&cursor=${encodeURIComponent(cursor)}` : '?limit=200';
      const next = await api<Detail>(`/api/v1/recordings/${encodeURIComponent(recordingId)}${query}`, signal);
      if (!detailLane.isCurrent(generation) || selectedRecordingRef.current !== recordingId) return;
      if (next.recordingId !== recordingId) throw new Error('Recording detail identity mismatch');
      const previous = append ? detailRef.current : null;
      const result = retainPage(previous?.events ?? [], next.events, MAX_RETAINED_EVENTS, next.nextCursor ?? null);
      const incomingSequences = new Set(next.events.map((item) => item.sequence));
      const priorCursors = eventPageCursors.current;
      eventPageCursors.current = new Map(result.items.map((item) => [
        item.sequence, incomingSequences.has(item.sequence) ? cursor : priorCursors.get(item.sequence) ?? null,
      ]));
      const updated = { ...next, events: result.items, nextCursor: result.nextCursor };
      detailRef.current = updated;
      setDetail(updated);
      setOlderEventsReleased(result.released > 0);
      const first = result.items[0];
      if (first) dispatchReplay({ type: 'initialize-selection', recordingId, frameId: first.frameId ?? null, sequence: first.sequence });
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

  function activateRecording(recordingId: string, preserveOutgoing = true) {
    const previous = selectedRecordingRef.current;
    const changed = previous !== recordingId;
    if (changed && preserveOutgoing && previous) {
      const prior = tabSelections.current.get(previous);
      const cursor = replay.sequence !== null && eventPageCursors.current.has(replay.sequence)
        ? eventPageCursors.current.get(replay.sequence) ?? null
        : prior && prior.sequence === replay.sequence ? prior.cursor : null;
      tabSelections.current.set(previous, { frameId: replay.frameId, sequence: replay.sequence, cursor });
    }
    selectedRecordingRef.current = recordingId;
    const restore = tabSelections.current.get(recordingId);
    dispatchReplay({ type: 'select-recording', recordingId,
      restore: restore ? { frameId: restore.frameId, sequence: restore.sequence } : undefined });
    setActivePane(recordingId ? 'events' : 'recordings');
    if (changed) {
      detailLane.invalidate();
      eventPageCursors.current.clear();
      detailRef.current = null;
      setDetail(null);
      setDetailError('');
      setDetailBusy(false);
      setOlderEventsReleased(false);
      void loadDetail(recordingId, restore?.cursor);
    }
    setAnnouncement(recordingId ? `Recording ${recordingId} selected` : 'Recording tab closed');
  }

  function selectRecording(recordingId: string) {
    setArrivals((current) => new Set([...current].filter((id) => id !== recordingId)));
    setOpenRecordings((current) => current.some(({ id }) => id === recordingId)
      ? current
      : [...current, { id: recordingId, endpoint: catalogMode === 'linked' ? selectedEndpointSnapshot : null }]);
    activateRecording(recordingId);
  }

  function closeRecording(recordingId: string) {
    const index = openRecordings.findIndex(({ id }) => id === recordingId);
    if (index < 0) return;
    const remaining = openRecordings.filter(({ id }) => id !== recordingId);
    setOpenRecordings(remaining);
    tabSelections.current.delete(recordingId);
    const next = recordingId === selectedRecording ? remaining[Math.min(index, remaining.length - 1)]?.id ?? '' : selectedRecording;
    if (recordingId === selectedRecording) activateRecording(next, false);
    requestAnimationFrame(() => {
      if (next) document.getElementById(`open-recording-${next}`)?.focus();
      else {
        const search = document.getElementById('request-search');
        search?.focus();
        if (document.activeElement !== search) document.querySelector<HTMLElement>('.collapsed-panel--requests')?.focus();
      }
    });
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
  const activeRecordingTab = openRecordings.find(({ id }) => id === selectedRecording);
  const currentRows = catalogMode === 'linked' ? linked : unmatched;
  const currentRecording = currentRows.find((item) => item.recordingId === selectedRecording);
  const currentStatus = currentRecording?.status ?? (detail?.recordingId === selectedRecording ? detail.status : 'no selection');
  const eventCount = detail?.events.length ?? 0;
  // A refreshed window can move or omit the selected event without changing its identity.
  const selectedEvent = detail && detail.recordingId === selectedRecording && replay.sequence !== null
    ? detail.events.findIndex((item) => item.sequence === replay.sequence && (item.frameId ?? null) === replay.frameId)
    : -1;
  const event = detail?.events[selectedEvent];
  const selectionUnavailable = detail && replay.sequence !== null && selectedEvent < 0
    ? 'Selected event is not in the loaded window.'
    : null;

  const loadedFrameIds = useMemo(() => new Set((detail?.events ?? []).flatMap((item) => item.frameId ? [item.frameId] : [])), [detail]);
  const frameControls = useMemo(
    () => navigationControls(event?.navigation as NavFrameNavigation | undefined, loadedFrameIds),
    [event, loadedFrameIds],
  );
  const missingSelection = selectionUnavailable ?? 'Select an event first.';
  const backReason = selectedEvent < 0 ? missingSelection : selectedEvent === 0 ? 'No earlier event in the loaded window.' : null;
  const nextReason = selectedEvent < 0 ? missingSelection : selectedEvent === eventCount - 1
    ? detail?.nextCursor ? 'Load the next window to reach more events.' : 'No later event in the loaded window.'
    : null;

  const selectEvent = useCallback((recordingId: string, item: ReplayEvent) => {
    const frameId = item.frameId ?? null;
    tabSelections.current.set(recordingId, { frameId, sequence: item.sequence,
      cursor: eventPageCursors.current.get(item.sequence) ?? null });
    dispatchReplay({ type: 'select-frame', frameId, sequence: item.sequence });
  }, []);

  const moveEvent = useCallback((delta: -1 | 1) => {
    const reason = delta < 0 ? backReason : nextReason;
    if (reason) {
      setAnnouncement(reason);
      return;
    }
    if (!detail) return;
    const next = detail.events[selectedEvent + delta];
    if (!next) return;
    selectEvent(detail.recordingId, next);
    setAnnouncement(`Event ${next.sequence} selected`);
  }, [backReason, detail, nextReason, selectEvent, selectedEvent]);

  useEffect(() => {
    if (auth !== 'ready' || catalogMode === 'endpoints') return;
    const timer = window.setInterval(() => {
      if (document.visibilityState !== 'visible' || catalogModeRef.current !== catalogMode) return;
      if (!document.getElementById('request-search')?.getClientRects().length) return;
      if (catalogMode === 'linked' && linkedFirstPage.current && !linkedBusy) void loadLinked(selectedOperation);
      if (catalogMode === 'unmatched' && unmatchedFirstPage.current && !unmatchedBusy) void loadUnmatched();
    }, 15_000);
    return () => window.clearInterval(timer);
  }, [auth, catalogMode, linkedBusy, loadLinked, loadUnmatched, selectedOperation, unmatchedBusy]);

  function openEndpoint(endpoint: Endpoint) {
    endpointLane.invalidate(); setEndpointBusy(false);
    unmatchedLane.invalidate(); setUnmatchedBusy(false); setUnmatchedError('');
    catalogModeRef.current = 'linked';
    selectedOperationRef.current = endpoint.operationId;
    setSelectedOperation(endpoint.operationId);
    setSelectedEndpointSnapshot(endpoint);
    setCatalogMode('linked');
    setArrivals(new Set());
    setLinked([]); linkedRef.current = []; linkedFirstPage.current = false; setLinkedCursor(null); setLinkedError('');
    linkedLane.invalidate(); setLinkedBusy(false);
    setOlderLinkedReleased(false);
    void loadLinked(endpoint.operationId);
  }

  function openUnmatched() {
    endpointLane.invalidate(); setEndpointBusy(false); setEndpointError('');
    linkedLane.invalidate(); setLinkedBusy(false); setLinkedError('');
    catalogModeRef.current = 'unmatched';
    selectedOperationRef.current = '';
    setSelectedOperation('');
    setSelectedEndpointSnapshot(null);
    setCatalogMode('unmatched');
    setArrivals(new Set());
    setUnmatched([]); unmatchedRef.current = []; unmatchedFirstPage.current = false; setUnmatchedCursor(null); setUnmatchedError('');
    unmatchedLane.invalidate(); setUnmatchedBusy(false);
    setOlderUnmatchedReleased(false);
    void loadUnmatched();
  }

  function backToEndpoints() {
    linkedLane.invalidate(); setLinkedBusy(false); setLinkedError('');
    unmatchedLane.invalidate(); setUnmatchedBusy(false); setUnmatchedError('');
    catalogModeRef.current = 'endpoints';
    selectedOperationRef.current = '';
    setSelectedOperation('');
    setSelectedEndpointSnapshot(null); setCatalogMode('endpoints');
    setLinked([]); linkedRef.current = []; setLinkedCursor(null);
    if (!endpointHasLoaded.current) void loadEndpoints();
  }

  const nextEndpoints = () => endpointCursor && void loadEndpoints(endpointCursor, true);
  const nextLinked = () => linkedCursor && selectedOperation && void loadLinked(selectedOperation, linkedCursor, true);
  const nextUnmatched = () => unmatchedCursor && void loadUnmatched(unmatchedCursor, true);
  const nextDetail = () => detail?.nextCursor && selectedRecording && void loadDetail(selectedRecording, detail.nextCursor, true);

  const refreshCatalog = () => catalogMode === 'endpoints' ? void loadEndpoints() : catalogMode === 'linked' ? void loadLinked(selectedOperation) : void loadUnmatched();
  const refreshDetail = () => selectedRecording && void loadDetail(selectedRecording, eventWindowStartCursor.current);
  const pickEvent = (item: ReplayEvent) => {
    selectEvent(selectedRecording, item);
    setActivePane('evidence');
    setAnnouncement(`Event ${item.sequence} selected`);
  };

  const navigateToFrame = useCallback((action: string, frameId: string) => {
    const target = detail?.events.find((item) => item.frameId === frameId);
    if (!target) {
      setAnnouncement(`${action}: the target frame is outside the loaded window. Load more events to reach it; paging backward is not available yet.`);
      return;
    }
    selectEvent(selectedRecording, target);
    setAnnouncement(`Selected event ${target.sequence}`);
  }, [detail, selectEvent, selectedRecording]);

  const selectFrame = (frameId: string) => {
    // A Map node represents a frame and can stand for more than one recorded event.
    if (event?.frameId !== frameId) navigateToFrame('select', frameId);
  };
  const navigateKey = useCallback((action: NavAction) => {
    const target = frameControls.find((control) => control.action === action);
    if (target?.targetFrameId && target.enabled) navigateToFrame(action, target.targetFrameId);
    else if (target?.reason) setAnnouncement(target.reason);
  }, [frameControls, navigateToFrame]);

  useEffect(() => {
    const onKeyDown = (keyboard: KeyboardEvent) => {
      if (!keyboard.altKey || keyboard.ctrlKey || keyboard.metaKey) return;
      if (keyboard.target instanceof HTMLElement && keyboard.target.closest('input, select, textarea, [contenteditable="true"]')) return;
      const key = keyboard.code || keyboard.key;
      if (key === 'ArrowDown' || key === 'ArrowUp') {
        keyboard.preventDefault();
        if (keyboard.shiftKey) navigateKey(key === 'ArrowDown' ? 'next' : 'previous');
        else moveEvent(key === 'ArrowDown' ? 1 : -1);
        return;
      }
      switch (key) {
        case 'KeyI': case 'i': keyboard.preventDefault(); navigateKey('into'); break;
        case 'KeyO': case 'o': keyboard.preventDefault(); navigateKey('over'); break;
        case 'KeyU': case 'u': keyboard.preventDefault(); navigateKey('out'); break;
        case 'KeyM': case 'm':
          if (!eventCount) return;
          keyboard.preventDefault();
          dispatchReplay({ type: 'set-mode', mode: replay.mode === 'linear' ? 'canvas' : 'linear' });
          setActivePane('events');
          requestAnimationFrame(() => {
            document.querySelector<HTMLElement>('.event[tabindex="0"], .canvas-tree [role="treeitem"][tabindex="0"]')?.focus();
          });
          break;
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [eventCount, moveEvent, navigateKey, replay.mode]);

  return <AppShell activePane={activePane} onPane={setActivePane} announcement={announcement} auth={auth} authError={authError}
    openRecordings={openRecordings} selectedRecording={selectedRecording} onSelectRecording={activateRecording} onCloseRecording={closeRecording}
    sourceEvent={event}>
    <CatalogPanel
      active={activePane === 'recordings'}
      catalogMode={catalogMode}
      endpointLane={{ items: endpoints, cursor: endpointCursor, busy: endpointBusy, error: endpointError, released: olderEndpointsReleased }}
      linkedLane={{ items: linked, cursor: linkedCursor, busy: linkedBusy, error: linkedError, released: olderLinkedReleased }}
      unmatchedLane={{ items: unmatched, cursor: unmatchedCursor, busy: unmatchedBusy, error: unmatchedError, released: olderUnmatchedReleased }}
      arrivals={arrivals}
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
      endpoint={activeRecordingTab?.endpoint ?? null}
      detail={detail}
      detailBusy={detailBusy}
      detailError={detailError}
      selectedEvent={event}
      selectionUnavailable={selectionUnavailable}
      olderEventsReleased={olderEventsReleased}
      onRefresh={refreshDetail}
      onPickEvent={pickEvent}
      onNextWindow={nextDetail}
      mode={replay.mode}
      onMode={(mode) => dispatchReplay({ type: 'set-mode', mode })}
      onSelectFrame={selectFrame}
      onNavigateKey={navigateKey}
      onMove={moveEvent}
      backReason={backReason}
      nextReason={nextReason}
      frameControls={frameControls}
    />
    <EvidencePanel active={activePane === 'evidence'} currentStatus={currentStatus} detail={detail} event={event} selectionUnavailable={selectionUnavailable} onBackToEvent={() => {
      setActivePane('events');
      requestAnimationFrame(() => {
        const row = document.querySelector<HTMLElement>('.event[aria-current="true"], .canvas-tree [aria-selected="true"]');
        (row ?? document.getElementById('events-tab'))?.focus();
      });
    }} onNavigate={navigateToFrame} />
  </AppShell>;
}
