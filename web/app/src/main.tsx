import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import type { components } from './api.generated';
import { api, ApiError, failureMessage } from './api';
import { AppShell } from './app-shell';
import { recentlyObserved } from './features/catalog/recording-arrivals';
import { CatalogPanel } from './features/catalog/CatalogPanel';
import type { OpenRecording } from './features/shell/RecordingTabs';
import { EventsPanel } from './features/events/EventsPanel';
import { focusStepControl, stepScrollOwner } from './features/events/useStepWindow';
import { revealWithin } from './features/common/reveal-within';
import { EvidencePanel } from './features/evidence/EvidencePanel';
import { retainPage } from './retained-page';
import { replayPage, retainReplayWindow } from './replay/window';
import type { ReplayPage, WindowDirection } from './replay/window';
import { initialReplayState, replayReducer } from './replay/state';
import { filteredSteps } from './replay/loaded-tools';
import type { MissingTarget } from './replay/missing';
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
  const replayPages = useRef<ReplayPage[]>([]);
  const detailRetry = useRef<{ cursor: string | null; direction: WindowDirection } | null>(null);
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
  const [releasedEvents, setReleasedEvents] = useState<'earlier' | 'later' | null>(null);
  const [startKnown, setStartKnown] = useState(false);
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
  const authLane = useLane();

  useEffect(() => { endpointsRef.current = endpoints; }, [endpoints]);
  useEffect(() => { linkedRef.current = linked; }, [linked]);
  useEffect(() => { unmatchedRef.current = unmatched; }, [unmatched]);

  const markExpired = (error: unknown) => {
    if (!(error instanceof ApiError) || error.status !== 401) return;
    authLane.invalidate();
    endpointLane.invalidate(); linkedLane.invalidate();
    unmatchedLane.invalidate(); detailLane.invalidate();
    setEndpointBusy(false); setLinkedBusy(false); setUnmatchedBusy(false); setDetailBusy(false);
    setAuth('expired');
  };

  const applyEndpointPage = useCallback((page: components['schemas']['ObservedEndpointPage'], append: boolean) => {
    const result = retainPage(append ? endpointsRef.current : [], page.items, MAX_RETAINED_ROWS, page.nextCursor);
    endpointsRef.current = result.items;
    setEndpoints(result.items);
    setEndpointCursor(result.nextCursor);
    setOlderEndpointsReleased(result.released > 0);
    endpointHasLoaded.current = true;
    if (catalogModeRef.current === 'endpoints') setAnnouncement(`${page.items.length} observed endpoints loaded`);
  }, []);

  const loadEndpoints = useCallback(async (cursor: string | null = null, append = false) => {
    const { generation, signal } = endpointLane.begin();
    setEndpointBusy(true);
    setEndpointError('');
    try {
      const query = cursor ? `?limit=100&cursor=${encodeURIComponent(cursor)}` : '?limit=100';
      const page = await api<components['schemas']['ObservedEndpointPage']>(`/api/v1/endpoints${query}`, signal);
      if (!endpointLane.isCurrent(generation)) return;
      applyEndpointPage(page, append);
    } catch (error) {
      if (!endpointLane.isCurrent(generation)) return;
      markExpired(error);
      setEndpointError(failureMessage(error));
    } finally {
      if (endpointLane.isCurrent(generation)) {
        setEndpointBusy(false);
      }
    }
  }, [applyEndpointPage]);

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

  const loadDetail = useCallback(async (recordingId: string, cursor: string | null = null, direction: WindowDirection = 'replace') => {
    if (!recordingId || selectedRecordingRef.current !== recordingId) return;
    const { generation, signal } = detailLane.begin();
    setDetailBusy(true);
    setDetailError('');
    detailRetry.current = null;
    try {
      const query = cursor !== null ? `?limit=200&cursor=${encodeURIComponent(cursor)}` : '?limit=200';
      const next = await api<Detail>(`/api/v1/recordings/${encodeURIComponent(recordingId)}${query}`, signal);
      if (!detailLane.isCurrent(generation) || selectedRecordingRef.current !== recordingId) return;
      if (next.recordingId !== recordingId) throw new Error('Recording detail identity mismatch');
      const result = retainReplayWindow(replayPages.current, replayPage(next, cursor, direction), direction, MAX_RETAINED_EVENTS);
      replayPages.current = result.pages;
      eventPageCursors.current = new Map(result.pages.flatMap((page) =>
        page.events.map((item) => [item.sequence, page.requestCursor] as const)));
      setDetail({ ...next, events: result.events, prevCursor: result.prevCursor, nextCursor: result.nextCursor });
      setStartKnown(result.startKnown);
      setReleasedEvents(result.released > 0 ? direction === 'earlier' ? 'later' : 'earlier' : null);
      const first = result.events[0];
      if (first) dispatchReplay({ type: 'initialize-selection', recordingId, frameId: first.frameId ?? null, sequence: first.sequence });
      setAnnouncement(`${next.events.length} events available for selection`);
    } catch (error) {
      if (!detailLane.isCurrent(generation) || selectedRecordingRef.current !== recordingId) return;
      markExpired(error);
      detailRetry.current = { cursor, direction };
      setDetailError(failureMessage(error));
    } finally {
      if (detailLane.isCurrent(generation) && selectedRecordingRef.current === recordingId) setDetailBusy(false);
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
      replayPages.current = [];
      detailRetry.current = null;
      setStartKnown(false);
      setDetail(null);
      setDetailError('');
      setDetailBusy(false);
      setReleasedEvents(null);
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
    const fragmentText = window.location.hash.slice(1);
    const fragment = new URLSearchParams(fragmentText);
    const token = fragment.get('token');
    // Always discard the one-time fragment before rendering an error or sending a request.
    window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    if (!token) {
      if (fragmentText) {
        setAuth('error');
        setAuthError('The one-time viewer link is missing. Restart xtrace open --viewer.');
        return;
      }
      // Catalog navigation may supersede its own reads while this guarded session probe
      // is pending. It must not cancel authentication or overwrite a newer catalog page.
      const { generation, signal } = authLane.begin();
      void api<components['schemas']['ObservedEndpointPage']>('/api/v1/endpoints?limit=100', signal).then((page) => {
        if (!authLane.isCurrent(generation)) return;
        if (!endpointHasLoaded.current) applyEndpointPage(page, false);
        setAuth('ready');
      }).catch((cause: unknown) => {
        if (!authLane.isCurrent(generation)) return;
        markExpired(cause);
        setAuthError('The local viewer could not verify this session. Restart xtrace open --viewer.');
        setAuth((current) => current === 'checking' ? 'error' : current);
      });
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
  }, [applyEndpointPage, loadEndpoints]);

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
  const navigableEvents = useMemo(() => replay.mode === 'linear'
    ? filteredSteps(detail?.events ?? [], replay.filter, event) : detail?.events ?? [], [detail, event, replay.filter, replay.mode]);
  const navigableIndex = event ? navigableEvents.indexOf(event) : -1;
  const selectionUnavailable = detail && replay.sequence !== null && selectedEvent < 0
    ? 'Selected event is not in the loaded window.'
    : null;

  const loadedFrameIds = useMemo(() => new Set((detail?.events ?? []).flatMap((item) => item.frameId ? [item.frameId] : [])), [detail]);
  const frameControls = useMemo(
    () => navigationControls(event?.navigation as NavFrameNavigation | undefined, loadedFrameIds),
    [event, loadedFrameIds],
  );
  const missingSelection = selectionUnavailable ?? 'Select an event first.';
  const filterActive = replay.mode === 'linear' && replay.filter.kinds.length > 0;
  const backReason = selectedEvent < 0 ? missingSelection : navigableIndex === 0
    ? filterActive ? 'No earlier matching step in the loaded window.' : 'No earlier event in the loaded window.' : null;
  const nextReason = selectedEvent < 0 ? missingSelection : navigableIndex === navigableEvents.length - 1
    ? detail?.nextCursor ? 'Load the next window to reach more events.' : filterActive ? 'No later matching step in the loaded window.' : 'No later event in the loaded window.'
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
    const next = navigableEvents[navigableIndex + delta];
    if (!next) return;
    selectEvent(detail.recordingId, next);
    setAnnouncement(`Event ${next.sequence} selected`);
  }, [backReason, detail, navigableEvents, navigableIndex, nextReason, selectEvent]);

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
  const changeWindow = (direction: 'earlier' | 'later') => {
    const cursor = direction === 'earlier' ? detail?.prevCursor : detail?.nextCursor;
    if (cursor && selectedRecording && !detailBusy) void loadDetail(selectedRecording, cursor, direction);
  };

  const refreshCatalog = () => catalogMode === 'endpoints' ? void loadEndpoints() : catalogMode === 'linked' ? void loadLinked(selectedOperation) : void loadUnmatched();
  const refreshDetail = () => {
    if (!selectedRecording) return;
    const current = replayPages.current[0];
    const cursor = event && eventPageCursors.current.has(event.sequence) ? eventPageCursors.current.get(event.sequence) : current?.requestCursor;
    void loadDetail(selectedRecording, cursor ?? null);
  };
  const retryDetail = () => {
    const retry = detailRetry.current;
    if (selectedRecording && retry) void loadDetail(selectedRecording, retry.cursor, retry.direction);
  };

  const jumpToSequence = (sequence: string) => {
    if (!selectedRecording || detail?.recordingId !== selectedRecording) return;
    const target = detail.events.find((item) => item.sequence === sequence);
    if (!target) {
      setAnnouncement('Event sequence is not in the loaded window.');
      return;
    }
    selectEvent(selectedRecording, target);
    setActivePane('events');
    setAnnouncement(`Event ${sequence} selected`);
    requestAnimationFrame(() => {
      if (selectedRecordingRef.current !== selectedRecording) return;
      const current = document.querySelector<HTMLElement>(replay.mode === 'linear' ? '.event[aria-current="true"]' : '.canvas-tree [aria-selected="true"]');
      if (current) focusStepControl(current);
      else document.querySelector<HTMLElement>('.replay-tools > button')?.focus({ preventScroll: true });
    });
  };
  const pickEvent = (item: ReplayEvent) => {
    selectEvent(selectedRecording, item);
    setActivePane('evidence');
    setAnnouncement(`Event ${item.sequence} selected`);
  };

  const goToMissing = ({ recordingId, sequence, frameId }: MissingTarget) => {
    if (selectedRecordingRef.current !== recordingId || detail?.recordingId !== recordingId) return;
    const target = detail.events.find((item) => item.sequence === sequence && (item.frameId ?? null) === frameId);
    if (!target) {
      setAnnouncement('Selected event is not in the loaded window.');
      return;
    }
    selectEvent(recordingId, target);
    dispatchReplay({ type: 'set-mode', mode: 'linear' });
    setActivePane('events');
    setAnnouncement(`Event ${sequence} selected`);
    requestAnimationFrame(() => {
      if (selectedRecordingRef.current !== recordingId) return;
      const current = document.querySelector<HTMLElement>('.event[aria-current="true"]');
      if (current && current.querySelector('.event-seq')?.textContent === sequence) focusStepControl(current);
    });
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
    sourceEvent={event} detail={detail} endpoint={activeRecordingTab?.endpoint ?? null}>
    <CatalogPanel
      active={activePane === 'recordings'}
      catalogMode={catalogMode}
      endpointLane={{ items: endpoints, cursor: endpointCursor, busy: endpointBusy || auth === 'checking', error: endpointError, released: olderEndpointsReleased }}
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
      detail={detail}
      detailBusy={detailBusy}
      detailError={detailError}
      selectedEvent={event}
      selectionUnavailable={selectionUnavailable}
      releasedEvents={releasedEvents}
      startKnown={startKnown}
      onRefresh={refreshDetail}
      onRetry={retryDetail}
      onPickEvent={pickEvent}
      onChangeWindow={changeWindow}
      onJumpToSequence={jumpToSequence}
      filter={replay.filter}
      onFilter={(kinds) => {
        dispatchReplay({ type: 'set-filter', kinds });
        setAnnouncement(kinds.length ? 'Step filter changed. The selected step stays listed.' : 'Showing all loaded steps.');
      }}
      onActivate={() => setActivePane('events')}
      onAnnounce={setAnnouncement}
      onFocusedRowReleased={() => setAnnouncement('The focused event was released from the loaded window.')}
      mode={replay.mode}
      onMode={(mode) => dispatchReplay({ type: 'set-mode', mode })}
      onSelectFrame={selectFrame}
      onNavigateKey={navigateKey}
      onMove={moveEvent}
      backReason={backReason}
      nextReason={nextReason}
      frameControls={frameControls}
    />
    <EvidencePanel active={activePane === 'evidence'} currentStatus={currentStatus} detail={detail} event={event} selectionUnavailable={selectionUnavailable} onGoToMissing={goToMissing} onBackToEvent={() => {
      setActivePane('events');
      const recordingId = selectedRecording;
      requestAnimationFrame(() => {
        if (selectedRecordingRef.current !== recordingId) return;
        const step = document.querySelector<HTMLElement>('#events-panel .event[aria-current="true"]');
        if (step) {
          focusStepControl(step);
          return;
        }
        const row = document.querySelector<HTMLElement>('#events-panel .canvas-tree [aria-selected="true"]');
        const tree = row?.closest<HTMLElement>('.canvas-tree');
        if (row && tree) {
          revealWithin(tree, row, 'vertical');
          revealWithin(stepScrollOwner(tree), tree, 'vertical');
          row.focus({ preventScroll: true });
        } else {
          document.getElementById('events-tab')?.focus({ preventScroll: true });
        }
      });
    }} onNavigate={navigateToFrame} />
  </AppShell>;
}
