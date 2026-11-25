import { useMemo, useRef } from 'react';
import type { Detail, ReplayEvent } from '../../types';
import { ErrorState } from '../common/ErrorState';
import { CanvasView } from '../canvas/CanvasView';
import type { NavAction, NavControl } from '../../replay/navigation';
import type { ReplayFilter, ReplayMode } from '../../replay/state';
import { filteredSteps, loadedTiming } from '../../replay/loaded-tools';
import { OutcomeBanner } from './OutcomeBanner';
import { ReplayWindows } from './ReplayWindows';
import { ReplayToolbar, type PhoneReplayControls } from './ReplayToolbar';
import { StepsList } from './StepsList';
import { focusStepControl } from './useStepWindow';
import { ReplayTools } from './ReplayTools';
import { useViewerPreferences } from '../shell/viewer-preferences';
import { useViewport } from '../shell/viewport';

export interface EventsPanelProps {
  active: boolean;
  phone: PhoneReplayControls;
  selectedRecording: string;
  detail: Detail | null;
  detailBusy: boolean;
  detailError: string;
  selectedEvent: ReplayEvent | undefined;
  selectionUnavailable: string | null;
  releasedEvents: 'earlier' | 'later' | null;
  startKnown: boolean;
  onRefresh: () => void;
  onRetry: () => void;
  onPickEvent: (event: ReplayEvent) => void;
  onChangeWindow: (direction: 'earlier' | 'later') => void;
  onJumpToSequence: (sequence: string) => void;
  filter: ReplayFilter;
  onFilter: (kinds: readonly string[]) => void;
  onActivate: () => void;
  onAnnounce: (message: string) => void;
  onFocusedRowReleased: () => void;
  mode: ReplayMode;
  onMode: (mode: ReplayMode, focusSelection: boolean) => void;
  onSelectFrame: (frameId: string) => void;
  onNavigateKey: (action: NavAction) => void;
  onMove: (direction: -1 | 1) => void;
  backReason: string | null;
  nextReason: string | null;
  frameControls: readonly NavControl[];
}

export function EventsPanel({ active, phone, selectedRecording, detail, detailBusy, detailError, selectedEvent, selectionUnavailable, releasedEvents, startKnown, onRefresh, onRetry, onPickEvent, onChangeWindow, onJumpToSequence, filter, onFilter, onActivate, onAnnounce, onFocusedRowReleased, mode, onMode, onSelectFrame, onNavigateKey, onMove, backReason, nextReason, frameControls }: EventsPanelProps) {
  const windowControl = useRef<HTMLButtonElement>(null);
  const preferences = useViewerPreferences();
  function focusTools() {
    const control = windowControl.current;
    if (control && !control.closest('[hidden]')) focusStepControl(control);
    else document.querySelector<HTMLButtonElement>('.phone-actions [aria-expanded]')?.focus();
  }
  const steps = useMemo(() => filteredSteps(detail?.events ?? [], filter, selectedEvent), [detail, filter, selectedEvent]);
  const timing = useMemo(() => loadedTiming(detail?.events ?? []), [detail]);
  const phoneLayout = useViewport('(max-width: 699px)');
  const toolbar = detail?.events.length ? <ReplayToolbar phone={phone} backReason={backReason} nextReason={nextReason} frameControls={frameControls} onMove={onMove} onNavigate={onNavigateKey}
          tools={<ReplayTools key={detail.recordingId} events={detail.events} selected={selectedEvent} filter={filter} busy={detailBusy}
            onFilter={onFilter} onGo={onJumpToSequence} onActivate={onActivate} onAnnounce={onAnnounce} controlRef={windowControl} />} /> : null;
  return <section className="pane" role="tabpanel" id="events-panel" aria-labelledby="events-tab" data-active={active} aria-label="Ordered event window">
        {!phoneLayout ? toolbar : null}
        <div className="steps-content">
          <div className="pane-head center-head"><div className="center-title"><div className="eyebrow">Replay steps</div><h1>{selectedRecording || 'Select a recording'}</h1></div><button className="button" onClick={onRefresh} disabled={detailBusy}>Refresh</button></div>
          {detailError ? <ErrorState message={detailError} onRetry={onRetry} /> : null}
          {!selectedRecording && !detailError ? <div className="empty"><strong>No recording selected</strong><p>Choose a linked or unmatched recording in Requests.</p></div> : null}
          {selectionUnavailable ? <p className="window-retention">{selectionUnavailable}</p> : null}
          {detail && detail.events.length ? <div className="mode-switch" role="tablist" aria-label="Replay view" onKeyDown={(event) => {
            let next: ReplayMode;
            switch (event.key) {
              case 'Home': next = 'linear'; break;
              case 'End': next = 'canvas'; break;
              case 'ArrowLeft':
              case 'ArrowRight': next = mode === 'linear' ? 'canvas' : 'linear'; break;
              default: return;
            }
            event.preventDefault();
            onMode(next, false);
            event.currentTarget.querySelector<HTMLElement>(next === 'linear' ? '[data-mode="linear"]' : '[data-mode="canvas"]')?.focus();
          }}>
            <button className="button" role="tab" id="replay-view-steps-tab" aria-controls="replay-view-steps-panel" data-mode="linear" aria-selected={mode === 'linear'} tabIndex={mode === 'linear' ? 0 : -1} onClick={() => onMode('linear', true)}>Steps</button>
            <button className="button" role="tab" id="replay-view-map-tab" aria-controls="replay-view-map-panel" data-mode="canvas" aria-selected={mode === 'canvas'} tabIndex={mode === 'canvas' ? 0 : -1} onClick={() => onMode('canvas', true)}>Map</button>
          </div> : null}
          {detail ? <OutcomeBanner detail={detail} /> : null}
          {detail ? <ReplayWindows key={detail.recordingId} prevCursor={detail.prevCursor ?? null} nextCursor={detail.nextCursor ?? null}
            count={detail.events.length} busy={detailBusy} startKnown={startKnown} released={releasedEvents}
            onChange={onChangeWindow} /> : null}
          {detail && filter.kinds.length ? <p className="window-retention replay-filter-note">Filter on: showing {steps.length} of {detail.events.length} loaded steps. The selected step stays listed.
            <button type="button" className="link-button" onClick={() => {
              onFilter([]);
              // Clearing removes this button. Keep keyboard focus on a persistent replay control.
              focusTools();
            }}>Show all steps</button></p> : null}
          {preferences.timing === 'on' && mode === 'linear' ? <p className="window-retention">Timing is since the first loaded step, from recorded monotonic timestamps; not a step duration. Invalid timestamps are unavailable; backwards timestamps are labelled non-monotonic.</p> : null}
          {detailBusy && !detail ? <div className="loading">Verifying persisted event window…</div> : null}
          {detail && detail.events.length === 0 ? <div className="empty"><strong>No projected events</strong><p>The persisted recording has no event window to display.</p></div> : null}
          {detail && detail.events.length ? <>
            <div className="replay-view-panel" role="tabpanel" id="replay-view-map-panel" aria-labelledby="replay-view-map-tab" hidden={mode !== 'canvas'}>
              {mode === 'canvas' && selectedEvent && selectedEvent.frameId == null ? <p className="window-retention">Frame ID unavailable for the selected event.</p> : null}
              {mode === 'canvas' ? <>
                {filter.kinds.length ? <p className="window-retention">Map shows all loaded frames for call context. The step filter applies in Steps.</p> : null}
                <CanvasView events={detail.events} selectedFrameId={selectedEvent?.frameId ?? null} onSelectFrame={onSelectFrame} onNavigate={onNavigateKey} />
              </> : null}
            </div>
            <div className="replay-view-panel" role="tabpanel" id="replay-view-steps-panel" aria-labelledby="replay-view-steps-tab" hidden={mode !== 'linear'}>
              {mode === 'linear' ? <StepsList events={steps} selected={selectedEvent} timing={preferences.timing === 'on' ? timing : undefined} onPick={onPickEvent} onMove={onMove} onFocusedRowReleased={(sequence) => {
                focusTools();
                if (detail.events.some((event) => event.sequence === sequence)) onAnnounce('The focused step is hidden by the step filter.');
                else onFocusedRowReleased();
              }} /> : null}
            </div>
          </> : null}
        </div>
        {phoneLayout ? toolbar : null}
      </section>;
}
