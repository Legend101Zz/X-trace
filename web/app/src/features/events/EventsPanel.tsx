import { useRef } from 'react';
import type { Detail, ReplayEvent } from '../../types';
import { ErrorState } from '../common/ErrorState';
import { CanvasView } from '../canvas/CanvasView';
import type { NavAction, NavControl } from '../../replay/navigation';
import type { ReplayMode } from '../../replay/state';
import { OutcomeBanner } from './OutcomeBanner';
import { ReplayWindows } from './ReplayWindows';
import { ReplayToolbar } from './ReplayToolbar';
import { StepsList } from './StepsList';
import { focusStepControl } from './useStepWindow';

export interface EventsPanelProps {
  active: boolean;
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
  onFocusedRowReleased: () => void;
  mode: ReplayMode;
  onMode: (mode: ReplayMode) => void;
  onSelectFrame: (frameId: string) => void;
  onNavigateKey: (action: NavAction) => void;
  onMove: (direction: -1 | 1) => void;
  backReason: string | null;
  nextReason: string | null;
  frameControls: readonly NavControl[];
}

export function EventsPanel({ active, selectedRecording, detail, detailBusy, detailError, selectedEvent, selectionUnavailable, releasedEvents, startKnown, onRefresh, onRetry, onPickEvent, onChangeWindow, onJumpToSequence, onFocusedRowReleased, mode, onMode, onSelectFrame, onNavigateKey, onMove, backReason, nextReason, frameControls }: EventsPanelProps) {
  const windowSearch = useRef<HTMLInputElement>(null);
  return <section className="pane" role="tabpanel" id="events-panel" aria-labelledby="events-tab" data-active={active} aria-label="Ordered event window">
        {detail?.events.length ? <ReplayToolbar backReason={backReason} nextReason={nextReason} frameControls={frameControls} onMove={onMove} onNavigate={onNavigateKey} /> : null}
        <div className="steps-content">
          <div className="pane-head center-head"><div className="center-title"><div className="eyebrow">Replay steps</div><h1>{selectedRecording || 'Select a recording'}</h1></div><button className="button" onClick={onRefresh} disabled={detailBusy}>Refresh</button></div>
          {detailError ? <ErrorState message={detailError} onRetry={onRetry} /> : null}
          {!selectedRecording && !detailError ? <div className="empty"><strong>No recording selected</strong><p>Choose a linked or unmatched recording from the left pane.</p></div> : null}
          {detail ? <OutcomeBanner detail={detail} /> : null}
          {selectionUnavailable ? <p className="window-retention">{selectionUnavailable}</p> : null}
          {detail && detail.events.length ? <div className="mode-switch" role="group" aria-label="Replay view">
            <button className="button" aria-pressed={mode === 'linear'} onClick={() => onMode('linear')}>Steps</button>
            <button className="button" aria-pressed={mode === 'canvas'} onClick={() => onMode('canvas')}>Map</button>
          </div> : null}
          {detail ? <ReplayWindows key={detail.recordingId} prevCursor={detail.prevCursor ?? null} nextCursor={detail.nextCursor ?? null}
            count={detail.events.length} busy={detailBusy} startKnown={startKnown} released={releasedEvents}
            onChange={onChangeWindow} onJump={onJumpToSequence} searchRef={windowSearch} /> : null}
          {mode === 'canvas' && selectedEvent && selectedEvent.frameId == null ? <p className="window-retention">Frame ID unavailable for the selected event.</p> : null}
          {detail && detail.events.length && mode === 'canvas' ? <CanvasView events={detail.events} selectedFrameId={selectedEvent?.frameId ?? null} onSelectFrame={onSelectFrame} onNavigate={onNavigateKey} /> : null}
          {detailBusy && !detail ? <div className="loading">Verifying persisted event window…</div> : null}
          {detail && detail.events.length === 0 ? <div className="empty"><strong>No projected events</strong><p>The persisted recording has no event window to display.</p></div> : null}
          {detail?.events.length && mode === 'linear' ? <StepsList events={detail.events} selected={selectedEvent} onPick={onPickEvent} onMove={onMove} onFocusedRowReleased={() => {
            if (!windowSearch.current) return;
            focusStepControl(windowSearch.current);
            onFocusedRowReleased();
          }} /> : null}
        </div>
      </section>;
}
