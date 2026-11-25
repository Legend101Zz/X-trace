import type { Detail, Endpoint, ReplayEvent } from '../../types';
import { ErrorState } from '../common/ErrorState';
import { CanvasView } from '../canvas/CanvasView';
import type { NavAction, NavControl } from '../../replay/navigation';
import type { ReplayMode } from '../../replay/state';
import { nsToLabel } from '../../replay/outcome';
import { OutcomeBanner } from './OutcomeBanner';
import { ReplayToolbar } from './ReplayToolbar';
import { StepsList } from './StepsList';

export interface EventsPanelProps {
  active: boolean;
  selectedRecording: string;
  endpoint: Endpoint | null;
  detail: Detail | null;
  detailBusy: boolean;
  detailError: string;
  selectedEvent: ReplayEvent | undefined;
  selectionUnavailable: string | null;
  olderEventsReleased: boolean;
  onRefresh: () => void;
  onPickEvent: (event: ReplayEvent) => void;
  onNextWindow: () => void;
  mode: ReplayMode;
  onMode: (mode: ReplayMode) => void;
  onSelectFrame: (frameId: string) => void;
  onNavigateKey: (action: NavAction) => void;
  onMove: (direction: -1 | 1) => void;
  backReason: string | null;
  nextReason: string | null;
  frameControls: readonly NavControl[];
}

export function EventsPanel({ active, selectedRecording, endpoint, detail, detailBusy, detailError, selectedEvent, selectionUnavailable, olderEventsReleased, onRefresh, onPickEvent, onNextWindow, mode, onMode, onSelectFrame, onNavigateKey, onMove, backReason, nextReason, frameControls }: EventsPanelProps) {
  return <section className="pane" role="tabpanel" id="events-panel" aria-labelledby="events-tab" data-active={active} aria-label="Ordered event window">
        <div className="pane-head center-head"><div className="center-title"><div className="eyebrow">Replay steps</div><h1>{selectedRecording || 'Select a recording'}</h1></div><button className="button" onClick={onRefresh} disabled={detailBusy}>Refresh</button></div>
        {detailError ? <ErrorState message={detailError} onRetry={onRefresh} /> : null}
        {!selectedRecording && !detailError ? <div className="empty"><strong>No recording selected</strong><p>Choose a linked or unmatched recording from the left pane.</p></div> : null}
        {detail ? <>
          <div className="recording-bar" aria-label="Recording summary">
            <span className="recording-bar-field">{endpoint ? `${endpoint.method} ${endpoint.routeTemplate}` : 'Not linked to an endpoint'}</span>
            <span>{detail.outcome?.httpStatus == null ? 'HTTP status unavailable' : `HTTP ${detail.outcome.httpStatus}`}</span>
            <span>{detail.completion === 'unavailable' ? 'Completion unavailable' : `Recording ${detail.completion}`}</span>
            <span>{detail.durationNs == null ? 'Duration unavailable' : `Duration ${nsToLabel(detail.durationNs)}`}</span>
            <span>Capture mode not reported</span>
            {selectedEvent ? <span className="recording-bar-field">Event sequence {selectedEvent.sequence}{selectedEvent.symbol ? ` · ${selectedEvent.symbol}` : ''}</span> : null}
          </div>
          <OutcomeBanner detail={detail} />
        </> : null}
        {selectionUnavailable ? <p className="window-retention">{selectionUnavailable}</p> : null}
        {detail?.events.length ? <ReplayToolbar backReason={backReason} nextReason={nextReason} frameControls={frameControls} onMove={onMove} onNavigate={onNavigateKey} /> : null}
        {detail && detail.events.length ? <div className="mode-switch" role="group" aria-label="Replay view">
          <button className="button" aria-pressed={mode === 'linear'} onClick={() => onMode('linear')}>Steps</button>
          <button className="button" aria-pressed={mode === 'canvas'} onClick={() => onMode('canvas')}>Map</button>
        </div> : null}
        {mode === 'canvas' && selectedEvent && selectedEvent.frameId == null ? <p className="window-retention">Frame ID unavailable for the selected event.</p> : null}
        {detail && detail.events.length && mode === 'canvas' ? <CanvasView events={detail.events} selectedFrameId={selectedEvent?.frameId ?? null} onSelectFrame={onSelectFrame} onNavigate={onNavigateKey} /> : null}
        {detailBusy && !detail ? <div className="loading">Verifying persisted event window…</div> : null}
        {detail && detail.events.length === 0 ? <div className="empty"><strong>No projected events</strong><p>The persisted recording has no event window to display.</p></div> : null}
        {detail?.events.length && mode === 'linear' ? <StepsList events={detail.events} selected={selectedEvent} onPick={onPickEvent} onMove={onMove} /> : null}
        {olderEventsReleased ? <p className="window-retention" role="status">Earlier events were released from memory. Continue from the current event cursor.</p> : null}
        {detail?.nextCursor ? <div className="page-controls"><span className="top-meta">More events in verified window</span><button className="button button-primary" onClick={onNextWindow} disabled={detailBusy}>Load next window</button></div> : null}
      </section>;
}
