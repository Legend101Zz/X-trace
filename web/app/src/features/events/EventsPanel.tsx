import type { Detail } from '../../types';
import { ErrorState } from '../common/ErrorState';
import { CanvasView } from '../canvas/CanvasView';
import type { NavAction } from '../../replay/navigation';
import type { ReplayMode } from '../../replay/state';
import { OutcomeBanner } from './OutcomeBanner';

export interface EventsPanelProps {
  active: boolean;
  selectedRecording: string;
  detail: Detail | null;
  detailBusy: boolean;
  detailError: string;
  selectedEvent: number;
  olderEventsReleased: boolean;
  onRefresh: () => void;
  onPickEvent: (index: number) => void;
  onNextWindow: () => void;
  mode: ReplayMode;
  onMode: (mode: ReplayMode) => void;
  onSelectFrame: (frameId: string) => void;
  onNavigateKey: (action: NavAction) => void;
}

export function EventsPanel({ active, selectedRecording, detail, detailBusy, detailError, selectedEvent, olderEventsReleased, onRefresh, onPickEvent, onNextWindow, mode, onMode, onSelectFrame, onNavigateKey }: EventsPanelProps) {
  return <section className="pane" role="tabpanel" id="events-panel" aria-labelledby="events-tab" data-active={active} aria-label="Ordered event window">
        <div className="pane-head center-head"><div className="center-title"><div className="eyebrow">Linear event window</div><h1>{selectedRecording || 'Select a recording'}</h1></div><button className="button" onClick={onRefresh} disabled={detailBusy}>Refresh</button></div>
        {detailError ? <ErrorState message={detailError} onRetry={onRefresh} /> : null}
        {!selectedRecording && !detailError ? <div className="empty"><strong>No recording selected</strong><p>Choose a linked or unmatched recording from the left pane.</p></div> : null}
        {detail ? <OutcomeBanner detail={detail} /> : null}
        {detail && detail.events.length ? <div className="mode-switch" role="group" aria-label="Replay view">
          <button className="button" aria-pressed={mode === 'linear'} onClick={() => onMode('linear')}>Linear</button>
          <button className="button" aria-pressed={mode === 'canvas'} onClick={() => onMode('canvas')}>Canvas</button>
        </div> : null}
        {detail && detail.events.length && mode === 'canvas' ? <CanvasView events={detail.events} selectedFrameId={detail.events[selectedEvent]?.frameId ?? null} onSelectFrame={onSelectFrame} onNavigate={onNavigateKey} /> : null}
        {detailBusy && !detail ? <div className="loading">Verifying persisted event window…</div> : null}
        {detail && detail.events.length === 0 ? <div className="empty"><strong>No projected events</strong><p>The persisted recording has no event window to display.</p></div> : null}
        {detail && detail.events.length && mode === 'linear' ? <div className="event-rail">
          <div className="window-note"><span>{detail.events.length} ordered events</span><span>ALT + ↑ / ↓ to step</span></div>
          {detail.events.map((item, index) => <button key={`${item.sequence}-${index}`} className={`event ${item.kind.toLowerCase().endsWith(':gap') || item.kind.toLowerCase() === 'gap' ? 'gap-event' : ''}`} aria-current={index === selectedEvent} onClick={() => onPickEvent(index)}>
            <span className="event-seq">{item.sequence}</span><span className="event-copy"><span className="event-kind" title={item.kind}>{item.kind}</span><span className="event-symbol">{item.symbol || 'No symbol persisted'}</span></span><span className="event-time">{item.monotonicNs} ns</span>
          </button>)}
        </div> : null}
        {olderEventsReleased ? <p className="window-retention" role="status">Earlier events were released from memory. Continue from the current event cursor.</p> : null}
        {detail?.nextCursor ? <div className="page-controls"><span className="top-meta">More events in verified window</span><button className="button button-primary" onClick={onNextWindow} disabled={detailBusy}>Load next window</button></div> : null}
      </section>;
}
