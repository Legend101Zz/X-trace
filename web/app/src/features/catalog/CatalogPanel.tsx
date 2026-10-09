import type { CatalogMode, Endpoint, Recording } from '../../types';
import { ErrorState } from '../common/ErrorState';
import { RecordingRows } from './RecordingRows';

/** One paged catalog lane as the panel sees it. */
export interface CatalogLaneView<T> {
  items: T[];
  cursor: string | null;
  busy: boolean;
  error: string;
  released: boolean;
}

export interface CatalogPanelProps {
  active: boolean;
  catalogMode: CatalogMode;
  endpointLane: CatalogLaneView<Endpoint>;
  linkedLane: CatalogLaneView<Recording>;
  unmatchedLane: CatalogLaneView<Recording>;
  selectedEndpoint: Endpoint | null;
  selectedRecording: string;
  onRefresh: () => void;
  onRetryEndpoints: () => void;
  onRetryLinked: () => void;
  onRetryUnmatched: () => void;
  onNextEndpoints: () => void;
  onNextLinked: () => void;
  onNextUnmatched: () => void;
  onOpenEndpoint: (endpoint: Endpoint) => void;
  onOpenUnmatched: () => void;
  onBack: () => void;
  onSelectRecording: (id: string) => void;
}

export function CatalogPanel(props: CatalogPanelProps) {
  const {
    active, catalogMode, selectedEndpoint, selectedRecording,
    onRefresh, onRetryEndpoints, onRetryLinked, onRetryUnmatched,
    onNextEndpoints, onNextLinked, onNextUnmatched, onOpenEndpoint, onOpenUnmatched, onBack, onSelectRecording,
  } = props;
  const { items: endpoints, cursor: endpointCursor, busy: endpointBusy, error: endpointError, released: olderEndpointsReleased } = props.endpointLane;
  const { items: linked, cursor: linkedCursor, busy: linkedBusy, error: linkedError, released: olderLinkedReleased } = props.linkedLane;
  const { items: unmatched, cursor: unmatchedCursor, busy: unmatchedBusy, error: unmatchedError, released: olderUnmatchedReleased } = props.unmatchedLane;
  return <section className="pane" role="tabpanel" id="recordings-panel" aria-labelledby="recordings-tab" data-active={active} aria-label="Recordings">
        <div className="pane-head"><div><div className="eyebrow">Observed catalog</div><h1>{catalogMode === 'endpoints' ? 'Endpoints' : catalogMode === 'linked' ? 'Linked recordings' : 'Unmatched recordings'}</h1></div>
          <button className="button" onClick={onRefresh} disabled={endpointBusy || linkedBusy || unmatchedBusy}>Refresh</button></div>
        {catalogMode === 'linked' ? <div className="catalog-back"><div className="catalog-actions"><button className="button" onClick={onBack}>← Observed endpoints</button><button className="button" onClick={onOpenUnmatched}>Unmatched recordings</button></div><span>{selectedEndpoint?.method} {selectedEndpoint?.routeTemplate}</span><small>Component: {selectedEndpoint?.applicationComponent} · Binding: {selectedEndpoint?.binding}</small></div> : null}
        {catalogMode === 'endpoints' ? <>
          <div className="catalog-switch"><button className="button" aria-current="page">Observed endpoints</button><button className="button" onClick={onOpenUnmatched}>Unmatched recordings</button></div>
          <div className="policy-note"><strong>Operator-selected policy</strong><span>{endpoints[0]?.observationPolicy ?? 'spring-orders-v1'} does not attest which adapter or application produced the event.</span></div>
          {endpointBusy && endpoints.length === 0 ? <div className="loading">Reading observed endpoints…</div> : null}
          {endpointError ? <ErrorState message={endpointError} onRetry={onRetryEndpoints} /> : null}
          {!endpointBusy && !endpointError && endpoints.length === 0 ? <div className="empty"><strong>No observed endpoints</strong><p>A persisted capture must include the exact operator-selected policy and approved route.</p></div> : null}
          <div className="recording-list endpoint-list">{endpoints.map((endpoint) => <button className="recording endpoint-card" key={endpoint.operationId} onClick={() => onOpenEndpoint(endpoint)}>
            <span className="endpoint-method">{endpoint.method}</span><span><span className="recording-title">{endpoint.routeTemplate}</span><span className="recording-sub">Component: {endpoint.applicationComponent}<br />Binding: {endpoint.binding}</span><span className="recording-status">observed</span></span>
          </button>)}</div>
          {endpointCursor ? <div className="page-controls"><span className="top-meta">More endpoints</span><button className="button" onClick={onNextEndpoints} disabled={endpointBusy}>Load next page</button></div> : null}
        </> : null}
        {catalogMode === 'linked' ? <>
          <div className="policy-note"><strong>Operator-selected policy</strong><span>{selectedEndpoint?.observationPolicy ?? 'spring-orders-v1'} does not attest which adapter or application produced the event.</span></div>
          {linkedBusy && linked.length === 0 ? <div className="loading">Reading linked recordings…</div> : null}
          {linkedError ? <ErrorState message={linkedError} onRetry={onRetryLinked} /> : null}
          {!linkedBusy && !linkedError && linked.length === 0 ? <div className="empty"><strong>No linked recordings</strong><p>This endpoint has no persisted linked recording in the current page.</p></div> : null}
          <RecordingRows items={linked} selected={selectedRecording} onSelect={onSelectRecording} />
          {linkedCursor ? <div className="page-controls"><span className="top-meta">More linked recordings</span><button className="button" onClick={onNextLinked} disabled={linkedBusy}>Load next page</button></div> : null}
        </> : null}
        {catalogMode === 'unmatched' ? <>
          <div className="catalog-switch"><button className="button" onClick={onBack}>Observed endpoints</button><button className="button" aria-current="page">Unmatched recordings</button></div>
          <div className="context-note unmatched-note">These recordings have no observed endpoint association. A historical recording may have no reason code.</div>
          {unmatchedBusy && unmatched.length === 0 ? <div className="loading">Reading unmatched recordings…</div> : null}
          {unmatchedError ? <ErrorState message={unmatchedError} onRetry={onRetryUnmatched} /> : null}
          {!unmatchedBusy && !unmatchedError && unmatched.length === 0 ? <div className="empty"><strong>No unmatched recordings</strong><p>Unlinked and legacy recordings appear here.</p></div> : null}
          <RecordingRows items={unmatched} selected={selectedRecording} onSelect={onSelectRecording} />
          {unmatchedCursor ? <div className="page-controls"><span className="top-meta">More unmatched recordings</span><button className="button" onClick={onNextUnmatched} disabled={unmatchedBusy}>Load next page</button></div> : null}
        </> : null}
        {(catalogMode === 'endpoints' ? olderEndpointsReleased : catalogMode === 'linked' ? olderLinkedReleased : olderUnmatchedReleased) ? <p className="window-retention" role="status">Earlier rows were released from memory. Continue from the current page cursor.</p> : null}
        <aside className="context-note">Only persisted endpoint and recording evidence is shown. No handler discovery or application attestation is implied.</aside>
      </section>;
}
