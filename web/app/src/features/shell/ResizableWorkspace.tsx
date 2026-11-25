import { useLayoutEffect, useRef, useState } from 'react';
import type { CSSProperties, KeyboardEvent, PointerEvent, ReactNode } from 'react';
import { clampPanel, DEFAULT_LAYOUT, PANEL_LIMITS, readPanelLayout, savePanelLayout } from './panel-layout';
import type { Panel, PanelLayout } from './panel-layout';
import { useViewport } from './viewport';
import { CodeEvidence } from '../code/CodeEvidence';
import type { Pane, ReplayEvent } from '../../types';
import './workspace.css';

const LABELS = { requests: 'Requests', code: 'Code', inspector: 'Inspector' } as const;
const IDS = { requests: 'recordings-panel', code: 'code-panel', inspector: 'evidence-panel' } as const;
const TABLET = '(min-width: 700px) and (max-width: 860px)';
const DESKTOP = '(min-width: 861px)';

export type InspectorDock = 'bottom' | 'right';

function Splitter({ panel, value, lastOpen, stacked, onResize, onCommit }: {
  panel: Panel;
  value: number;
  lastOpen: number;
  stacked: boolean;
  onResize: (value: number) => void;
  onCommit: (value: number) => void;
}) {
  const drag = useRef<{ pointer: number; from: number; startSize: number; originalSize: number; extent: number; stacked: boolean; moved: boolean } | null>(null);
  const [min, max] = PANEL_LIMITS[panel];
  const axis = (event: PointerEvent, stacked: boolean) => stacked ? event.clientY : event.clientX;
  function resizeByKey(event: KeyboardEvent<HTMLDivElement>) {
    const direction = stacked ? { decrease: 'ArrowDown', increase: 'ArrowUp' }
      : panel === 'requests' ? { decrease: 'ArrowLeft', increase: 'ArrowRight' } : { decrease: 'ArrowRight', increase: 'ArrowLeft' };
    let next: number;
    switch (event.key) {
      case direction.decrease: next = clampPanel(panel, (value || min) - 2); break;
      case direction.increase: next = clampPanel(panel, (value || min) + 2); break;
      case 'Home': next = min; break;
      case 'End': next = max; break;
      case 'Enter': next = value ? 0 : lastOpen; break;
      default: return;
    }
    event.preventDefault();
    onCommit(next);
  }

  function startDrag(event: PointerEvent<HTMLDivElement>) {
    if (event.button !== 0) return;
    const workspace = event.currentTarget.closest('.workspace');
    const group = panel === 'code' ? event.currentTarget.closest('.steps-and-code') : workspace;
    const extent = stacked ? workspace?.clientHeight : group?.clientWidth;
    if (!extent) return;
    event.preventDefault();
    event.currentTarget.focus();
    event.currentTarget.setPointerCapture(event.pointerId);
    drag.current = {
      pointer: event.pointerId, from: axis(event, stacked), startSize: value || lastOpen,
      originalSize: value, extent, stacked, moved: false,
    };
  }

  function dragValue(event: PointerEvent<HTMLDivElement>) {
    const start = drag.current;
    if (!start || start.pointer !== event.pointerId) return;
    const distance = axis(event, start.stacked) - start.from;
    if (distance !== 0) start.moved = true;
    if (!start.moved) return;
    const sign = panel === 'requests' ? 1 : -1;
    return clampPanel(panel, start.startSize + sign * 100 * distance / start.extent);
  }

  return <div role="separator" tabIndex={0} className={`panel-splitter panel-splitter--${panel}`}
    aria-label={`Resize ${LABELS[panel]}`} aria-controls={IDS[panel]} aria-orientation={stacked ? 'horizontal' : 'vertical'}
    aria-valuenow={value} aria-valuemin={0} aria-valuemax={max}
    aria-valuetext={value ? `${LABELS[panel]} size preference ${value}%` : `${LABELS[panel]} collapsed`}
    onKeyDown={resizeByKey} onPointerDown={startDrag} onPointerMove={(event) => {
      const next = dragValue(event);
      if (next !== undefined) onResize(next);
    }} onPointerUp={(event) => {
      const next = dragValue(event);
      drag.current = null;
      if (next !== undefined) onCommit(next);
    }} onPointerCancel={() => {
      if (drag.current) onResize(drag.current.originalSize);
      drag.current = null;
    }}
    onDoubleClick={() => onCommit(value ? 0 : lastOpen)} />;
}

export function ResizableWorkspace({ requests, steps, inspector, sourceEvent, activePane, dock }: {
  requests: ReactNode;
  steps: ReactNode;
  inspector: ReactNode;
  sourceEvent: ReplayEvent | undefined;
  activePane: Pane;
  dock: InspectorDock;
}) {
  const [layout, setLayout] = useState(readPanelLayout);
  const layoutRef = useRef(layout);
  const { sizes, lastOpen } = layout;

  function resize(panel: Panel, value: number, persist = false) {
    const current = layoutRef.current;
    const next: PanelLayout = {
      sizes: { ...current.sizes, [panel]: value },
      lastOpen: persist ? { ...current.lastOpen, [panel]: value || current.lastOpen[panel] } : current.lastOpen,
    };
    layoutRef.current = next;
    setLayout(next);
    if (persist) savePanelLayout(next);
  }
  function reset() {
    layoutRef.current = DEFAULT_LAYOUT;
    setLayout(DEFAULT_LAYOUT);
    savePanelLayout(DEFAULT_LAYOUT);
  }
  const showSourcePane = useViewport(DESKTOP);
  const tablet = useViewport(TABLET);
  const inspectorStacked = tablet || (showSourcePane && dock === 'bottom');
  const splitter = (panel: Panel) => <Splitter panel={panel} value={sizes[panel]} lastOpen={lastOpen[panel]} stacked={panel === 'inspector' && inspectorStacked}
    onResize={(value) => resize(panel, value)} onCommit={(value) => resize(panel, value, true)} />;
  const restore = (panel: Panel) => <button className={`button collapsed-panel collapsed-panel--${panel}`}
    type="button" onClick={() => {
      resize(panel, lastOpen[panel], true);
      document.querySelector<HTMLElement>(`.panel-splitter--${panel}`)?.focus();
    }}>{LABELS[panel]}</button>;
  const style = {
    '--requests-size': sizes.requests ? `${sizes.requests}%` : '44px',
    '--code-size': sizes.code ? `${sizes.code}%` : '44px',
    '--inspector-size': sizes.inspector ? `${sizes.inspector}%` : '44px',
  } as CSSProperties;
  const codePane = useRef<HTMLElement>(null);
  useLayoutEffect(() => { if (codePane.current) codePane.current.scrollTop = 0; }, [sourceEvent, showSourcePane]);

  return <main className="workspace viewer-workspace" data-pane={activePane} data-dock={dock} style={style}>
    <div className="workspace-requests" data-collapsed={sizes.requests === 0}>
      {requests}{sizes.requests === 0 ? restore('requests') : null}
    </div>
    {splitter('requests')}
    <div className="steps-and-code" data-code-collapsed={sizes.code === 0}>
      {steps}
      {splitter('code')}
      <section id="code-panel" ref={codePane} className="workspace-code" aria-label="Code">
        {sizes.code === 0 ? restore('code') : <div className="workspace-code-body">
          <h2>Code</h2>
          {showSourcePane && sourceEvent ? <CodeEvidence event={sourceEvent} /> : <p>Select an event</p>}
        </div>}
      </section>
    </div>
    {splitter('inspector')}
    <div className="workspace-inspector" data-collapsed={sizes.inspector === 0}>
      {inspector}{sizes.inspector === 0 ? restore('inspector') : null}
    </div>
    <button type="button" className="button reset-panels" onClick={reset}>Reset panels</button>
  </main>;
}
