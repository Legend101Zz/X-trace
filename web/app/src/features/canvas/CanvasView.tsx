import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent, ReactNode } from 'react';
import { projectFrameGraph, treeRows } from '../../replay/graph';
import type { GraphFrame } from '../../replay/graph';
import type { NavAction } from '../../replay/navigation';
import type { ReplayEvent } from '../../types';
import { revealWithin } from '../common/reveal-within';
import { useMapTreeWindow } from './useMapTreeWindow';
import './canvas.css';

const NODE_W = 168;
const NODE_H = 28;
const COL_GAP = 16;
const ROW_GAP = 22;
/** Drawing cap: the SVG never grows with the whole retained window. The tree still lists every node. */
const MAX_DRAWN_NODES = 400;

type FrameEvent = ReplayEvent & { parentFrameId?: string | null; asyncParentFrameId?: string | null; depth?: number | null };

export interface CanvasViewProps {
  events: readonly ReplayEvent[];
  /** Frame id of the selected event, shared with the Linear view. */
  selectedFrameId: string | null;
  onSelectFrame: (frameId: string) => void;
  /** Arrow keys on the tree ask for a server-resolved step from the selected frame. */
  onNavigate: (action: NavAction) => void;
}

/** Canvas: an SVG frame graph with a parallel ARIA tree that carries focus, names and keyboard control. */
export function CanvasView({ events, selectedFrameId, onSelectFrame, onNavigate }: CanvasViewProps) {
  const { graph, undrawn, anyParent } = useMemo(() => {
    const frames: GraphFrame[] = [];
    let skipped = 0;
    let parents = false;
    for (const raw of events as readonly FrameEvent[]) {
      if (!raw.frameId) { skipped += 1; continue; }
      if (raw.parentFrameId) parents = true;
      frames.push({ frameId: raw.frameId, sequence: raw.sequence, kind: raw.kind, symbol: raw.symbol || raw.kind, parentFrameId: raw.parentFrameId ?? null, asyncParentFrameId: raw.asyncParentFrameId ?? null, depth: raw.depth ?? null });
    }
    return { graph: projectFrameGraph(frames), undrawn: skipped, anyParent: parents };
  }, [events]);

  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const rows = useMemo(() => treeRows(graph, expanded), [graph, expanded]);
  const [preferredRowKey, setPreferredRowKey] = useState<string>();
  const scrollRef = useRef<HTMLDivElement>(null);
  const selectedNode = selectedFrameId ? graph.nodeOfFrame[selectedFrameId] ?? null : null;
  // The group and its first member can share a frame id but remain distinct tree rows.
  const selectedRow = rows.find((row) => row.frameId === selectedFrameId && row.key === preferredRowKey)
    ?? rows.find((row) => row.frameId === selectedFrameId)
    ?? rows.find((row) => row.nodeId === selectedNode && !row.isMember) ?? null;
  const focusKey = selectedRow?.key ?? rows[0]?.key ?? null;
  const { tree, mounted, offsets, captureViewport, setFocusedKey } = useMapTreeWindow(rows, focusKey, selectedRow ? selectedFrameId : null);
  const drawn = graph.nodes.slice(0, MAX_DRAWN_NODES);
  const drawnIds = new Set(drawn.map((node) => node.id));
  const width = Math.max(1, Math.ceil(Math.max(0, ...drawn.map((node) => node.column)) + 1)) * (NODE_W + COL_GAP);
  const height = Math.max(1, Math.max(0, ...drawn.map((node) => node.layer)) + 1) * (NODE_H + ROW_GAP);
  const kindOf = (node: { kind: string }) => (node.kind.toLowerCase() === 'gap' || node.kind.toLowerCase().endsWith(':gap') ? 'gap' : 'frame');
  useLayoutEffect(() => {
    revealWithin(scrollRef.current, scrollRef.current?.querySelector('[data-selected="true"]') ?? null, 'both');
  }, [selectedFrameId, focusKey]);
  const pos = (node: { column: number; layer: number }) => ({ x: node.column * (NODE_W + COL_GAP), y: node.layer * (NODE_H + ROW_GAP) });
  const byId = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph]);

  const selectRow = (row: (typeof rows)[number]) => {
    setPreferredRowKey(row.key);
    onSelectFrame(row.frameId);
  };
  // Tree order is depth-first preorder (= call/sequence order), not layout order.
  const move = (from: string | null, delta: number) => {
    const index = rows.findIndex((row) => row.key === from);
    const next = rows[Math.max(0, Math.min(rows.length - 1, index + delta))];
    if (next) selectRow(next);
  };
  const toggle = (nodeId: string) => setExpanded((current) => {
    const next = new Set(current);
    if (next.has(nodeId)) next.delete(nodeId); else next.add(nodeId);
    return next;
  });
  const onKeyDown = (keyboard: KeyboardEvent) => {
    // Alt+ArrowUp/Down belong to the viewer-wide event stepping handler.
    const target = keyboard.target as HTMLElement;
    if (keyboard.altKey || target.tagName === 'BUTTON'
      || (keyboard.key.startsWith('Arrow') && (keyboard.ctrlKey || keyboard.metaKey || keyboard.shiftKey))) return;
    const from = target.closest<HTMLElement>('[role="treeitem"]')?.dataset.key ?? focusKey;
    const actions: Record<string, () => void> = {
      ArrowDown: () => move(from, 1), ArrowUp: () => move(from, -1),
      Home: () => rows[0] && selectRow(rows[0]),
      End: () => rows.length && selectRow(rows[rows.length - 1]),
      Enter: () => { if (selectedRow?.expandable) toggle(selectedRow.nodeId); },
      ' ': () => { if (selectedRow?.expandable) toggle(selectedRow.nodeId); },
      ArrowRight: () => onNavigate('into'), ArrowLeft: () => onNavigate('out'),
    };
    const action = actions[keyboard.key];
    if (!action) return;
    keyboard.preventDefault();
    action();
  };

  const content: ReactNode[] = [];
  let previous = 0;
  const spacer = (end: number) => {
    if (end > previous) content.push(<li key={`spacer-${end}`} role="presentation" aria-hidden="true"
      className="canvas-tree-spacer" style={{ height: offsets[end] - offsets[previous] }} />);
  };
  for (const index of mounted) {
    spacer(index);
    previous = index + 1;
    const row = rows[index];
    const node = byId.get(row.nodeId)!;
    const kind = kindOf(node);
    const label = row.isMember ? `${node.symbol} (call ${row.posInSet} of ${row.setSize})` : `${node.symbol}${node.count > 1 ? ` (${node.count} repeated calls)` : ''}`;
    content.push(<li key={row.key} role="treeitem" data-kind={kind} aria-level={row.level} aria-posinset={row.posInSet} aria-setsize={row.setSize}
      aria-selected={row.key === focusKey && selectedRow !== null} aria-expanded={row.expandable ? row.expanded : undefined}
      tabIndex={row.key === focusKey ? 0 : -1} onClick={() => selectRow(row)}
      data-key={row.key} onFocus={() => setFocusedKey(row.key)} onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setFocusedKey(undefined);
      }}>
      {label}{kind === 'gap' ? ' · evidence gap (events missing here)'  : ''}{!row.isMember && node.parentOutsideWindow ? ' · parent outside window' : ''}{!row.isMember && node.parentNotObserved ? ' · parent not observed' : ''}
      {row.expandable ? <button type="button" tabIndex={-1} className="tree-expand" aria-label={`${row.expanded ? 'Collapse' : 'Expand'} ${node.count} repeated calls of ${node.symbol}`} onClick={(click) => { click.stopPropagation(); toggle(row.nodeId); }}>{row.expanded ? 'Collapse' : 'Expand'}</button> : null}
    </li>);
  }
  spacer(rows.length);

  if (graph.nodes.length === 0) return <div className="empty"><strong>No frames to draw</strong><p>This window has no events with a frame id.</p></div>;
  return <div className="canvas-view">
    {!anyParent || undrawn > 0 || graph.dropped > 0 || drawn.length < graph.nodes.length ? <div className="canvas-notes" role="region" aria-label="Frame graph evidence" tabIndex={0}>
      {!anyParent ? <div className="evidence-state">Parent links were not observed for these frames; they are drawn as one level, not as a call tree.</div> : null}
      {undrawn > 0 ? <div className="evidence-state">{undrawn} events have no frame id and are not drawn.</div> : null}
      {graph.dropped > 0 ? <div className="evidence-state">{graph.dropped} events are not drawn or listed: duplicate frame ids or a parent cycle in the recorded data.</div> : null}
      {drawn.length < graph.nodes.length ? <div className="evidence-state">Drawing the shallowest {drawn.length} of {graph.nodes.length} nodes; the tree below lists all of them.</div> : null}
    </div> : null}
    <div ref={scrollRef} className="canvas-scroll" role="region" aria-label="Frame graph drawing" tabIndex={0}>
      <svg className="canvas-svg" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true" focusable="false">
        {graph.edges.map((edge) => {
          const from = byId.get(edge.from); const to = byId.get(edge.to);
          if (!from || !to || !drawnIds.has(edge.from) || !drawnIds.has(edge.to)) return null;
          const a = pos(from); const b = pos(to);
          return <path key={`${edge.kind}-${edge.from}-${edge.to}`} className={`canvas-edge canvas-edge--${edge.kind}`} d={`M${a.x + NODE_W / 2} ${a.y + NODE_H} L${b.x + NODE_W / 2} ${b.y}`} />;
        })}
        {drawn.map((node) => {
          const { x, y } = pos(node);
          return <g key={node.id} className="canvas-node" data-kind={kindOf(node)} data-selected={node.id === selectedNode} onClick={() => onSelectFrame(node.id)}>
            <rect x={x} y={y} width={NODE_W} height={NODE_H} />
            <text x={x + 8} y={y + 18}>{node.symbol.length > 22 ? `${node.symbol.slice(0, 21)}…` : node.symbol}{node.count > 1 ? ` ×${node.count}` : ''}</text>
          </g>;
        })}
      </svg>
    </div>
    <ul ref={tree} className="canvas-tree" role="tree" aria-label="Frame graph, one row per node; repeated calls are collapsed and can be expanded" onKeyDown={onKeyDown} onScroll={captureViewport}>
      {content}
    </ul>
  </div>;
}
