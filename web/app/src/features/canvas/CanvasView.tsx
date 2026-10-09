import { useMemo } from 'react';
import type { KeyboardEvent } from 'react';
import { projectFrameGraph } from '../../replay/graph';
import type { GraphFrame } from '../../replay/graph';
import type { NavAction } from '../../replay/navigation';
import type { ReplayEvent } from '../../types';

const NODE_W = 168;
const NODE_H = 28;
const COL_GAP = 16;
const ROW_GAP = 22;

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

  const selectedNode = selectedFrameId ? graph.nodeOfFrame[selectedFrameId] ?? null : null;
  const focusId = selectedNode ?? graph.nodes[0]?.id ?? null;
  const width = Math.max(1, Math.ceil(graph.columns)) * (NODE_W + COL_GAP);
  const height = Math.max(1, graph.layers) * (NODE_H + ROW_GAP);
  const pos = (node: { column: number; layer: number }) => ({ x: node.column * (NODE_W + COL_GAP), y: node.layer * (NODE_H + ROW_GAP) });
  const byId = new Map(graph.nodes.map((node) => [node.id, node]));

  const move = (delta: number) => {
    const index = graph.nodes.findIndex((node) => node.id === focusId);
    const next = graph.nodes[Math.max(0, Math.min(graph.nodes.length - 1, index + delta))];
    if (next) onSelectFrame(next.id);
  };
  const onKeyDown = (keyboard: KeyboardEvent) => {
    const actions: Record<string, () => void> = {
      ArrowDown: () => move(1), ArrowUp: () => move(-1),
      Home: () => graph.nodes[0] && onSelectFrame(graph.nodes[0].id),
      End: () => graph.nodes.length && onSelectFrame(graph.nodes[graph.nodes.length - 1].id),
      ArrowRight: () => onNavigate('into'), ArrowLeft: () => onNavigate('out'),
    };
    const action = actions[keyboard.key];
    if (!action) return;
    keyboard.preventDefault();
    action();
  };

  if (graph.nodes.length === 0) return <div className="empty"><strong>No frames to draw</strong><p>This window has no events with a frame id.</p></div>;
  return <div className="canvas-view">
    {!anyParent ? <div className="evidence-state">Parent links were not observed for these frames; they are drawn as one level, not as a call tree.</div> : null}
    {undrawn > 0 ? <div className="evidence-state">{undrawn} events have no frame id and are not drawn.</div> : null}
    <div className="canvas-scroll">
      <svg className="canvas-svg" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true" focusable="false">
        {graph.edges.map((edge) => {
          const from = byId.get(edge.from); const to = byId.get(edge.to);
          if (!from || !to) return null;
          const a = pos(from); const b = pos(to);
          return <path key={`${edge.kind}-${edge.from}-${edge.to}`} className={`canvas-edge canvas-edge--${edge.kind}`} d={`M${a.x + NODE_W / 2} ${a.y + NODE_H} L${b.x + NODE_W / 2} ${b.y}`} />;
        })}
        {graph.nodes.map((node) => {
          const { x, y } = pos(node);
          return <g key={node.id} className="canvas-node" data-selected={node.id === selectedNode} onClick={() => onSelectFrame(node.id)}>
            <rect x={x} y={y} width={NODE_W} height={NODE_H} />
            <text x={x + 8} y={y + 18}>{node.symbol.length > 22 ? `${node.symbol.slice(0, 21)}…` : node.symbol}{node.count > 1 ? ` ×${node.count}` : ''}</text>
          </g>;
        })}
      </svg>
    </div>
    <ul className="canvas-tree" role="tree" aria-label="Frame graph, same frames as the linear view" onKeyDown={onKeyDown}>
      {graph.nodes.map((node) => <li key={node.id} role="treeitem" aria-level={node.layer + 1} aria-selected={node.id === selectedNode}
        tabIndex={node.id === focusId ? 0 : -1} onClick={() => onSelectFrame(node.id)}
        ref={(element) => { if (element && node.id === selectedNode && document.activeElement?.closest('.canvas-tree')) element.focus(); }}>
        {node.symbol}{node.count > 1 ? ` (${node.count} repeated calls)` : ''}{node.parentOutsideWindow ? ' · parent outside window' : ''}
      </li>)}
    </ul>
  </div>;
}
