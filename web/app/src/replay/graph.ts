/**
 * Frame-graph projection for the Canvas view: collapses repeated sibling leaves into one counted node
 * and lays nodes out in deterministic layers. Pure; input order does not matter (frames sort by sequence).
 * It never invents a parent: a frame whose parent was not observed or not in the window is a root and is flagged.
 */

export interface GraphFrame {
  frameId: string;
  /** Decimal string, as on the wire. */
  sequence: string;
  kind: string;
  symbol: string;
  /** Present only when the parent frame was observed. */
  parentFrameId?: string | null;
  asyncParentFrameId?: string | null;
  depth?: number | null;
}

export interface GraphNode {
  /** Frame id of the first member; stable across re-projection of the same window. */
  id: string;
  /** Every frame this node stands for, in sequence order (length === count). */
  memberFrameIds: string[];
  count: number;
  kind: string;
  symbol: string;
  parentId: string | null;
  asyncParentId: string | null;
  /** The frame names a parent that is not in this window (or parent flag set without a parent id). */
  parentOutsideWindow: boolean;
  /** Recorded depth > 0 but no parent frame id was observed, so the node is drawn as a root without a known caller. */
  parentNotObserved: boolean;
  layer: number;
  /** Horizontal slot in column units; parents are centred over their children. */
  column: number;
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: 'call' | 'async';
}

export interface FrameGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  layers: number;
  columns: number;
  /** frameId -> id of the node that stands for it. */
  nodeOfFrame: Record<string, string>;
  /** Input frames that appear in no node: duplicate frame ids and members of parent cycles. */
  dropped: number;
}

/** Sequences are decimal strings; a malformed one must not throw, so it sorts after numeric ones. */
const toBig = (value: string): bigint | null => (/^\d+$/.test(value) ? BigInt(value) : null);

const compareSequence = (a: GraphFrame, b: GraphFrame): number => {
  const x = toBig(a.sequence);
  const y = toBig(b.sequence);
  if (x === null || y === null) {
    if (x !== null) return -1;
    if (y !== null) return 1;
    return a.sequence < b.sequence ? -1 : a.sequence > b.sequence ? 1 : 0;
  }
  return x < y ? -1 : x > y ? 1 : a.frameId < b.frameId ? -1 : a.frameId > b.frameId ? 1 : 0;
};

interface Draft {
  frames: GraphFrame[];
  children: Draft[];
  parent: Draft | null;
}

export function projectFrameGraph(input: readonly GraphFrame[]): FrameGraph {
  const frames = [...input].sort(compareSequence);
  const byId = new Map<string, GraphFrame>();
  for (const frame of frames) if (!byId.has(frame.frameId)) byId.set(frame.frameId, frame);
  const unique = frames.filter((frame) => byId.get(frame.frameId) === frame);

  // Step 1: one draft per frame, linked by observed parent ids inside the window.
  const drafts = new Map<string, Draft>();
  for (const frame of unique) drafts.set(frame.frameId, { frames: [frame], children: [], parent: null });
  const outside = new Set<string>();
  const roots: Draft[] = [];
  for (const frame of unique) {
    const draft = drafts.get(frame.frameId)!;
    const parentDraft = frame.parentFrameId ? drafts.get(frame.parentFrameId) : undefined;
    if (parentDraft && parentDraft !== draft) {
      draft.parent = parentDraft;
      parentDraft.children.push(draft);
    } else {
      roots.push(draft);
      if (frame.parentFrameId) outside.add(frame.frameId);
    }
  }

  // Step 2: collapse runs of adjacent sibling leaves with the same kind and symbol.
  const collapse = (siblings: Draft[]): Draft[] => {
    const out: Draft[] = [];
    for (const draft of siblings) {
      const last = out[out.length - 1];
      const mergeable = last && last.children.length === 0 && draft.children.length === 0
        && last.frames[0].kind === draft.frames[0].kind && last.frames[0].symbol === draft.frames[0].symbol
        && !last.frames[0].asyncParentFrameId && !draft.frames[0].asyncParentFrameId;
      if (mergeable) last.frames.push(...draft.frames);
      else out.push(draft);
    }
    return out;
  };
  const tree = (siblings: Draft[]): Draft[] => {
    const collapsed = collapse(siblings);
    for (const draft of collapsed) draft.children = tree(draft.children);
    return collapsed;
  };
  const rootNodes = tree(roots);

  // Step 3: layered layout. Layer is the tree depth within the window; leaves take consecutive columns.
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const nodeOfFrame: Record<string, string> = {};
  let nextColumn = 0;
  let layers = 0;
  const place = (draft: Draft, layer: number, parentId: string | null): GraphNode => {
    const first = draft.frames[0];
    const id = first.frameId;
    const node: GraphNode = {
      id, memberFrameIds: draft.frames.map((frame) => frame.frameId), count: draft.frames.length,
      kind: first.kind, symbol: first.symbol, parentId,
      asyncParentId: first.asyncParentFrameId ?? null,
      parentOutsideWindow: outside.has(first.frameId),
      parentNotObserved: !first.parentFrameId && (first.depth ?? 0) > 0,
      layer, column: 0,
    };
    nodes.push(node);
    for (const frame of draft.frames) nodeOfFrame[frame.frameId] = id;
    layers = Math.max(layers, layer + 1);
    if (parentId) edges.push({ from: parentId, to: id, kind: 'call' });
    if (draft.children.length === 0) {
      node.column = nextColumn;
      nextColumn += 1;
    } else {
      const placed = draft.children.map((child) => place(child, layer + 1, id));
      node.column = (placed[0].column + placed[placed.length - 1].column) / 2;
    }
    return node;
  };
  for (const root of rootNodes) place(root, 0, null);

  // Async edges only when both ends are in the window; the async parent is never inferred.
  for (const node of nodes) {
    if (!node.asyncParentId) continue;
    const target = nodeOfFrame[node.asyncParentId];
    if (target) edges.push({ from: target, to: node.id, kind: 'async' });
  }

  nodes.sort((a, b) => a.layer - b.layer || a.column - b.column || (a.id < b.id ? -1 : 1));
  return { nodes, edges, layers, columns: nextColumn, nodeOfFrame, dropped: input.length - Object.keys(nodeOfFrame).length };
}

export interface TreeRow {
  /** Unique within the tree. */
  key: string;
  nodeId: string;
  /** Frame this row selects. For a collapsed node's own row this is the first member. */
  frameId: string;
  level: number;
  posInSet: number;
  setSize: number;
  /** Set only on the row of a collapsed node (count > 1). */
  expandable: boolean;
  expanded: boolean;
  /** Member rows are children of their collapsed node's row. */
  isMember: boolean;
}

/**
 * Depth-first preorder rows for the parallel ARIA tree: a parent always precedes its children and
 * siblings keep sequence order, so level never jumps by more than +1. Layout order (breadth-first) is not used here.
 */
export function treeRows(graph: FrameGraph, expanded: ReadonlySet<string>): TreeRow[] {
  const children = new Map<string | null, GraphNode[]>();
  for (const node of graph.nodes) {
    const list = children.get(node.parentId) ?? [];
    list.push(node);
    children.set(node.parentId, list);
  }
  const rows: TreeRow[] = [];
  const visit = (parent: string | null, level: number) => {
    const siblings = (children.get(parent) ?? []).slice().sort((a, b) => a.column - b.column || (a.id < b.id ? -1 : 1));
    siblings.forEach((node, index) => {
      const open = node.count > 1 && expanded.has(node.id);
      rows.push({ key: node.id, nodeId: node.id, frameId: node.id, level, posInSet: index + 1, setSize: siblings.length, expandable: node.count > 1, expanded: open, isMember: false });
      if (open) {
        node.memberFrameIds.forEach((frameId, memberIndex) => rows.push({ key: `${node.id}/${frameId}`, nodeId: node.id, frameId, level: level + 1, posInSet: memberIndex + 1, setSize: node.count, expandable: false, expanded: false, isMember: true }));
      }
      visit(node.id, level + 1);
    });
  };
  visit(null, 1);
  return rows;
}
